package httpapi

// 邮件服务配置（管理台「系统设置 · 邮件服务」）的用例。
//
// 重点是三条：
//  1. 口令只写不读——响应里不能出现明文，库里必须是密文；
//  2. 明文连接 + 口令必须显式放行，否则拒绝保存（防止口令明文过网）；
//  3. 没有加密密钥时拒绝写口令，而不是降级成明文落库。

import (
	"bytes"
	"context"
	"encoding/base64"
	"net/http"
	"testing"

	"docvault/internal/notify"
	"docvault/internal/rbac"
	"docvault/internal/secretbox"
)

// mailTestKey 是 32 字节测试密钥（base64）。
func mailTestKey() string { return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)) }

func TestMailConfigRoundTripHidesSecrets(t *testing.T) {
	srv, pool, slug := setupWith(t, func(a *API) {
		box, err := secretbox.New(mailTestKey())
		if err != nil {
			t.Fatalf("构造加密箱失败: %v", err)
		}
		a.SecretBox = box
		a.Mail = notify.NewStore(a.Pool, box)
		a.MailRouter = notify.NewRouter(nil, a.Mail.Load, nil)
	})
	tenantID := tenantOf(t, pool, slug)
	seedRole(t, pool, tenantID, userIDByName(t, slug, "bob"), rbac.SysAdmin)
	tok := login(t, srv.URL, slug)

	// 1) 初始状态：跟随平台默认，未配置
	_, body := getJSON(t, srv.URL+"/v1/admin/mail", tok)
	view := dataMap(t, body)
	cfg, _ := view["config"].(map[string]any)
	if cfg["mode"] != "inherit" || cfg["source"] != "none" {
		t.Fatalf("初始应为跟随平台默认，实际 %v", cfg)
	}
	env, _ := view["environment"].(map[string]any)
	if env["secretKeyAvailable"] != true {
		t.Fatalf("应报告密钥可用，实际 %v", env)
	}

	// 2) 保存 SMTP 配置（含口令）
	resp, out := sendJSONMap(t, http.MethodPut, srv.URL+"/v1/admin/mail", tok, map[string]any{
		"mode": "smtp", "smtpHost": "smtp.example.com", "smtpPort": 587,
		"smtpTls": "starttls", "smtpUser": "robot@example.com",
		"smtpPassword": "s3cret-pass", "fromAddr": "noreply@example.com",
		"fromName": "NeuroDMS 文档平台",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("保存失败 %d: %v", resp.StatusCode, out)
	}
	savedCfg, _ := dataMap(t, out)["config"].(map[string]any)
	if _, leaked := savedCfg["smtpPassword"]; leaked {
		t.Fatalf("响应不应包含口令: %v", savedCfg)
	}
	if savedCfg["hasSmtpPassword"] != true {
		t.Fatalf("应标记已保存口令，实际 %v", savedCfg)
	}

	// 3) 读回来同样不返回口令
	_, body = getJSON(t, srv.URL+"/v1/admin/mail", tok)
	cfg, _ = dataMap(t, body)["config"].(map[string]any)
	if _, leaked := cfg["smtpPassword"]; leaked {
		t.Fatalf("读接口不应包含口令: %v", cfg)
	}
	if cfg["source"] != "database" || cfg["mode"] != "smtp" {
		t.Fatalf("应读回数据库配置，实际 %v", cfg)
	}

	// 4) 库里必须是密文：直接查表不允许出现明文
	var enc []byte
	if err := pool.QueryRow(context.Background(),
		`SELECT smtp_password_enc FROM mail_config WHERE tenant_id = $1`, tenantID).Scan(&enc); err != nil {
		t.Fatalf("读取密文失败: %v", err)
	}
	if len(enc) == 0 {
		t.Fatal("口令未落库")
	}
	if bytes.Contains(enc, []byte("s3cret-pass")) {
		t.Fatal("口令以明文落库")
	}

	// 5) 留空口令再保存 = 不修改（否则界面每改一次端口就把口令清空）
	resp, out = sendJSONMap(t, http.MethodPut, srv.URL+"/v1/admin/mail", tok, map[string]any{
		"mode": "smtp", "smtpHost": "smtp2.example.com", "smtpPort": 465,
		"smtpTls": "tls", "smtpUser": "robot@example.com",
		"fromAddr": "noreply@example.com",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("二次保存失败 %d: %v", resp.StatusCode, out)
	}
	var enc2 []byte
	if err := pool.QueryRow(context.Background(),
		`SELECT smtp_password_enc FROM mail_config WHERE tenant_id = $1`, tenantID).Scan(&enc2); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(enc, enc2) {
		t.Fatal("口令留空时应保持原密文，实际被改写")
	}
}

// 明文连接 + 口令：必须显式勾选「允许明文连接」，否则拒绝。
func TestMailConfigRejectsPlaintextPassword(t *testing.T) {
	srv, pool, slug := setupWith(t, func(a *API) {
		box, _ := secretbox.New(mailTestKey())
		a.Mail = notify.NewStore(a.Pool, box)
		a.MailRouter = notify.NewRouter(nil, a.Mail.Load, nil)
	})
	tenantID := tenantOf(t, pool, slug)
	seedRole(t, pool, tenantID, userIDByName(t, slug, "bob"), rbac.SysAdmin)
	tok := login(t, srv.URL, slug)

	resp, out := sendJSONMap(t, http.MethodPut, srv.URL+"/v1/admin/mail", tok, map[string]any{
		"mode": "smtp", "smtpHost": "relay.local", "smtpPort": 25,
		"smtpTls": "none", "smtpUser": "robot", "smtpPassword": "pw",
		"fromAddr": "noreply@example.com",
	})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("明文 + 口令应被拒绝，实际 %d: %v", resp.StatusCode, out)
	}

	// 勾选放行后允许保存（内网中继场景）
	resp, out = sendJSONMap(t, http.MethodPut, srv.URL+"/v1/admin/mail", tok, map[string]any{
		"mode": "smtp", "smtpHost": "relay.local", "smtpPort": 25,
		"smtpTls": "none", "smtpUser": "robot", "smtpPassword": "pw",
		"smtpAllowPlaintext": true, "fromAddr": "noreply@example.com",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("显式放行后应可保存，实际 %d: %v", resp.StatusCode, out)
	}
}

// 没有加密密钥时不能写口令：宁可功能不可用，也不明文落库。
func TestMailConfigRequiresSecretKey(t *testing.T) {
	srv, pool, slug := setupWith(t, func(a *API) {
		// box = nil：模拟未配置 DOCVAULT_SECRET_KEY
		a.Mail = notify.NewStore(a.Pool, nil)
		a.MailRouter = notify.NewRouter(nil, a.Mail.Load, nil)
	})
	tenantID := tenantOf(t, pool, slug)
	seedRole(t, pool, tenantID, userIDByName(t, slug, "bob"), rbac.SysAdmin)
	tok := login(t, srv.URL, slug)

	resp, out := sendJSONMap(t, http.MethodPut, srv.URL+"/v1/admin/mail", tok, map[string]any{
		"mode": "smtp", "smtpHost": "smtp.example.com", "smtpPort": 587,
		"smtpTls": "starttls", "smtpPassword": "pw",
		"fromAddr": "noreply@example.com",
	})
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("无密钥应 409，实际 %d: %v", resp.StatusCode, out)
	}
	if code, _ := out["code"].(string); code != "NO_SECRET_KEY" {
		t.Fatalf("应返回 NO_SECRET_KEY，实际 %q", code)
	}

	// 不含口令的配置仍然可以保存（地址、端口这些不敏感）
	resp, out = sendJSONMap(t, http.MethodPut, srv.URL+"/v1/admin/mail", tok, map[string]any{
		"mode": "smtp", "smtpHost": "smtp.example.com", "smtpPort": 587,
		"smtpTls": "starttls", "fromAddr": "noreply@example.com",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("无口令配置应可保存，实际 %d: %v", resp.StatusCode, out)
	}
}

// 只有 sysadmin 能看/改：邮件配置能决定"以谁的名义发信"。
func TestMailConfigRequiresSysAdmin(t *testing.T) {
	srv, pool, slug := setupWith(t, func(a *API) {
		box, _ := secretbox.New(mailTestKey())
		a.Mail = notify.NewStore(a.Pool, box)
		a.MailRouter = notify.NewRouter(nil, a.Mail.Load, nil)
	})
	_ = pool
	plain := login(t, srv.URL, slug) // 无任何管理角色

	if resp, _ := getJSON(t, srv.URL+"/v1/admin/mail", plain); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("普通成员读配置应 403，实际 %d", resp.StatusCode)
	}
	resp, _ := sendJSONMap(t, http.MethodPut, srv.URL+"/v1/admin/mail", plain,
		map[string]any{"mode": "inherit"})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("普通成员改配置应 403，实际 %d", resp.StatusCode)
	}
}
