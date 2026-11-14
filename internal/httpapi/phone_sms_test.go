package httpapi

import (
	"context"
	"net/http"
	"testing"

	"docvault/internal/auth"
	"docvault/internal/dbtest"
	"docvault/internal/sms"

	"github.com/jackc/pgx/v5/pgxpool"
)

// enableSMSLogin 打开租户的短信登录开关。
//
// 2026-11-14 起，发码/短信登录在服务层会检查"档位 × 租户开关"（默认关）。
// 这是产品要求：关掉后脚本直接调接口也不能继续烧短信费。
// 因此面向登录的用例必须先把开关打开，否则测的是"被闸门挡住"而不是登录逻辑。
func enableSMSLogin(t *testing.T, pool *pgxpool.Pool, slug string) {
	t.Helper()
	// 用 upsert：测试租户可能还没建过配置行（UPDATE 会静默影响 0 行，
	// 表现成"开关打开了但发码仍 503"，很难查）。
	if _, err := pool.Exec(context.Background(), `
		INSERT INTO tenant_config (tenant_id, policy) VALUES ($1, '{"smsLogin":true}'::jsonb)
		ON CONFLICT (tenant_id) DO UPDATE
		   SET policy = tenant_config.policy || '{"smsLogin":true}'::jsonb`, tenantOf(t, pool, slug)); err != nil {
		t.Fatalf("打开短信登录开关失败: %v", err)
	}
}

// 这些用例锁的是"小程序登录"的四条硬规则：
//  1. 未验证手机号的口令登录在小程序通道被拒；
//  2. 自助绑定后同一账号可以登录；
//  3. 手机号+验证码能签发会话，错码被拒；
//  4. 同名账号跨租户时必须用 username@tenant，服务端不猜。
func TestPhoneLoginFlow(t *testing.T) {
	srv, pool, slug := setupWith(t, func(api *API) {
		api.Auth.SetSMS(sms.NewMock("123456"))
		api.SMSConfigured = true
	})
	enableSMSLogin(t, pool, slug)

	// 1. 未登记手机号：小程序通道拒绝，Web 通道不受影响
	resp, body := postJSON(t, srv.URL+"/v1/auth/login", "", map[string]any{
		"account": "bob", "password": pwd, "channel": "mp",
	})
	if resp.StatusCode != http.StatusForbidden || body["code"] != "PHONE_NOT_REGISTERED" {
		t.Fatalf("未登记手机号的小程序登录应 403 PHONE_NOT_REGISTERED，实际 %d %v", resp.StatusCode, body)
	}
	resp, body = postJSON(t, srv.URL+"/v1/auth/login", "", map[string]any{
		"tenantSlug": slug, "username": "bob", "password": pwd,
	})
	if resp.StatusCode != 200 {
		t.Fatalf("Web 登录不应受手机号影响，实际 %d: %v", resp.StatusCode, body)
	}
	webToken := dataMap(t, body)["accessToken"].(string)

	// 2. 自助绑定：口令 + 新号码验证码
	resp, body = postJSON(t, srv.URL+"/v1/me/phone/request", webToken, map[string]any{
		"phone": "138 0013 8000", "password": pwd,
	})
	if resp.StatusCode != 200 {
		t.Fatalf("请求绑定手机号应成功，实际 %d: %v", resp.StatusCode, body)
	}
	resp, body = postJSON(t, srv.URL+"/v1/me/phone/confirm", webToken, map[string]any{
		"phone": "13800138000", "code": "000000",
	})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("错误验证码应 401，实际 %d: %v", resp.StatusCode, body)
	}
	resp, body = postJSON(t, srv.URL+"/v1/me/phone/confirm", webToken, map[string]any{
		"phone": "13800138000", "code": "123456",
	})
	if resp.StatusCode != 200 {
		t.Fatalf("正确验证码应绑定成功，实际 %d: %v", resp.StatusCode, body)
	}
	if got := dataMap(t, body)["phoneMasked"]; got != "138****8000" {
		t.Fatalf("应只回掩码，实际 %v", got)
	}

	// /v1/me 应能读到掩码与已验证标记
	_, me := getJSON(t, srv.URL+"/v1/me", webToken)
	md := dataMap(t, me)
	if md["phoneMasked"] != "138****8000" || md["phoneVerified"] != true || md["tenantSlug"] != slug {
		t.Fatalf("/v1/me 手机号字段不正确: %v", md)
	}

	// 3. 绑定后小程序口令登录通过
	resp, body = postJSON(t, srv.URL+"/v1/auth/login", "", map[string]any{
		"account": "bob", "password": pwd, "channel": "mp",
	})
	if resp.StatusCode != 200 {
		t.Fatalf("绑定后小程序登录应成功，实际 %d: %v", resp.StatusCode, body)
	}

	// 4. 手机号 + 验证码
	resp, body = postJSON(t, srv.URL+"/v1/auth/sms/send", "", map[string]any{"account": "13800138000"})
	if resp.StatusCode != 200 {
		t.Fatalf("发码应成功，实际 %d: %v", resp.StatusCode, body)
	}
	if dataMap(t, body)["sentTo"] != "138****8000" {
		t.Fatalf("发码响应不应回明文号码: %v", body)
	}
	// 60 秒内第二次必须被频控挡住，并给出 Retry-After
	resp, body = postJSON(t, srv.URL+"/v1/auth/sms/send", "", map[string]any{"account": "13800138000"})
	if resp.StatusCode != http.StatusTooManyRequests || body["code"] != "SMS_RATE_LIMITED" {
		t.Fatalf("重发应 429 SMS_RATE_LIMITED，实际 %d %v", resp.StatusCode, body)
	}
	if resp.Header.Get("Retry-After") == "" {
		t.Fatal("429 应带 Retry-After，前端倒计时依赖它")
	}
	resp, body = postJSON(t, srv.URL+"/v1/auth/sms/login", "", map[string]any{
		"account": "13800138000", "code": "999999",
	})
	if resp.StatusCode != http.StatusUnauthorized || body["code"] != "SMS_CODE_INVALID" {
		t.Fatalf("错码应 401 SMS_CODE_INVALID，实际 %d %v", resp.StatusCode, body)
	}
	resp, body = postJSON(t, srv.URL+"/v1/auth/sms/login", "", map[string]any{
		"account": "13800138000", "code": "123456",
	})
	if resp.StatusCode != 200 || dataMap(t, body)["accessToken"] == nil {
		t.Fatalf("正确验证码应签发令牌，实际 %d: %v", resp.StatusCode, body)
	}

	// 5. 未登记的号码：同样 200，但不透露、不发送
	resp, body = postJSON(t, srv.URL+"/v1/auth/sms/send", "", map[string]any{"account": "13900139000"})
	if resp.StatusCode != 200 {
		t.Fatalf("未登记号码也应返回 200（防枚举），实际 %d: %v", resp.StatusCode, body)
	}

	// 6. 跨租户同名：必须补 @tenant
	ctx := context.Background()
	t2 := uuid(t)
	if _, err := pool.Exec(ctx,
		`INSERT INTO tenant (id, slug, name, edition) VALUES ($1,$2,'另一个组织','business')`,
		t2, "http-"+t2[:8]); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { dbtest.CleanupTenant(t, pool, t2) })
	hash, _ := auth.HashPassword(pwd)
	if _, err := pool.Exec(ctx, `
		INSERT INTO app_user (id, tenant_id, username, display_name, password_hash, status)
		VALUES ($1,$2,'bob','Bob 2',$3,'active')`, uuid(t), t2, hash); err != nil {
		t.Fatal(err)
	}

	resp, body = postJSON(t, srv.URL+"/v1/auth/login", "", map[string]any{
		"account": "bob", "password": pwd, "channel": "mp",
	})
	if resp.StatusCode != http.StatusConflict || body["code"] != "AMBIGUOUS_ACCOUNT" {
		t.Fatalf("跨租户同名应 409 AMBIGUOUS_ACCOUNT，实际 %d %v", resp.StatusCode, body)
	}
	resp, body = postJSON(t, srv.URL+"/v1/auth/login", "", map[string]any{
		"account": "bob@" + slug, "password": pwd, "channel": "mp",
	})
	if resp.StatusCode != 200 {
		t.Fatalf("username@tenant 应能登录，实际 %d: %v", resp.StatusCode, body)
	}
}

// TestAdminPhoneVerify 锁的是"管理员录入 → 事后补验"这条链：
// 录入即落库但不可登录，验证后才可用；改号一定重置为待验证。
func TestAdminPhoneVerify(t *testing.T) {
	srv, pool, slug := setupWith(t, func(api *API) {
		api.Auth.SetSMS(sms.NewMock("123456"))
		api.SMSConfigured = true
	})
	tok := adminToken(t, srv.URL, pool, slug)

	// 1) 新建成员时录入手机号：落库但未验证
	resp, body := postJSON(t, srv.URL+"/v1/admin/members", tok, map[string]any{
		"username": "carol", "displayName": "Carol", "password": "Carol-Pass-2026",
		"phone": "138 0013 8001",
	})
	if resp.StatusCode != 200 {
		t.Fatalf("创建带手机号的成员应成功，实际 %d: %v", resp.StatusCode, body)
	}
	carolID := dataMap(t, body)["id"].(string)
	if got := dataMap(t, body)["phoneMasked"]; got != "138****8001" {
		t.Fatalf("应回掩码，实际 %v", got)
	}
	if dataMap(t, body)["phoneVerified"] != false {
		t.Fatal("录入后必须是待验证，不能直接算已验证")
	}

	// 未验证的号码不能用于小程序登录
	resp, body = postJSON(t, srv.URL+"/v1/auth/login", "", map[string]any{
		"account": "carol", "password": "Carol-Pass-2026", "channel": "mp",
	})
	if resp.StatusCode != http.StatusForbidden || body["code"] != "PHONE_NOT_REGISTERED" {
		t.Fatalf("待验证号码应拒绝小程序登录，实际 %d %v", resp.StatusCode, body)
	}

	// 2) 同一号码不能给第二个账号（租户内唯一）
	resp, body = postJSON(t, srv.URL+"/v1/admin/members", tok, map[string]any{
		"username": "dave", "displayName": "Dave", "password": "Dave-Pass-20266",
		"phone": "13800138001",
	})
	if resp.StatusCode != http.StatusConflict || body["code"] != "PHONE_TAKEN" {
		t.Fatalf("重复号码应 409 PHONE_TAKEN，实际 %d %v", resp.StatusCode, body)
	}

	// 3) 发码 + 校验
	resp, body = postJSON(t, srv.URL+"/v1/admin/members/"+carolID+"/phone/request", tok, map[string]any{})
	if resp.StatusCode != 200 {
		t.Fatalf("管理员发码应成功，实际 %d: %v", resp.StatusCode, body)
	}
	if got := dataMap(t, body)["sentTo"]; got != "138****8001" {
		t.Fatalf("发码响应应只回掩码，实际 %v", got)
	}
	resp, body = postJSON(t, srv.URL+"/v1/admin/members/"+carolID+"/phone/confirm", tok, map[string]any{"code": "000000"})
	if resp.StatusCode != http.StatusUnauthorized || body["code"] != "SMS_CODE_INVALID" {
		t.Fatalf("错码应 401，实际 %d %v", resp.StatusCode, body)
	}
	resp, body = postJSON(t, srv.URL+"/v1/admin/members/"+carolID+"/phone/confirm", tok, map[string]any{"code": "123456"})
	if resp.StatusCode != 200 {
		t.Fatalf("正确码应验证成功，实际 %d %v", resp.StatusCode, body)
	}
	if dataMap(t, body)["phoneVerified"] != true {
		t.Fatal("验证后应返回已验证")
	}

	// 验证后小程序口令登录通过
	resp, body = postJSON(t, srv.URL+"/v1/auth/login", "", map[string]any{
		"account": "carol", "password": "Carol-Pass-2026", "channel": "mp",
	})
	if resp.StatusCode != 200 {
		t.Fatalf("验证后小程序登录应成功，实际 %d %v", resp.StatusCode, body)
	}

	// 4) 改号必须重置验证状态：否则"填谁的号谁就能登录"
	resp, body = sendJSONMap(t, http.MethodPatch, srv.URL+"/v1/admin/members/"+carolID, tok, map[string]any{
		"phone": "13800138002",
	})
	if resp.StatusCode != 200 {
		t.Fatalf("改号应成功，实际 %d %v", resp.StatusCode, body)
	}
	if dataMap(t, body)["phoneVerified"] != false {
		t.Fatalf("改号后必须回到待验证，实际 %v", dataMap(t, body))
	}

	// 5) 清除
	resp, body = sendJSONMap(t, http.MethodDelete, srv.URL+"/v1/admin/members/"+carolID+"/phone", tok, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("清除手机号应成功，实际 %d %v", resp.StatusCode, body)
	}
	if dataMap(t, body)["phoneMasked"] != "" {
		t.Fatalf("清除后不应再有号码，实际 %v", dataMap(t, body))
	}
}

// TestSMSLoginRequiresTenantSwitch 锁"关掉开关后接口也拒绝"：
// 只在界面上藏入口是不够的，脚本仍会继续烧短信费。
func TestSMSLoginRequiresTenantSwitch(t *testing.T) {
	srv, pool, slug := setupWith(t, func(api *API) {
		api.Auth.SetSMS(sms.NewMock("123456"))
		api.SMSConfigured = true
	})
	ctx := context.Background()
	// 直接把号码置为已验证：本用例只关心闸门，不关心绑定流程
	if _, err := pool.Exec(ctx, `
		UPDATE app_user SET phone = '+8613800138077', phone_verified_at = now(), phone_source = 'manual'
		 WHERE tenant_id = $1 AND username = 'bob'`, tenantOf(t, pool, slug)); err != nil {
		t.Fatal(err)
	}

	resp, body := postJSON(t, srv.URL+"/v1/auth/sms/send", "", map[string]any{"account": "13800138077"})
	if resp.StatusCode != http.StatusServiceUnavailable || body["code"] != "SMS_NOT_CONFIGURED" {
		t.Fatalf("开关关闭时发码应 503，实际 %d %v", resp.StatusCode, body)
	}
	resp, body = postJSON(t, srv.URL+"/v1/auth/sms/login", "", map[string]any{
		"account": "13800138077", "code": "123456",
	})
	if resp.StatusCode != http.StatusServiceUnavailable || body["code"] != "SMS_NOT_CONFIGURED" {
		t.Fatalf("开关关闭时短信登录应 503，实际 %d %v", resp.StatusCode, body)
	}

	// 公开的登录方式接口必须同步反映"未开通"
	_, m := getJSON(t, srv.URL+"/v1/auth/methods?tenant="+slug, "")
	if dataMap(t, m)["sms"] != false {
		t.Fatalf("未开通时 /v1/auth/methods 应报 sms=false，实际 %v", dataMap(t, m))
	}

	enableSMSLogin(t, pool, slug)
	resp, body = postJSON(t, srv.URL+"/v1/auth/sms/send", "", map[string]any{"account": "13800138077"})
	if resp.StatusCode != 200 {
		t.Fatalf("开通后发码应成功，实际 %d %v", resp.StatusCode, body)
	}
	_, m = getJSON(t, srv.URL+"/v1/auth/methods?tenant="+slug, "")
	if dataMap(t, m)["sms"] != true {
		t.Fatalf("开通后 /v1/auth/methods 应报 sms=true，实际 %v", dataMap(t, m))
	}
}
