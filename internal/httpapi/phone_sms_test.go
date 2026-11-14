package httpapi

import (
	"context"
	"net/http"
	"testing"

	"docvault/internal/auth"
	"docvault/internal/dbtest"
	"docvault/internal/sms"
)

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
