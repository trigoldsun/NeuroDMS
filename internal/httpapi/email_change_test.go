package httpapi

// AC-61 换绑联系方式：必须提供旧凭证（口令）+ 新地址验证码，换绑后旧会话立刻失效。

import (
	"context"
	"net/http"
	"testing"

	"docvault/internal/auth"
)

// captureSender 记录最后一次发出的验证码，供测试断言（不真的发邮件）。
type captureSender struct {
	lastTo   string
	lastCode string
	failWith error
}

func (s *captureSender) SendCode(_ context.Context, _, to, _, code string) error {
	if s.failWith != nil {
		return s.failWith
	}
	s.lastTo, s.lastCode = to, code
	return nil
}

func TestAC61EmailChangeRequiresOldCredential(t *testing.T) {
	sender := &captureSender{}
	srv, _, slug := setupWith(t, func(a *API) {
		otp := auth.NewOTPStore(a.Pool, []byte("0123456789abcdef0123456789abcdef"), auth.DefaultOTPConfig())
		a.Auth.SetMFA(otp, sender)
	})
	token := login(t, srv.URL, slug)

	// 1) 不提供口令 → 401（绝不能"缺参数就跳过校验"）
	resp, out := sendJSONMap(t, http.MethodPost, srv.URL+"/v1/me/email/request", token,
		map[string]any{"newEmail": "new@example.com"})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("AC-61 缺口令应 401，实际 %d: %v", resp.StatusCode, out)
	}

	// 2) 错口令 → 401
	resp, out = sendJSONMap(t, http.MethodPost, srv.URL+"/v1/me/email/request", token,
		map[string]any{"newEmail": "new@example.com", "password": "WrongPass_12345"})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("AC-61 错口令应 401，实际 %d: %v", resp.StatusCode, out)
	}
	if sender.lastCode != "" {
		t.Fatal("AC-61 口令错误时不应发送任何验证码")
	}

	// 3) 正确口令 → 200 且发码到新邮箱
	resp, out = sendJSONMap(t, http.MethodPost, srv.URL+"/v1/me/email/request", token,
		map[string]any{"newEmail": "new@example.com", "password": pwd})
	if resp.StatusCode != 200 {
		t.Fatalf("AC-61 正确口令应 200，实际 %d: %v", resp.StatusCode, out)
	}
	if sender.lastTo != "new@example.com" || sender.lastCode == "" {
		t.Fatalf("AC-61 验证码应发到新邮箱，实际 to=%q code=%q", sender.lastTo, sender.lastCode)
	}

	// 4) 错码 → 400
	resp, out = sendJSONMap(t, http.MethodPost, srv.URL+"/v1/me/email/confirm", token,
		map[string]any{"newEmail": "new@example.com", "code": "000000"})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("AC-61 错码应 400，实际 %d: %v", resp.StatusCode, out)
	}

	// 5) 正确码 → 200
	resp, out = sendJSONMap(t, http.MethodPost, srv.URL+"/v1/me/email/confirm", token,
		map[string]any{"newEmail": "new@example.com", "code": sender.lastCode})
	if resp.StatusCode != 200 {
		t.Fatalf("AC-61 正确码应 200，实际 %d: %v", resp.StatusCode, out)
	}

	// 6) 换绑后旧会话必须失效（否则攻击者换完绑还能继续用）
	if r, raw := getJSON(t, srv.URL+"/v1/me", token); r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("AC-61 换绑后旧令牌应 401，实际 %d: %s", r.StatusCode, raw)
	}
}

// 验证码不能跨账号/跨邮箱复用：A 的码不能用来改 B，也不能用来改到另一个地址。
func TestAC61CodeIsBoundToUserAndAddress(t *testing.T) {
	sender := &captureSender{}
	srv, _, slug := setupWith(t, func(a *API) {
		otp := auth.NewOTPStore(a.Pool, []byte("0123456789abcdef0123456789abcdef"), auth.DefaultOTPConfig())
		a.Auth.SetMFA(otp, sender)
	})
	token := login(t, srv.URL, slug)

	if resp, out := sendJSONMap(t, http.MethodPost, srv.URL+"/v1/me/email/request", token,
		map[string]any{"newEmail": "a@example.com", "password": pwd}); resp.StatusCode != 200 {
		t.Fatalf("发码失败 %d: %v", resp.StatusCode, out)
	}
	code := sender.lastCode

	// 同一个码，改到另一个地址 → 必须失败（subject 绑定了地址）
	if resp, out := sendJSONMap(t, http.MethodPost, srv.URL+"/v1/me/email/confirm", token,
		map[string]any{"newEmail": "b@example.com", "code": code}); resp.StatusCode == 200 {
		t.Fatalf("AC-61 验证码不应跨地址生效: %v", out)
	}
}

// 未配置邮件通道时必须拒绝换绑，而不是"跳过验证码直接改"。
func TestAC61FailsClosedWithoutChannel(t *testing.T) {
	srv, _, slug := setup(t) // 未注入 MFA/通道
	token := login(t, srv.URL, slug)

	resp, out := sendJSONMap(t, http.MethodPost, srv.URL+"/v1/me/email/request", token,
		map[string]any{"newEmail": "x@example.com", "password": pwd})
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("AC-61 无通道应 503，实际 %d: %v", resp.StatusCode, out)
	}
	if out["code"] != "CHANNEL_UNAVAILABLE" {
		t.Fatalf("AC-61 应返回 CHANNEL_UNAVAILABLE: %v", out)
	}
}
