package httpapi

// AC-50 / AC-51：分享链接的邮箱白名单与验证码失败锁定。

import (
	"context"
	"net/http"
	"testing"

	"docvault/internal/auth"
)

// newVerifyShare 创建一个"需要邮箱验证 + 白名单"的分享，返回 token。
func newVerifyShare(t *testing.T, srvURL, token string, whitelist []string) string {
	t.Helper()
	_, body := postJSON(t, srvURL+"/v1/spaces", token, map[string]any{"kind": "project", "name": "验证空间"})
	spaceID := dataMap(t, body)["spaceId"].(string)
	_, up := upload(t, srvURL+"/v1/spaces/"+spaceID+"/files", token, "verify.txt", "验证内容")
	nodeID := dataMap(t, up)["nodeId"].(string)

	resp, shareOut := postJSON(t, srvURL+"/v1/shares", token, map[string]any{
		"objectType": "node", "objectId": nodeID,
		"requireVerify": true, "allowDownload": true,
		"emailWhitelist": whitelist,
	})
	if resp.StatusCode != 200 {
		t.Fatalf("创建验证分享失败 %d: %v", resp.StatusCode, shareOut)
	}
	return dataMap(t, shareOut)["token"].(string)
}

// AC-50：白名单外的邮箱不能申请验证码，且不会发出任何验证码。
func TestAC50NonWhitelistedEmailCannotRequestCode(t *testing.T) {
	sender := &captureSender{}
	srv, _, slug := setupWith(t, func(a *API) {
		otp := auth.NewOTPStore(a.Pool, []byte("0123456789abcdef0123456789abcdef"), auth.DefaultOTPConfig())
		a.Auth.SetMFA(otp, sender)
	})
	owner := login(t, srv.URL, slug)
	shareToken := newVerifyShare(t, srv.URL, owner, []string{"@partner.com"})

	// 白名单外
	resp, out := sendJSONMap(t, http.MethodPost,
		srv.URL+"/v1/public/shares/"+shareToken+"/verify/request", "",
		map[string]any{"email": "attacker@gmail.com"})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("AC-50 白名单外应 403，实际 %d: %v", resp.StatusCode, out)
	}
	if out["code"] != "EMAIL_NOT_ALLOWED" {
		t.Fatalf("AC-50 应返回 EMAIL_NOT_ALLOWED: %v", out)
	}
	if sender.lastCode != "" {
		t.Fatal("AC-50 拒绝时不得发出验证码（否则等于免费邮件发送器）")
	}

	// 白名单内（域名匹配）
	resp, out = sendJSONMap(t, http.MethodPost,
		srv.URL+"/v1/public/shares/"+shareToken+"/verify/request", "",
		map[string]any{"email": "alice@partner.com"})
	if resp.StatusCode != 200 {
		t.Fatalf("AC-50 白名单内应 200，实际 %d: %v", resp.StatusCode, out)
	}
	if sender.lastCode == "" || sender.lastTo != "alice@partner.com" {
		t.Fatalf("AC-50 应发码到白名单邮箱: to=%q", sender.lastTo)
	}
}

// AC-51：验证码连错 6 次后，即使输入正确码也失效。
func TestAC51ShareCodeLocksAfterSixFailures(t *testing.T) {
	sender := &captureSender{}
	srv, _, slug := setupWith(t, func(a *API) {
		otp := auth.NewOTPStore(a.Pool, []byte("0123456789abcdef0123456789abcdef"), auth.DefaultOTPConfig())
		a.Auth.SetMFA(otp, sender)
	})
	owner := login(t, srv.URL, slug)
	shareToken := newVerifyShare(t, srv.URL, owner, []string{"alice@partner.com"})

	if resp, out := sendJSONMap(t, http.MethodPost,
		srv.URL+"/v1/public/shares/"+shareToken+"/verify/request", "",
		map[string]any{"email": "alice@partner.com"}); resp.StatusCode != 200 {
		t.Fatalf("发码失败 %d: %v", resp.StatusCode, out)
	}
	good := sender.lastCode

	// 连错 5 次（MaxAttempts 默认 5）
	for i := 0; i < 5; i++ {
		resp, _ := sendJSONMap(t, http.MethodPost,
			srv.URL+"/v1/public/shares/"+shareToken+"/verify/confirm", "",
			map[string]any{"email": "alice@partner.com", "code": "000000"})
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("第 %d 次错码应 400，实际 %d", i+1, resp.StatusCode)
		}
	}

	// 第 6 次送正确码：必须失效（只限制"错误次数"不限制"错误后仍可用"等于没锁）
	resp, out := sendJSONMap(t, http.MethodPost,
		srv.URL+"/v1/public/shares/"+shareToken+"/verify/confirm", "",
		map[string]any{"email": "alice@partner.com", "code": good})
	if resp.StatusCode == 200 {
		t.Fatalf("AC-51 连续失败后正确码也应失效: %v", out)
	}
}

// 验证通过后能拿到票据，且验证记录是一次性的（不能重复兑换同一条记录）。
func TestShareVerifyGrantsTicketOnce(t *testing.T) {
	sender := &captureSender{}
	srv, pool, slug := setupWith(t, func(a *API) {
		otp := auth.NewOTPStore(a.Pool, []byte("0123456789abcdef0123456789abcdef"), auth.DefaultOTPConfig())
		a.Auth.SetMFA(otp, sender)
	})
	owner := login(t, srv.URL, slug)
	shareToken := newVerifyShare(t, srv.URL, owner, []string{"alice@partner.com"})

	if resp, out := sendJSONMap(t, http.MethodPost,
		srv.URL+"/v1/public/shares/"+shareToken+"/verify/request", "",
		map[string]any{"email": "alice@partner.com"}); resp.StatusCode != 200 {
		t.Fatalf("发码失败 %d: %v", resp.StatusCode, out)
	}

	resp, out := sendJSONMap(t, http.MethodPost,
		srv.URL+"/v1/public/shares/"+shareToken+"/verify/confirm", "",
		map[string]any{"email": "alice@partner.com", "code": sender.lastCode})
	if resp.StatusCode != 200 {
		t.Fatalf("验证并兑换失败 %d: %v", resp.StatusCode, out)
	}
	if d := dataMap(t, out); d["ticket"] == nil || d["ticket"] == "" {
		t.Fatalf("应返回访问票据: %v", d)
	}

	// 验证记录已被消费（一条记录只能兑换一次）
	shareID := dataMap(t, out)["shareId"].(string)
	var consumed int
	if err := pool.QueryRow(context.Background(), `
		SELECT count(*) FROM share_verify WHERE share_id = $1 AND consumed_at IS NOT NULL`,
		shareID).Scan(&consumed); err != nil {
		t.Fatal(err)
	}
	if consumed < 1 {
		t.Fatal("验证记录应被消费，否则可重复兑换")
	}
}
