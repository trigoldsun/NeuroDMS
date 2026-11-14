package httpapi

// 外发访问记录：分享人可见性 + 打印上报。
//
// 这一组对应"发出去之后到底怎么样了"这个最基本的问题：
// 之前只有管理员能在审计里查到，分享人自己是瞎的。

import (
	"bytes"
	"encoding/base64"
	"net/http"
	"testing"

	"docvault/internal/notify"
	"docvault/internal/rbac"
	"docvault/internal/secretbox"
)

func TestShareAccessVisibility(t *testing.T) {
	srv, _, slug := setup(t)
	owner := login(t, srv.URL, slug)
	_, nodeID := prepareFile(t, srv.URL, owner)

	resp, sb := postJSON(t, srv.URL+"/v1/shares", owner, map[string]any{
		"objectType": "node", "objectId": nodeID, "expiresInHours": 1, "allowPrint": true,
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("创建分享失败 %d: %v", resp.StatusCode, sb)
	}
	d := dataMap(t, sb)
	shareID := d["shareId"].(string)
	token := d["token"].(string)

	// 访客兑换 + 预览
	_, rb := getJSON(t, srv.URL+"/v1/public/shares/"+token, "")
	ticket := dataMap(t, rb)["ticket"].(string)
	if r, _ := getRaw(t, srv.URL+"/v1/public/tickets/"+ticket+"/content?inline=1", ""); r.StatusCode != 200 {
		t.Fatalf("预览应成功，实际 %d", r.StatusCode)
	}

	// 打印上报：第一次记录，第二次（5 秒内）被节流
	resp, pr := postJSON(t, srv.URL+"/v1/public/tickets/"+ticket+"/print", "", nil)
	if resp.StatusCode != http.StatusOK || dataMap(t, pr)["recorded"] != true {
		t.Fatalf("首次打印上报应记录，实际 %d: %v", resp.StatusCode, pr)
	}
	resp, pr = postJSON(t, srv.URL+"/v1/public/tickets/"+ticket+"/print", "", nil)
	if resp.StatusCode != http.StatusOK || dataMap(t, pr)["recorded"] != false {
		t.Fatalf("重复上报应被节流，实际 %d: %v", resp.StatusCode, pr)
	}

	// 我的分享：能看到预览 1 次、打印 1 次、独立 IP 1 个
	_, mine := getJSON(t, srv.URL+"/v1/shares/mine", owner)
	items := dataMap(t, mine)["items"].([]any)
	if len(items) != 1 {
		t.Fatalf("应只有 1 条自己的分享，实际 %d", len(items))
	}
	it := items[0].(map[string]any)
	if it["views"].(float64) != 1 || it["prints"].(float64) != 1 {
		t.Fatalf("统计不正确: %v", it)
	}
	if it["distinctIps"].(float64) != 1 {
		t.Fatalf("独立 IP 应为 1，实际 %v", it["distinctIps"])
	}

	// 访问明细：创建者可见，含动作与 IP
	resp, vb := getJSON(t, srv.URL+"/v1/shares/"+shareID+"/visits", owner)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("创建者应能查看访问记录，实际 %d: %v", resp.StatusCode, vb)
	}
	visits := dataMap(t, vb)
	if visits["summary"].(map[string]any)["prints"].(float64) != 1 {
		t.Fatalf("明细统计不正确: %v", visits["summary"])
	}
	list := visits["items"].([]any)
	if len(list) == 0 {
		t.Fatal("应有访问记录")
	}
	first := list[0].(map[string]any)
	if first["ip"] == "" || first["scope"] == "" {
		t.Fatalf("记录应含 IP 与可见范围: %v", first)
	}

	// 别人看不到：既不是创建者，也没有该对象的 manage_acl
	other := seedUser(t, srv.URL, slug, "access-other")
	resp, _ = getJSON(t, srv.URL+"/v1/shares/"+shareID+"/visits", other)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("无关成员应 403，实际 %d", resp.StatusCode)
	}
}

// 不允许打印的分享：上报要被拒，并留一条 denied 审计。
func TestSharePrintDeniedWhenPolicyOff(t *testing.T) {
	srv, _, slug := setup(t)
	owner := login(t, srv.URL, slug)
	_, nodeID := prepareFile(t, srv.URL, owner)

	_, sb := postJSON(t, srv.URL+"/v1/shares", owner, map[string]any{
		"objectType": "node", "objectId": nodeID, "expiresInHours": 1,
	})
	token := dataMap(t, sb)["token"].(string)
	_, rb := getJSON(t, srv.URL+"/v1/public/shares/"+token, "")
	ticket := dataMap(t, rb)["ticket"].(string)

	resp, out := postJSON(t, srv.URL+"/v1/public/tickets/"+ticket+"/print", "", nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("不允许打印时应 403，实际 %d: %v", resp.StatusCode, out)
	}
}

// 隐私政策链接只允许 http(s)：它会被渲染成分享页/邮件里的 <a href>。
func TestBrandingPrivacyURLCannotBeJavascript(t *testing.T) {
	srv, pool, slug := setupWith(t, func(a *API) {
		box, _ := secretbox.New(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)))
		a.Mail = notify.NewStore(a.Pool, box)
	})
	tenantID := tenantOf(t, pool, slug)
	seedRole(t, pool, tenantID, userIDByName(t, slug, "bob"), rbac.SysAdmin)
	tok := login(t, srv.URL, slug)

	resp, out := sendJSONMap(t, http.MethodPut, srv.URL+"/v1/admin/branding", tok, map[string]any{
		"productName": "森莘", "primaryColor": "#12724a", "accentColor": "#0b5fa5",
		"footerText": "", "privacyUrl": "javascript:alert(1)",
	})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("javascript: 链接应被拒，实际 %d: %v", resp.StatusCode, out)
	}

	resp, out = sendJSONMap(t, http.MethodPut, srv.URL+"/v1/admin/branding", tok, map[string]any{
		"productName": "森莘", "primaryColor": "#12724a", "accentColor": "#0b5fa5",
		"footerText": "", "privacyUrl": "https://example.com/privacy",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("合法链接应保存成功，实际 %d: %v", resp.StatusCode, out)
	}
	if got := dataMap(t, out)["privacyUrl"]; got != "https://example.com/privacy" {
		t.Fatalf("privacyUrl 未回显: %v", got)
	}
}
