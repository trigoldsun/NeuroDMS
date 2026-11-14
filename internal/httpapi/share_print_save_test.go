package httpapi

// 外发分享的「允许保存 / 允许打印」控制。
//
// 这一组用例对应一个真实缺陷：只读分享（allowDownload=false）的访客
// 仍然能在浏览器 PDF 阅读器的工具栏里点「下载」——接口层拦了 403，
// 但呈现层把 PDF 直接交给了浏览器自带的阅读器。
//
// 修复分两层：
//   1. 策略位落库（allow_save / allow_print），接口按策略返回；
//   2. 前端不再用 iframe 显示 PDF，改成画布渲染（见 PdfCanvasViewer）。
// 这里验证第 1 层，以及"自相矛盾的组合必须被拒"。

import (
	"bytes"
	"encoding/base64"
	"net/http"
	"testing"

	"docvault/internal/notify"
	"docvault/internal/rbac"
	"docvault/internal/secretbox"
)

func TestShareSavePrintFlags(t *testing.T) {
	srv, _, slug := setup(t)
	owner := login(t, srv.URL, slug)
	_, nodeID := prepareFile(t, srv.URL, owner)

	// 1) 不传 allowSave/allowPrint：跟随 allowDownload（= false）→ 只读
	resp, sb := postJSON(t, srv.URL+"/v1/shares", owner, map[string]any{
		"objectType": "node", "objectId": nodeID, "allowDownload": false,
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("创建只读分享失败 %d: %v", resp.StatusCode, sb)
	}
	d := dataMap(t, sb)
	if d["allowSave"] != false || d["allowPrint"] != false {
		t.Fatalf("只读分享默认应不可保存、不可打印，实际 %v / %v", d["allowSave"], d["allowPrint"])
	}

	// 票据信息里也要带上：前端按它决定显示哪些按钮
	token := d["token"].(string)
	_, rb := getJSON(t, srv.URL+"/v1/public/shares/"+token, "")
	redeem := dataMap(t, rb)
	if redeem["allowSave"] != false || redeem["allowPrint"] != false {
		t.Fatalf("兑换响应应带策略位，实际 %v / %v", redeem["allowSave"], redeem["allowPrint"])
	}
	ticket := redeem["ticket"].(string)
	_, tb := getJSON(t, srv.URL+"/v1/public/tickets/"+ticket, "")
	ti := dataMap(t, tb)
	if ti["allowSave"] != false || ti["allowPrint"] != false {
		t.Fatalf("票据信息应带策略位，实际 %v / %v", ti["allowSave"], ti["allowPrint"])
	}

	// 2) 下载仍被拒（这条是原有能力，回归守住）
	if r, _ := getRaw(t, srv.URL+"/v1/public/tickets/"+ticket+"/content?download=1", ""); r.StatusCode != http.StatusForbidden {
		t.Fatalf("只读分享下载应 403，实际 %d", r.StatusCode)
	}

	// 3) 自相矛盾：不允许保存却允许下载原件 → 400
	resp, out := postJSON(t, srv.URL+"/v1/shares", owner, map[string]any{
		"objectType": "node", "objectId": nodeID,
		"allowDownload": true, "allowSave": false,
	})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("allowSave=false 且 allowDownload=true 应 400，实际 %d: %v", resp.StatusCode, out)
	}

	// 4) 允许保存但不允许下载原件：可以的（对方只能留在查看器里的副本）
	resp, out = postJSON(t, srv.URL+"/v1/shares", owner, map[string]any{
		"objectType": "node", "objectId": nodeID,
		"allowDownload": false, "allowSave": true, "allowPrint": true,
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("允许保存的分享创建失败 %d: %v", resp.StatusCode, out)
	}
	if got := dataMap(t, out); got["allowSave"] != true || got["allowPrint"] != true || got["allowDownload"] != false {
		t.Fatalf("策略位未按提交保存：%v", got)
	}

	// 5) 允许下载时，保存/打印默认跟随为真
	resp, out = postJSON(t, srv.URL+"/v1/shares", owner, map[string]any{
		"objectType": "node", "objectId": nodeID, "allowDownload": true,
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("可下载分享创建失败 %d: %v", resp.StatusCode, out)
	}
	if got := dataMap(t, out); got["allowSave"] != true || got["allowPrint"] != true {
		t.Fatalf("允许下载时应默认允许保存与打印，实际 %v", got)
	}
}

// 邮件主题必须带租户自己的系统名称，而不是固定写 NeuroDMS。
func TestShareMailSubjectUsesBrand(t *testing.T) {
	uses := 1
	subject, text, html := shareMailBody("森莘", "张三", "合同.docx", "https://x/s/tok", "",
		shareOptionsForTest("", uses))
	if !contains(subject, "【森莘】") {
		t.Fatalf("主题应使用系统名称，实际 %q", subject)
	}
	if contains(subject, "NeuroDMS") {
		t.Fatalf("主题不应再出现固定产品名，实际 %q", subject)
	}
	if !contains(text, "通过 森莘 向你分享") || !contains(html, "通过 森莘 向你分享") {
		t.Fatalf("正文应使用系统名称：%s / %s", text, html)
	}

	// 品牌读不到时退回产品名，不能出现【】这种空括号
	subject, _, _ = shareMailBody("", "张三", "合同.docx", "https://x/s/tok", "", shareOptionsForTest("", uses))
	if !contains(subject, "【NeuroDMS】") {
		t.Fatalf("无品牌时应退回产品名，实际 %q", subject)
	}
}

// 品牌里的系统名称要能通过管理台配置，并立刻反映到邮件发件人显示名上。
func TestBrandingDrivesMailFromName(t *testing.T) {
	srv, pool, slug := setupWith(t, func(a *API) {
		box, _ := secretbox.New(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32)))
		a.Mail = notify.NewStore(a.Pool, box)
	})
	tenantID := tenantOf(t, pool, slug)
	seedRole(t, pool, tenantID, userIDByName(t, slug, "bob"), rbac.SysAdmin)
	tok := login(t, srv.URL, slug)

	// 先读默认：显示名由系统名称生成
	_, body := getJSON(t, srv.URL+"/v1/admin/mail", tok)
	if got, _ := dataMap(t, body)["effectiveFromName"].(string); !contains(got, "文档管理系统") {
		t.Fatalf("应给出默认发件人显示名，实际 %q", got)
	}

	resp, out := sendJSONMap(t, http.MethodPut, srv.URL+"/v1/admin/branding", tok, map[string]any{
		"productName": "森莘", "primaryColor": "#12724a", "accentColor": "#0b5fa5", "footerText": "",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("保存品牌失败 %d: %v", resp.StatusCode, out)
	}

	_, body = getJSON(t, srv.URL+"/v1/admin/mail", tok)
	if got, _ := dataMap(t, body)["effectiveFromName"].(string); got != "【森莘文档管理系统】" {
		t.Fatalf("发件人显示名应跟随系统名称，实际 %q", got)
	}
}
