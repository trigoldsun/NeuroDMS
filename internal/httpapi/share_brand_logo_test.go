package httpapi

import (
	"net/http"
	"strings"
	"testing"
)

// 分享页是访客唯一见到的租户品牌。
//
// 之前页眉渲染了一个 <img src={logoUrl}>，但 redeem 响应里**根本没有 logoUrl**，
// 结果永远显示内置图形——"客户觉得图标没生效"这类问题在服务端测试里能一眼看住。
func TestShareInfoCarriesBrandLogo(t *testing.T) {
	srv, pool, _ := setup(t)
	ct := createTenant(t, pool, srv.URL, "sharelogo")

	if r, b := sendJSONMap(t, http.MethodPut, srv.URL+"/v1/admin/branding", ct.token, map[string]any{
		"productName": "森莘", "primaryColor": "#123456", "accentColor": "#654321",
		"logoBase64": pngBase64(t, 64, 64), "logoMime": "image/png",
	}); r.StatusCode != http.StatusOK {
		t.Fatalf("上传图标失败 %d: %v", r.StatusCode, b)
	}

	_, nodeID := prepareFile(t, srv.URL, ct.token)
	resp, sb := postJSON(t, srv.URL+"/v1/shares", ct.token, map[string]any{
		"objectType": "node", "objectId": nodeID, "expiresInHours": 1,
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("创建分享失败 %d: %v", resp.StatusCode, sb)
	}
	token := dataMap(t, sb)["token"].(string)

	_, rb := getJSON(t, srv.URL+"/v1/public/shares/"+token, "")
	d := dataMap(t, rb)
	logoURL, _ := d["logoUrl"].(string)
	if logoURL == "" {
		t.Fatalf("分享信息里没有 logoUrl: %v", d)
	}
	if !strings.Contains(logoURL, "slug="+ct.slug) || !strings.Contains(logoURL, "v=") {
		t.Fatalf("图标地址应带 slug 与内容指纹，实际 %q", logoURL)
	}
	if d["logoMime"] != "image/png" {
		t.Fatalf("logoMime 应为 image/png，实际 %v", d["logoMime"])
	}
	if d["productName"] != "森莘" {
		t.Fatalf("productName 应来自品牌，实际 %v", d["productName"])
	}

	// 移除图标后分享页必须立刻回到默认图形：访客还在看的旧链接
	// 不能继续挂着一个已经撤掉的标。
	if r, b := sendJSONMap(t, http.MethodPut, srv.URL+"/v1/admin/branding", ct.token, map[string]any{
		"productName": "森莘", "primaryColor": "#123456", "accentColor": "#654321",
		"removeLogo": true,
	}); r.StatusCode != http.StatusOK {
		t.Fatalf("移除图标失败 %d: %v", r.StatusCode, b)
	}
	_, rb2 := getJSON(t, srv.URL+"/v1/public/shares/"+token, "")
	if got, _ := dataMap(t, rb2)["logoUrl"].(string); got != "" {
		t.Fatalf("移除后分享信息不应再有 logoUrl: %q", got)
	}
}
