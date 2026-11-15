package httpapi

import (
	"bytes"
	"context"
	"encoding/base64"
	"image"
	"image/png"
	"net/http"
	"strings"
	"testing"
)

// 品牌图标（logo）的两个关键约束：
//  1. **只改名称不能把图标清空** —— 早期 SQL 写的是 `logo = EXCLUDED.logo`，
//     而"只改系统名称"的请求里没有 logo，EXCLUDED 为 NULL，改个名字图标就没了。
//  2. 图标会渲染到未登录可见的页面，所以尺寸与格式必须在写入口拦。

func pngBase64(t *testing.T, w, h int) string {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(buf.Bytes())
}

func TestBrandingLogoLifecycle(t *testing.T) {
	srv, pool, _ := setup(t)
	ct := createTenant(t, pool, srv.URL, "logo")

	// 1. 首次保存品牌（还没图标）
	if r, b := sendJSONMap(t, http.MethodPut, srv.URL+"/v1/admin/branding", ct.token, map[string]any{
		"productName": "甲乙科技文档中心", "primaryColor": "#123456", "accentColor": "#654321",
	}); r.StatusCode != 200 {
		t.Fatalf("保存品牌失败 %d: %v", r.StatusCode, b)
	}

	// 2. 上传图标
	if r, b := sendJSONMap(t, http.MethodPut, srv.URL+"/v1/admin/branding", ct.token, map[string]any{
		"productName": "甲乙科技文档中心", "primaryColor": "#123456", "accentColor": "#654321",
		"logoBase64": pngBase64(t, 64, 64), "logoMime": "image/png",
	}); r.StatusCode != 200 {
		t.Fatalf("上传图标失败 %d: %v", r.StatusCode, b)
	}

	readLogo := func() (string, string) {
		resp, body := getJSON(t, srv.URL+"/v1/tenant/branding?slug="+ct.slug, "")
		if resp.StatusCode != 200 {
			t.Fatalf("公开品牌读取失败 %d: %v", resp.StatusCode, body)
		}
		d := dataMap(t, body)
		url, _ := d["logoUrl"].(string)
		mime, _ := d["logoMime"].(string)
		return url, mime
	}

	logoURL, logoMime := readLogo()
	if logoURL == "" || logoMime != "image/png" {
		t.Fatalf("图标未生效: url=%q mime=%q", logoURL, logoMime)
	}

	// 3. **只改名称**：图标必须还在（回归核心）
	if r, b := sendJSONMap(t, http.MethodPut, srv.URL+"/v1/admin/branding", ct.token, map[string]any{
		"productName": "甲乙科技 文档与知识库", "primaryColor": "#123456", "accentColor": "#654321",
	}); r.StatusCode != 200 {
		t.Fatalf("改名称失败 %d: %v", r.StatusCode, b)
	}
	if gotURL, gotMime := readLogo(); gotURL != logoURL || gotMime != "image/png" {
		t.Fatalf("只改名称不应影响图标: before=%q after=%q", logoURL, gotURL)
	}

	// 4. 换图标：URL 指纹必须变（否则浏览器用旧缓存）
	logoURL2, _ := func() (string, string) {
		if r, b := sendJSONMap(t, http.MethodPut, srv.URL+"/v1/admin/branding", ct.token, map[string]any{
			"productName": "甲乙科技 文档与知识库", "primaryColor": "#123456", "accentColor": "#654321",
			"logoBase64": pngBase64(t, 128, 128), "logoMime": "image/png",
		}); r.StatusCode != 200 {
			t.Fatalf("换图标失败 %d: %v", r.StatusCode, b)
		}
		return readLogo()
	}()
	if logoURL2 == "" || logoURL2 == logoURL {
		t.Fatalf("换图标后 URL 指纹应变化: before=%q after=%q", logoURL, logoURL2)
	}

	// 5. 显式移除
	if r, b := sendJSONMap(t, http.MethodPut, srv.URL+"/v1/admin/branding", ct.token, map[string]any{
		"productName": "甲乙科技 文档与知识库", "primaryColor": "#123456", "accentColor": "#654321",
		"removeLogo": true,
	}); r.StatusCode != 200 {
		t.Fatalf("移除图标失败 %d: %v", r.StatusCode, b)
	}
	if gotURL, _ := readLogo(); gotURL != "" {
		t.Fatalf("移除后不应再有 logoUrl: %q", gotURL)
	}

	// 6. 移除必须留痕，且与"更换"区分开：
	//    客户报"我的图标怎么没了"时，只有 logoChanged 分不清是换了还是删了。
	var detail string
	if err := pool.QueryRow(context.Background(), `
		SELECT detail::text FROM audit_event
		 WHERE action = 'tenant.branding.update'
		 ORDER BY seq DESC LIMIT 1`).Scan(&detail); err != nil {
		t.Fatalf("读取审计失败: %v", err)
	}
	if !strings.Contains(detail, "logoRemoved") {
		t.Fatalf("移除图标应记 logoRemoved，实际 %s", detail)
	}
}

func TestBrandingLogoValidation(t *testing.T) {
	srv, pool, _ := setup(t)
	ct := createTenant(t, pool, srv.URL, "logo-bad")

	put := func(extra map[string]any) (int, map[string]any) {
		body := map[string]any{
			"productName": "校验租户", "primaryColor": "#123456", "accentColor": "#654321",
		}
		for k, v := range extra {
			body[k] = v
		}
		r, b := sendJSONMap(t, http.MethodPut, srv.URL+"/v1/admin/branding", ct.token, body)
		return r.StatusCode, b
	}

	cases := []struct {
		name string
		in   map[string]any
	}{
		// 内容与声明不一致：上传"成功"但登录页破图，是最难排查的一类
		{"声明 jpeg 实际 png", map[string]any{
			"logoBase64": pngBase64(t, 64, 64), "logoMime": "image/jpeg",
		}},
		// 太小：放大到 30px 会糊
		{"尺寸过小", map[string]any{
			"logoBase64": pngBase64(t, 8, 8), "logoMime": "image/png",
		}},
		// 不支持的格式
		{"gif 不支持", map[string]any{
			"logoBase64": base64.StdEncoding.EncodeToString([]byte("GIF89a......")),
			"logoMime":   "image/gif",
		}},
		// SVG 里带脚本（会渲染到未登录页面）
		{"SVG 带脚本", map[string]any{
			"logoBase64": base64.StdEncoding.EncodeToString([]byte(
				`<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>`)),
			"logoMime": "image/svg+xml",
		}},
		// 像素上限：字节数挡不住"小文件解成大位图"
		{"像素过大", map[string]any{
			"logoBase64": base64.StdEncoding.EncodeToString(fakePNGHeader(5000, 5000)),
			"logoMime":   "image/png",
		}},
	}
	for _, c := range cases {
		if code, b := put(c.in); code != http.StatusBadRequest {
			t.Fatalf("%s 应 400，实际 %d: %v", c.name, code, b)
		}
	}

	// 合法的最小尺寸与 SVG 必须放行（否则规则过严，客户 32px 的图标也传不了）
	if code, b := put(map[string]any{
		"logoBase64": pngBase64(t, 16, 16), "logoMime": "image/png",
	}); code != 200 {
		t.Fatalf("16×16 应允许，实际 %d: %v", code, b)
	}
	if code, b := put(map[string]any{
		"logoBase64": base64.StdEncoding.EncodeToString([]byte(
			`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"><rect width="64" height="64"/></svg>`)),
		"logoMime": "image/svg+xml",
	}); code != 200 {
		t.Fatalf("干净 SVG 应允许，实际 %d: %v", code, b)
	}
}

// fakePNGHeader 造一个只有头的 PNG（尺寸真实、像素数据缺失）。
// 后端只读头部，所以这足以验证像素上限；不构造真实大图是为了不让测试吃几百 MB 内存。
func fakePNGHeader(w, h uint32) []byte {
	b := make([]byte, 33)
	copy(b, []byte{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A})
	b[8], b[9], b[10], b[11] = 0, 0, 0, 13
	copy(b[12:16], []byte("IHDR"))
	b[16], b[17], b[18], b[19] = byte(w>>24), byte(w>>16), byte(w>>8), byte(w)
	b[20], b[21], b[22], b[23] = byte(h>>24), byte(h>>16), byte(h>>8), byte(h)
	b[24], b[25] = 8, 6
	return b
}
