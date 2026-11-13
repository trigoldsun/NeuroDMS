package httpapi

// 上传相关的租户策略：扩展名白名单、超时、以及 MIME 推断。

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// setTenantPolicy 直接改 tenant_config.policy，绕过界面只测行为。
func setTenantPolicy(t *testing.T, pool *pgxpool.Pool, slug string, patch map[string]any) {
	t.Helper()
	ctx := context.Background()
	var tenantID string
	if err := pool.QueryRow(ctx, `SELECT id::text FROM tenant WHERE slug = $1`, slug).Scan(&tenantID); err != nil {
		t.Fatal(err)
	}
	m := map[string]any{}
	var raw []byte
	if err := pool.QueryRow(ctx,
		`SELECT policy FROM tenant_config WHERE tenant_id = $1`, tenantID).Scan(&raw); err == nil && len(raw) > 0 {
		_ = json.Unmarshal(raw, &m)
	}
	for k, v := range patch {
		m[k] = v
	}
	b, _ := json.Marshal(m)
	if _, err := pool.Exec(ctx, `
		INSERT INTO tenant_config (tenant_id, policy) VALUES ($1, $2::jsonb)
		ON CONFLICT (tenant_id) DO UPDATE SET policy = $2::jsonb`,
		tenantID, string(b)); err != nil {
		t.Fatal(err)
	}
}

// 白名单在**上传入口**生效：不在范围内的扩展名直接 415，不落 blob。
func TestUploadExtWhitelist(t *testing.T) {
	srv, pool, slug := setup(t)
	owner := login(t, srv.URL, slug)
	_, body := postJSON(t, srv.URL+"/v1/spaces", owner, map[string]any{"kind": "project", "name": "白名单空间"})
	spaceID := dataMap(t, body)["spaceId"].(string)

	setTenantPolicy(t, pool, slug, map[string]any{"allowedExts": []string{".pdf"}})

	r, o := upload(t, srv.URL+"/v1/spaces/"+spaceID+"/files", owner, "note.txt", "hello")
	if r.StatusCode != http.StatusUnsupportedMediaType || o["code"] != "EXT_NOT_ALLOWED" {
		t.Fatalf("不在白名单的类型应 415 EXT_NOT_ALLOWED，实际 %d: %v", r.StatusCode, o)
	}

	r, o = upload(t, srv.URL+"/v1/spaces/"+spaceID+"/files", owner, "doc.pdf", "%PDF-1.4\n")
	if r.StatusCode != http.StatusOK {
		t.Fatalf("白名单内应放行，实际 %d: %v", r.StatusCode, o)
	}

	// 分片通道同样要拦：否则绕过前端直接调 init 就能传任意类型
	r, o = postJSON(t, srv.URL+"/v1/uploads", owner, map[string]any{
		"spaceId": spaceID, "name": "movie.mkv", "sizeBytes": 1024,
	})
	if r.StatusCode != http.StatusUnsupportedMediaType {
		t.Fatalf("分片入口也应拦截，实际 %d: %v", r.StatusCode, o)
	}

	// 清空白名单 = 不限制
	setTenantPolicy(t, pool, slug, map[string]any{"allowedExts": nil})
	if r2, o2 := upload(t, srv.URL+"/v1/spaces/"+spaceID+"/files", owner, "note.txt", "hello"); r2.StatusCode != http.StatusOK {
		t.Fatalf("清空白名单后应放行，实际 %d: %v", r2.StatusCode, o2)
	}
}

// 浏览器给空/octet-stream 时按扩展名补 mime：
// 这是 HEIC"预览失败"的根因——mime 空导致预览分流把它丢给 LibreOffice。
func TestUploadInfersMimeFromExt(t *testing.T) {
	srv, _, slug := setup(t)
	owner := login(t, srv.URL, slug)
	_, body := postJSON(t, srv.URL+"/v1/spaces", owner, map[string]any{"kind": "project", "name": "MIME 空间"})
	spaceID := dataMap(t, body)["spaceId"].(string)

	// multipart 的 Content-Type 由 CreateFormFile 写成 application/octet-stream，
	// 正好复现 iPhone 上传 HEIC 时的情形
	r, o := upload(t, srv.URL+"/v1/spaces/"+spaceID+"/files", owner, "photo.heic", "ftypheic-fake-bytes")
	if r.StatusCode != http.StatusOK {
		t.Fatalf("上传失败 %d: %v", r.StatusCode, o)
	}
	nodeID := dataMap(t, o)["nodeId"].(string)

	var mime string
	if err := getJSONField(t, srv.URL+"/v1/nodes/"+nodeID, owner, "mime", &mime); err != nil {
		t.Fatal(err)
	}
	if mime != "image/heic" {
		t.Fatalf("HEIC 的 mime 应按扩展名补成 image/heic，实际 %q", mime)
	}

	// 预览必须走"内联返回"而不是转换：返回 200 且 Content-Type 保留 image/heic
	resp, _ := getRaw(t, srv.URL+"/v1/nodes/"+nodeID+"/preview", owner)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("HEIC 预览应直接流式返回，实际 %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "image/heic" {
		t.Fatalf("预览 Content-Type 应为 image/heic，实际 %q", ct)
	}
}

// getJSONField 读某个 JSON 字段（data 段内）。
func getJSONField(t *testing.T, url, token, field string, out any) error {
	t.Helper()
	resp, body := getJSON(t, url, token)
	if resp.StatusCode != http.StatusOK {
		return errStatus(resp.StatusCode)
	}
	d := dataMap(t, body)
	b, _ := json.Marshal(d[field])
	return json.Unmarshal(b, out)
}

type errStatus int

func (e errStatus) Error() string { return "意外状态码 " + http.StatusText(int(e)) }

// 格式目录：清单与预览能力必须由服务端给出，且与真实能力一致。
func TestFormatCatalog(t *testing.T) {
	srv, _, slug := setup(t)
	owner := login(t, srv.URL, slug)

	resp, out := getJSON(t, srv.URL+"/v1/meta/formats", owner)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("格式目录应可读，实际 %d: %v", resp.StatusCode, out)
	}
	d := dataMap(t, out)
	groups, _ := d["groups"].([]any)
	if len(groups) < 5 {
		t.Fatalf("分组过少，实际 %d", len(groups))
	}

	// 展平成 ext -> preview 便于断言
	kind := map[string]string{}
	for _, g := range groups {
		gm := g.(map[string]any)
		for _, it := range gm["items"].([]any) {
			im := it.(map[string]any)
			kind[im["ext"].(string)] = im["preview"].(string)
		}
	}

	cases := map[string]string{
		".pdf":  "native", // 浏览器直接渲染
		".jpg":  "native",
		".txt":  "native",
		".heic": "wasm", // 前端 wasm 解码
		".zip":  "none", // 没有预览通道
		".psd":  "none",
		".html": "none", // 同源渲染有 XSS 风险，走下载
	}
	for ext, want := range cases {
		got, ok := kind[ext]
		if !ok {
			t.Fatalf("清单缺少 %s", ext)
		}
		if got != want {
			t.Fatalf("%s 的预览能力应为 %s，实际 %s", ext, want, got)
		}
	}
	// Office 系列取决于本实例是否注入了转换器：无论哪种，都不能标成 native
	for _, ext := range []string{".docx", ".xlsx", ".pptx"} {
		if kind[ext] == "native" {
			t.Fatalf("%s 必须经转换，不能标 native", ext)
		}
	}
	if n := d["viewable"].(float64); n <= 0 {
		t.Fatalf("可预览数量应大于 0")
	}
}
