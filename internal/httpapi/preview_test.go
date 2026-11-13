package httpapi

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"docvault/internal/onlyoffice"
	"docvault/internal/preview"

	"github.com/jackc/pgx/v5/pgxpool"
)

// fakeConv 是测试用的"转换器"：不依赖 LibreOffice，输出可预期的 PDF 字节。
type fakeConv struct{ calls int32 }

func (f *fakeConv) Name() string { return "fake-1" }
func (f *fakeConv) Convert(_ context.Context, src io.Reader, _ string) (io.ReadCloser, error) {
	atomic.AddInt32(&f.calls, 1)
	_, _ = io.ReadAll(src)
	return io.NopCloser(strings.NewReader("%PDF-FAKE")), nil
}

func newFakePreview(t *testing.T) (*preview.Cache, *fakeConv) {
	t.Helper()
	conv := &fakeConv{}
	c, err := preview.NewCache(t.TempDir(), conv)
	if err != nil {
		t.Fatal(err)
	}
	return c, conv
}

// 令牌只能走 Authorization 头：放进查询参数会进访问日志与浏览器历史。
func TestPreviewRejectsTokenInQuery(t *testing.T) {
	srv, _, slug := setupWith(t, nil)
	tok := login(t, srv.URL, slug)
	body := uploadToSpace(t, srv.URL, tok, "note.txt", "hello")
	nodeID := body["nodeId"].(string)

	resp, err := http.Get(srv.URL + "/v1/nodes/" + nodeID + "/preview?token=" + tok)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("查询参数里的令牌不应被接受，实际 %d", resp.StatusCode)
	}
}

func TestPreviewInlineText(t *testing.T) {
	srv, _, slug := setupWith(t, nil)
	tok := login(t, srv.URL, slug)
	body := uploadToSpace(t, srv.URL, tok, "note.txt", "hello preview")
	nodeID := body["nodeId"].(string)

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/v1/nodes/"+nodeID+"/preview", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("预览应成功，实际 %d: %s", resp.StatusCode, raw)
	}
	if !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/plain") {
		t.Fatalf("txt 应内联返回 text/plain，实际 %s", resp.Header.Get("Content-Type"))
	}
	if resp.Header.Get("Content-Disposition") != "inline" {
		t.Fatalf("应为内联展示，实际 %s", resp.Header.Get("Content-Disposition"))
	}
}

func TestPreviewConvertsDocxAndCaches(t *testing.T) {
	cache, conv := newFakePreview(t)
	srv, _, slug := setupWith(t, func(a *API) { a.Preview = cache })
	tok := login(t, srv.URL, slug)
	body := uploadToSpace(t, srv.URL, tok, "report.docx", "fake docx bytes")
	nodeID := body["nodeId"].(string)

	get := func() *http.Response {
		req, _ := http.NewRequest(http.MethodGet, srv.URL+"/v1/nodes/"+nodeID+"/preview", nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}

	r1 := get()
	defer func() { _ = r1.Body.Close() }()
	if r1.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(r1.Body)
		t.Fatalf("转换预览应成功，实际 %d: %s", r1.StatusCode, raw)
	}
	if r1.Header.Get("Content-Type") != "application/pdf" {
		t.Fatalf("应返回 PDF，实际 %s", r1.Header.Get("Content-Type"))
	}
	if r1.Header.Get("X-Preview-Cache") != "miss" {
		t.Fatalf("首次应未命中缓存，实际 %s", r1.Header.Get("X-Preview-Cache"))
	}
	raw, _ := io.ReadAll(r1.Body)
	if !strings.HasPrefix(string(raw), "%PDF-") {
		t.Fatalf("内容应为 PDF，实际 %q", string(raw))
	}

	r2 := get()
	defer func() { _ = r2.Body.Close() }()
	if r2.Header.Get("X-Preview-Cache") != "hit" {
		t.Fatalf("第二次应命中缓存，实际 %s", r2.Header.Get("X-Preview-Cache"))
	}
	if atomic.LoadInt32(&conv.calls) != 1 {
		t.Fatalf("同一版本只应转换一次，实际 %d", conv.calls)
	}
}

// 未装转换器时必须明确 501，而不是 500 或空文件。
func TestPreviewWithoutConverterReturns501(t *testing.T) {
	srv, _, slug := setupWith(t, nil) // 未注入 Preview
	tok := login(t, srv.URL, slug)
	body := uploadToSpace(t, srv.URL, tok, "report.docx", "x")
	nodeID := body["nodeId"].(string)

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/v1/nodes/"+nodeID+"/preview", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotImplemented {
		t.Fatalf("无转换器应返回 501，实际 %d", resp.StatusCode)
	}
}

func TestEditConfigWithoutDocumentServer(t *testing.T) {
	srv, _, slug := setupWith(t, nil)
	tok := login(t, srv.URL, slug)
	body := uploadToSpace(t, srv.URL, tok, "a.docx", "x")
	nodeID := body["nodeId"].(string)

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/v1/nodes/"+nodeID+"/edit?mode=edit", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotImplemented {
		t.Fatalf("未配置文档服务应返回 501，实际 %d", resp.StatusCode)
	}
}

func officeService(t *testing.T, allowed ...string) *onlyoffice.Service {
	t.Helper()
	return onlyoffice.New(onlyoffice.Config{
		URL:          "http://onlyoffice:8080",
		PublicURL:    "http://docvault",
		Secret:       "office-secret-0123456789abcdef",
		AllowedHosts: allowed,
	})
}

func TestEditConfigReturnsSignedURL(t *testing.T) {
	office := officeService(t, "127.0.0.1")
	srv, _, slug := setupWith(t, func(a *API) { a.Office = office })
	tok := login(t, srv.URL, slug)
	body := uploadToSpace(t, srv.URL, tok, "a.docx", "docx-content")
	nodeID := body["nodeId"].(string)

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/v1/nodes/"+nodeID+"/edit?mode=edit", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(resp.Body)
		t.Fatalf("应返回配置，实际 %d: %s", resp.StatusCode, raw)
	}

	var out struct {
		Data struct {
			DocumentServerURL string         `json:"documentServerUrl"`
			Config            map[string]any `json:"config"`
			Mode              string         `json:"mode"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out.Data.DocumentServerURL == "" || out.Data.Mode != "edit" {
		t.Fatalf("配置不完整: %+v", out.Data)
	}
	doc := out.Data.Config["document"].(map[string]any)
	fileURL := doc["url"].(string)
	if !strings.Contains(fileURL, "/v1/onlyoffice/file/"+nodeID) {
		t.Fatalf("文档地址应指向节点: %s", fileURL)
	}

	// 签名 URL 可直接取到文件（文档服务就是这么用的）
	path := fileURL[strings.Index(fileURL, "/v1/onlyoffice/file/"):]
	r2, err := http.Get("http://" + srv.Listener.Addr().String() + path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r2.Body.Close() }()
	if r2.StatusCode != http.StatusOK {
		t.Fatalf("签名 URL 应可下载，实际 %d", r2.StatusCode)
	}
	got, _ := io.ReadAll(r2.Body)
	if string(got) != "docx-content" {
		t.Fatalf("下载内容不符: %q", string(got))
	}

	// 篡改签名必须被拒
	if resp, err := http.Get("http://" + srv.Listener.Addr().String() +
		strings.Replace(path, "s=", "s=tampered", 1)); err == nil {
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("篡改签名应 403，实际 %d", resp.StatusCode)
		}
	}
}

func TestOfficeCallbackRejectsForgedToken(t *testing.T) {
	office := officeService(t, "127.0.0.1")
	srv, _, _ := setupWith(t, func(a *API) { a.Office = office })

	body := `{"key":"abc","status":2,"url":"http://127.0.0.1/x"}`
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/v1/onlyoffice/callback", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer not-a-real-jwt")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("伪造回调应 403，实际 %d", resp.StatusCode)
	}
}

func TestOfficeCallbackSavesNewVersion(t *testing.T) {
	// 文档服务（伪造）：回传一份新内容
	docSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("edited-by-onlyoffice"))
	}))
	defer docSrv.Close()

	office := officeService(t, "127.0.0.1")
	srv, pool, slug := setupWith(t, func(a *API) { a.Office = office })
	tok := login(t, srv.URL, slug)
	body := uploadToSpace(t, srv.URL, tok, "a.docx", "original")
	nodeID := body["nodeId"].(string)

	// 模拟 ONLYOFFICE：把**回调体本身**作为 JWT 载荷签名。
	// key 必须是本系统签发的格式 "{nodeID}-{mode}-{hour}"。
	payload := map[string]any{
		"key":    nodeID + "-edit-498369",
		"status": 2,
		"url":    docSrv.URL + "/cache/file.docx",
	}
	unsigned, err := onlyoffice.SignJWT("office-secret-0123456789abcdef", payload)
	if err != nil {
		t.Fatal(err)
	}
	payload["token"] = unsigned
	raw, _ := json.Marshal(payload)
	_ = tenantOf(t, pool, slug)

	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/v1/onlyoffice/callback", strings.NewReader(string(raw)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+unsigned)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		rawBody, _ := io.ReadAll(resp.Body)
		t.Fatalf("回调应成功，实际 %d: %s", resp.StatusCode, rawBody)
	}
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if out["error"].(float64) != 0 {
		t.Fatalf("回调应返回 error=0，实际 %v", out)
	}

	// 新版本必须落库
	var versions int
	var latest string
	if err := pool.QueryRow(context.Background(), `
		SELECT count(*), max(version_no)::text FROM version WHERE node_id = $1`, nodeID).
		Scan(&versions, &latest); err != nil {
		t.Fatal(err)
	}
	if versions != 2 {
		t.Fatalf("应有 2 个版本（原始 + 编辑后），实际 %d", versions)
	}
	if latest != "2" {
		t.Fatalf("最新版本号应为 2，实际 %s", latest)
	}
}

// ---------------- 辅助 ----------------

// ensureSpace 保证租户下至少有一个空间，并返回其 ID。
func ensureSpace(t *testing.T, url, token string) string {
	t.Helper()
	resp, body := postJSON(t, url+"/v1/spaces", token, map[string]any{"kind": "project", "name": "预览测试"})
	if resp.StatusCode != 200 {
		t.Fatalf("建空间失败: %v", body)
	}
	return dataMap(t, body)["spaceId"].(string)
}

// uploadToSpace 在新建空间里上传文件，返回 data 体。
func uploadToSpace(t *testing.T, url, token, filename, content string) map[string]any {
	t.Helper()
	spaceID := ensureSpace(t, url, token)
	resp, body := upload(t, url+"/v1/spaces/"+spaceID+"/files", token, filename, content)
	if resp.StatusCode != 200 {
		t.Fatalf("上传失败: %v", body)
	}
	return dataMap(t, body)
}

func tenantOf(t *testing.T, pool *pgxpool.Pool, slug string) string {
	t.Helper()
	var id string
	if err := pool.QueryRow(context.Background(),
		`SELECT id::text FROM tenant WHERE slug = $1`, slug).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}
