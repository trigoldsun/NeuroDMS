package webui

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeFile(t *testing.T, dir, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// favicon.ico 没有实体文件时**不能**回退到 index.html：
// 浏览器会把 HTML 当图标解码，标签页上就是一个空白文档图标，
// 看上去像没做完的产品。这里断言它回落到内置的 SVG 图标。
func TestFaviconICOFallsBackToSVG(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "index.html", "<html>app</html>")
	writeFile(t, dir, "favicon.svg", `<svg xmlns="http://www.w3.org/2000/svg"></svg>`)

	h := New(dir)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/favicon.ico", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("期望 200，得到 %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "image/svg+xml") {
		t.Fatalf("Content-Type 应为 image/svg+xml，得到 %q", ct)
	}
	if !strings.Contains(rec.Body.String(), "<svg") {
		t.Fatalf("响应体不是 SVG: %q", rec.Body.String())
	}
}

// 真的放了 favicon.ico 时以文件为准（上面那条回退不能抢在静态文件之前）。
func TestFaviconICOFileWins(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "index.html", "<html>app</html>")
	writeFile(t, dir, "favicon.svg", `<svg xmlns="http://www.w3.org/2000/svg"></svg>`)
	writeFile(t, dir, "favicon.ico", "ICO-HERE")

	h := New(dir)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/favicon.ico", nil))

	if rec.Body.String() != "ICO-HERE" {
		t.Fatalf("应返回真实的 ico 文件，得到 %q", rec.Body.String())
	}
}

// SPA 回退仍然要生效：深层链接刷新不能白屏。
func TestSPAFallbackStillWorks(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "index.html", "<html>app</html>")
	writeFile(t, dir, "favicon.svg", `<svg xmlns="http://www.w3.org/2000/svg"></svg>`)

	h := New(dir)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/files/abc", nil))

	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "app") {
		t.Fatalf("深层链接应回退到 index.html，得到 %d %q", rec.Code, rec.Body.String())
	}
}

// 带扩展名的未知路径（扫描器最常探测的那类）必须 404，不能回退成 200 首页。
//
// 回归背景：/.env、/.git/config 曾经返回 200 + index.html，内容虽然没泄露，
// 但会让扫描器认为"路径存在"，也让真正的 404 失去排障意义。
func TestUnknownFileExtensionIsNotFound(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "index.html", "<html>app</html>")

	h := New(dir)
	for _, p := range []string{"/.env", "/.git/config", "/go.mod", "/backup.sql"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, p, nil))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("%s 应 404，实际 %d", p, rec.Code)
		}
	}
}
