package httpapi

// AC-55：预览产物必须带水印，不能通过预览接口取回原件。
//
// 这条用例针对的是一个很具体的绕过：
//   PDF 属于"浏览器能直接看"的类型，早期实现走的是"原字节直接流出"的捷径。
//   于是"只有 preview 位、没有 download 位"的人，只要把预览地址另存为，
//   就拿到了与下载完全相同的原始文件——密级、水印、下载位全部被绕过。

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"testing"

	"docvault/internal/watermark"

	"github.com/pdfcpu/pdfcpu/pkg/api"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/model"
)

// uploadBytes 上传二进制内容并指定 MIME（现有 upload helper 只接受 string 且不设 Content-Type）。
func uploadBytes(t *testing.T, url, token, filename, ctype string, data []byte) (*http.Response, map[string]any) {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	h := make(map[string][]string)
	h["Content-Disposition"] = []string{`form-data; name="file"; filename="` + filename + `"`}
	h["Content-Type"] = []string{ctype}
	fw, err := mw.CreatePart(h)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fw.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}

	req, _ := http.NewRequest(http.MethodPost, url, &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("上传请求失败: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	return resp, out
}

func samplePDF(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile("../watermark/testdata/sample.pdf")
	if err != nil {
		t.Fatalf("读取测试 PDF 失败: %v", err)
	}
	return b
}

// uploadPDFBytes 上传二进制内容（现有 upload helper 只接受 string）。
func uploadPDFBytes(t *testing.T, url, token, filename string, data []byte) map[string]any {
	t.Helper()
	resp, out := uploadBytes(t, url, token, filename, "application/pdf", data)
	if resp.StatusCode != 200 {
		t.Fatalf("上传 PDF 失败 %d: %v", resp.StatusCode, out)
	}
	return out
}

// AC-55：开启水印后，预览响应必须是"叠过水印的 PDF"，且与原件字节不同。
func TestAC55PreviewIsWatermarkedNotOriginal(t *testing.T) {
	srv, _, slug := setupWith(t, func(a *API) {
		wm, werr := watermark.New("", "")
		if werr != nil {
			t.Fatalf("水印初始化失败: %v", werr)
		}
		a.Watermark = wm
	})
	owner := login(t, srv.URL, slug)
	_, body := postJSON(t, srv.URL+"/v1/spaces", owner, map[string]any{"kind": "project", "name": "水印空间"})
	spaceID := dataMap(t, body)["spaceId"].(string)

	pdf := samplePDF(t)
	up := uploadPDFBytes(t, srv.URL+"/v1/spaces/"+spaceID+"/files", owner, "contract.pdf", pdf)
	nodeID := dataMap(t, up)["nodeId"].(string)

	resp, raw := getRaw(t, srv.URL+"/v1/nodes/"+nodeID+"/preview", owner)
	if resp.StatusCode != 200 {
		t.Fatalf("预览失败 %d: %s", resp.StatusCode, raw)
	}
	if ct := resp.Header.Get("Content-Type"); ct != "application/pdf" {
		t.Fatalf("预览应返回 PDF，实际 %s", ct)
	}
	// 关键断言一：不是原件（字节不同）
	if bytes.Equal(raw, pdf) {
		t.Fatal("AC-55 预览返回了原始字节——等同于绕过下载权限取回原件")
	}
	// 关键断言二：输出仍是合法 PDF，且比原件大（新增了水印 XObject）。
	//
	// 这里不在 HTTP 响应里搜 "/Watermark"：pdfcpu 输出会把页面内容流压缩，
	// 明文标记只存在于解压后的内容流（包内测试用 ExtractContent 验证过）。
	conf := model.NewDefaultConfiguration()
	conf.ValidationMode = model.ValidationRelaxed
	if err := api.Validate(context.Background(), bytes.NewReader(raw), conf, nil); err != nil {
		t.Fatalf("AC-55 预览产物不是合法 PDF: %v", err)
	}
	if len(raw) <= len(pdf) {
		t.Fatalf("带水印的产物应大于原件（新增水印对象），实际 %d ≤ %d", len(raw), len(pdf))
	}
	// 关键断言三：带个人水印的响应不能被缓存复用
	if cc := resp.Header.Get("Cache-Control"); cc != "private, no-store" {
		t.Fatalf("带水印的预览必须 no-store，实际 %q", cc)
	}
	// 原件完好：下载路径仍返回原始字节（有 download 位的人拿到的才是原件）
	if r2, raw2 := getRaw(t, srv.URL+"/v1/nodes/"+nodeID+"/content", owner); r2.StatusCode != 200 {
		t.Fatalf("下载应成功，实际 %d", r2.StatusCode)
	} else if !bytes.Equal(raw2, pdf) {
		t.Fatal("下载路径必须返回原件（水印只作用于预览）")
	}
}

// 未启用转换器且未启用水印时，PDF 直接流出（对照组，说明行为差异来自水印配置）。
func TestPreviewWithoutWatermarkReturnsOriginalPDF(t *testing.T) {
	srv, _, slug := setup(t) // 未注入 Watermark
	owner := login(t, srv.URL, slug)
	_, body := postJSON(t, srv.URL+"/v1/spaces", owner, map[string]any{"kind": "project", "name": "无水分印空间"})
	spaceID := dataMap(t, body)["spaceId"].(string)

	pdf := samplePDF(t)
	up := uploadPDFBytes(t, srv.URL+"/v1/spaces/"+spaceID+"/files", owner, "plain.pdf", pdf)
	nodeID := dataMap(t, up)["nodeId"].(string)

	_, raw := getRaw(t, srv.URL+"/v1/nodes/"+nodeID+"/preview", owner)
	if !bytes.Equal(raw, pdf) {
		t.Fatal("未启用加水印时应原样返回（用于确认差异来自配置而非其他环节）")
	}
}

// 水印失败时必须拒绝，而不是返回未加水印的原件。
func TestPreviewRejectsWhenWatermarkFails(t *testing.T) {
	srv, _, slug := setupWith(t, func(a *API) {
		wm, werr := watermark.New("", "")
		if werr != nil {
			t.Fatalf("水印初始化失败: %v", werr)
		}
		a.Watermark = wm
	})
	owner := login(t, srv.URL, slug)
	_, body := postJSON(t, srv.URL+"/v1/spaces", owner, map[string]any{"kind": "project", "name": "坏文件空间"})
	spaceID := dataMap(t, body)["spaceId"].(string)

	// 伪装成 PDF 的坏文件（魔数正确、结构不对）
	broken := append([]byte("%PDF-1.7\n"), bytes.Repeat([]byte("garbage\n"), 200)...)
	up := uploadPDFBytes(t, srv.URL+"/v1/spaces/"+spaceID+"/files", owner, "broken.pdf", broken)
	nodeID := dataMap(t, up)["nodeId"].(string)

	resp, raw := getRaw(t, srv.URL+"/v1/nodes/"+nodeID+"/preview", owner)
	if resp.StatusCode == 200 {
		t.Fatalf("水印失败时不应返回 200（否则就是未加水印的原件）: %d 字节", len(raw))
	}
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("期望 500 WATERMARK_FAILED，实际 %d: %s", resp.StatusCode, raw)
	}
	if !bytes.Contains(raw, []byte("WATERMARK_FAILED")) {
		t.Fatalf("应返回 WATERMARK_FAILED: %s", raw)
	}
	if bytes.Contains(raw, []byte("garbage")) {
		t.Fatal("错误响应里不应包含文件内容")
	}
	_ = context.Background()
}
