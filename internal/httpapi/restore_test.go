package httpapi

// 历史回退的 HTTP 层契约：状态码与错误码必须稳定，
// 因为前端只是把 message 透出来，靠 code 区分处置方式。

import (
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
)

// 重复回退：内容已与目标版本相同，必须 409 而不是再追加一个版本。
func TestRestoreTwiceReturnsContentSame(t *testing.T) {
	srv, _, slug := setup(t)
	owner := login(t, srv.URL, slug)
	spaceID, nodeID := prepareFile(t, srv.URL, owner)
	upload(t, srv.URL+"/v1/spaces/"+spaceID+"/files", owner, "report.txt", "第二版内容")

	r, raw := sendJSON(t, http.MethodPost,
		srv.URL+"/v1/nodes/"+nodeID+"/versions/1/restore", owner, map[string]any{})
	if r.StatusCode != http.StatusOK {
		t.Fatalf("首次回退应 200，实际 %d: %s", r.StatusCode, raw)
	}

	r, raw = sendJSON(t, http.MethodPost,
		srv.URL+"/v1/nodes/"+nodeID+"/versions/1/restore", owner, map[string]any{})
	if r.StatusCode != http.StatusConflict || !strings.Contains(string(raw), "VERSION_CONTENT_SAME") {
		t.Fatalf("重复回退应 409 VERSION_CONTENT_SAME，实际 %d: %s", r.StatusCode, raw)
	}
}

// 按版本下载：内容取指定版本，Content-Length 也必须是该版本大小。
// 若沿用 node 当前大小，响应会被截断或挂起——这是最容易被忽略的一处。
func TestVersionDownloadReturnsOldContent(t *testing.T) {
	srv, _, slug := setup(t)
	owner := login(t, srv.URL, slug)
	spaceID, nodeID := prepareFile(t, srv.URL, owner)
	upload(t, srv.URL+"/v1/spaces/"+spaceID+"/files", owner, "report.txt", "第二版内容")

	const oldContent = "敏感内容-不得泄漏"
	req, err := http.NewRequest(http.MethodGet,
		srv.URL+"/v1/nodes/"+nodeID+"/versions/1/download", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+owner)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("按版本下载应 200，实际 %d: %s", resp.StatusCode, string(b))
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != oldContent {
		t.Fatalf("应下载 v1 的内容，实际 %q", string(body))
	}
	if got := resp.Header.Get("Content-Length"); got != strconv.Itoa(len(oldContent)) {
		t.Fatalf("Content-Length 应为该版本大小 %d，实际 %s", len(oldContent), got)
	}
}
