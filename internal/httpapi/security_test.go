package httpapi

// M2-D 上传侧安全用例：SVG 净化、病毒扫描、扫描器故障时的 fail-closed。

import (
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"docvault/internal/scan"
)

// fakeClamd 起一个最小 clamd 服务端（INSTREAM 协议）。
func fakeClamd(t *testing.T, reply string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				hdr := make([]byte, 10)
				if _, err := io.ReadFull(c, hdr); err != nil {
					return
				}
				var lenBuf [4]byte
				for {
					if _, err := io.ReadFull(c, lenBuf[:]); err != nil {
						return
					}
					n := binary.BigEndian.Uint32(lenBuf[:])
					if n == 0 {
						break
					}
					if _, err := io.CopyN(io.Discard, c, int64(n)); err != nil {
						return
					}
				}
				_, _ = c.Write(append([]byte(reply), 0))
			}(conn)
		}
	}()
	return ln.Addr().String()
}

// AC-70：含脚本的 SVG 上传后必须已被净化（不是"拒绝"也不是"原样存"）。
func TestAC70SVGScriptStrippedOnUpload(t *testing.T) {
	srv, _, slug := setup(t)
	owner := login(t, srv.URL, slug)
	_, body := postJSON(t, srv.URL+"/v1/spaces", owner, map[string]any{"kind": "project", "name": "SVG 空间"})
	spaceID := dataMap(t, body)["spaceId"].(string)

	evil := `<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)">` +
		`<script>fetch('/v1/me')</script><rect width="10" height="10"/></svg>`
	resp, out := upload(t, srv.URL+"/v1/spaces/"+spaceID+"/files", owner, "pic.svg", evil)
	if resp.StatusCode != 200 {
		t.Fatalf("安全 SVG 经净化后应可上传，实际 %d: %v", resp.StatusCode, out)
	}
	nodeID := dataMap(t, out)["nodeId"].(string)

	_, raw := getRaw(t, srv.URL+"/v1/nodes/"+nodeID+"/content", owner)
	s := string(raw)
	if strings.Contains(strings.ToLower(s), "<script") || strings.Contains(s, "fetch(") ||
		strings.Contains(strings.ToLower(s), "onload") {
		t.Fatalf("AC-70 存储内容仍含脚本: %s", s)
	}
	if !strings.Contains(s, "rect") {
		t.Fatalf("AC-70 正常图形被破坏: %s", s)
	}
}

// AC-69：命中病毒特征的上传必须被拒，且不落盘。
func TestAC69VirusUploadRejected(t *testing.T) {
	addr := fakeClamd(t, "stream: Eicar-Test-Signature FOUND")
	srv, _, slug := setupWith(t, func(a *API) {
		a.Scanner = scan.New(addr, 3*time.Second)
	})
	owner := login(t, srv.URL, slug)
	_, body := postJSON(t, srv.URL+"/v1/spaces", owner, map[string]any{"kind": "project", "name": "扫描空间"})
	spaceID := dataMap(t, body)["spaceId"].(string)

	resp, out := upload(t, srv.URL+"/v1/spaces/"+spaceID+"/files", owner, "eicar.txt",
		`X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*`)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("AC-69 命中特征应 400，实际 %d: %v", resp.StatusCode, out)
	}
	if out["code"] != "VIRUS_DETECTED" {
		t.Fatalf("AC-69 应返回 VIRUS_DETECTED: %v", out)
	}

	_, list := getJSON(t, srv.URL+"/v1/spaces/"+spaceID+"/nodes", owner)
	if items, _ := dataMap(t, list)["items"].([]any); len(items) != 0 {
		t.Fatalf("AC-69 被拒后不应留下文件，实际 %d 个", len(items))
	}
}

// 扫描器故障必须拒绝上传：否则"打挂 ClamAV"就是一条上传通道。
func TestScanUnavailableFailsClosed(t *testing.T) {
	srv, _, slug := setupWith(t, func(a *API) {
		a.Scanner = scan.New("127.0.0.1:1", 300*time.Millisecond)
	})
	owner := login(t, srv.URL, slug)
	_, body := postJSON(t, srv.URL+"/v1/spaces", owner, map[string]any{"kind": "project", "name": "故障空间"})
	spaceID := dataMap(t, body)["spaceId"].(string)

	resp, out := upload(t, srv.URL+"/v1/spaces/"+spaceID+"/files", owner, "a.txt", "hello")
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("扫描器不可用应 503，实际 %d: %v", resp.StatusCode, out)
	}
	if out["code"] != "SCAN_UNAVAILABLE" {
		t.Fatalf("应返回 SCAN_UNAVAILABLE: %v", out)
	}
}

// 扫描器正常时应照常上传（避免"为了安全把功能关死"）。
func TestScanCleanAllowsUpload(t *testing.T) {
	addr := fakeClamd(t, "stream: OK")
	srv, _, slug := setupWith(t, func(a *API) {
		a.Scanner = scan.New(addr, 3*time.Second)
	})
	owner := login(t, srv.URL, slug)
	_, body := postJSON(t, srv.URL+"/v1/spaces", owner, map[string]any{"kind": "project", "name": "正常空间"})
	spaceID := dataMap(t, body)["spaceId"].(string)

	if resp, out := upload(t, srv.URL+"/v1/spaces/"+spaceID+"/files", owner, "ok.txt", "hello"); resp.StatusCode != 200 {
		t.Fatalf("干净文件应上传成功，实际 %d: %v", resp.StatusCode, out)
	}
}
