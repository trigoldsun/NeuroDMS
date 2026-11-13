package scan

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// fakeClamd 起一个最小的 clamd 服务端（INSTREAM 协议），返回地址。
//
// 用真实协议而不是打桩：INSTREAM 的分帧（4 字节大端长度 + 零结尾）
// 是最容易写错的地方，打桩测不出"长度写成本机字节序"这类错误。
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
				if !strings.HasPrefix(string(hdr), "zINSTREAM") {
					return
				}
				// 读取分块直到零长度
				var total int
				var lenBuf [4]byte
				for {
					if _, err := io.ReadFull(c, lenBuf[:]); err != nil {
						return
					}
					n := binary.BigEndian.Uint32(lenBuf[:])
					if n == 0 {
						break
					}
					total += int(n)
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

func TestScanClean(t *testing.T) {
	addr := fakeClamd(t, "stream: OK")
	c := New(addr, 5*time.Second)
	res, err := c.Scan(context.Background(), bytes.NewReader([]byte("hello world")))
	if err != nil {
		t.Fatalf("扫描失败: %v", err)
	}
	if res.Verdict != Clean {
		t.Fatalf("应判定 clean，实际 %v (%s)", res.Verdict, res.Detail)
	}
}

// AC-69：命中特征时必须返回 infected 并带特征名。
func TestScanInfected(t *testing.T) {
	addr := fakeClamd(t, "stream: Eicar-Test-Signature FOUND")
	c := New(addr, 5*time.Second)
	res, err := c.Scan(context.Background(), bytes.NewReader([]byte("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR")))
	if err != nil {
		t.Fatalf("扫描失败: %v", err)
	}
	if res.Verdict != Infected {
		t.Fatalf("应判定 infected，实际 %v", res.Verdict)
	}
	if !strings.Contains(res.Signature, "Eicar") {
		t.Fatalf("特征名解析错误: %q", res.Signature)
	}
}

// 未配置扫描器必须显式返回 not_scanned，而不是"clean"——
// 把未扫描当作通过，会让病毒防护在最需要它的时候静默失效。
func TestScanNotConfigured(t *testing.T) {
	res, err := New("", 0).Scan(context.Background(), bytes.NewReader(nil))
	if err != nil {
		t.Fatal(err)
	}
	if res.Verdict != NotScanned {
		t.Fatalf("未配置应返回 not_scanned，实际 %v", res.Verdict)
	}
}

// 扫描器不可达 → Failed（调用方据此拒绝上传，fail-closed）。
func TestScanUnreachable(t *testing.T) {
	c := New("127.0.0.1:1", 300*time.Millisecond)
	res, err := c.Scan(context.Background(), bytes.NewReader([]byte("x")))
	if res.Verdict != Failed {
		t.Fatalf("不可达应返回 failed，实际 %v", res.Verdict)
	}
	if err == nil {
		t.Fatal("不可达应同时返回 error")
	}
}

// 看不懂的响应必须判 Failed，不能当作 OK。
func TestParseReplyFailClosed(t *testing.T) {
	cases := map[string]Verdict{
		"stream: OK":                   Clean,
		"stream: Foo FOUND":            Infected,
		"ERROR: something":             Failed,
		"":                             Failed,
		"INSTREAM size limit exceeded": Failed,
	}
	for in, want := range cases {
		if got := parseReply(in).Verdict; got != want {
			t.Errorf("%q → 期望 %v，实际 %v", in, want, got)
		}
	}
}
