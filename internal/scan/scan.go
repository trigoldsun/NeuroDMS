// Package scan 提供病毒扫描（ClamAV clamd INSTREAM 协议）。
//
// 为什么必须显式区分"未扫描"与"扫描通过"：
// 大量系统的做法是"没配扫描器就当通过"，于是病毒防护在最需要它的时候（漏配）
// 完全静默。这里的 Verdict 只有三种：Clean / Infected / NotScanned，
// 调用方必须对 NotScanned 做出选择（本项目的选择是：按配置决定拒绝或放行并标注）。
package scan

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// Verdict 是扫描结论。
type Verdict string

const (
	// Clean 未发现威胁
	Clean Verdict = "clean"
	// Infected 命中特征
	Infected Verdict = "infected"
	// NotScanned 未配置扫描器
	NotScanned Verdict = "not_scanned"
	// Failed 扫描器不可用或超时
	Failed Verdict = "failed"
)

// Result 是扫描结果。Signature 仅在 Infected 时有值。
type Result struct {
	Verdict   Verdict
	Signature string
	Detail    string
}

// Client 是 clamd 客户端。
type Client struct {
	Addr    string // host:port
	Timeout time.Duration
}

// New 创建客户端；addr 为空返回 nil（表示未启用）。
func New(addr string, timeout time.Duration) *Client {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return nil
	}
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	return &Client{Addr: addr, Timeout: timeout}
}

// Scan 通过 INSTREAM 扫描内容。
//
// 协议：发送 "zINSTREAM\0"，随后若干块 [4 字节大端长度][数据]，以长度 0 结束，
// 服务端回一行文本，如 "stream: Eicar-Test-Signature FOUND" 或 "stream: OK"。
//
// 用 INSTREAM 而不是先落盘再 FILDES：扫描发生在写盘之前，
// 恶意样本不会有机会进入存储目录（哪怕是临时的）。
func (c *Client) Scan(ctx context.Context, r io.Reader) (Result, error) {
	if c == nil {
		return Result{Verdict: NotScanned, Detail: "未配置 ClamAV"}, nil
	}

	d := net.Dialer{Timeout: c.Timeout}
	conn, err := d.DialContext(ctx, "tcp", c.Addr)
	if err != nil {
		return Result{Verdict: Failed, Detail: "连接扫描器失败"}, fmt.Errorf("连接 clamd 失败: %w", err)
	}
	defer conn.Close()

	deadline := time.Now().Add(c.Timeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	_ = conn.SetDeadline(deadline)

	if _, err := conn.Write([]byte("zINSTREAM\x00")); err != nil {
		return Result{Verdict: Failed, Detail: "发送命令失败"}, err
	}

	buf := make([]byte, 64*1024)
	var lenBuf [4]byte
	for {
		n, rerr := r.Read(buf)
		if n > 0 {
			binary.BigEndian.PutUint32(lenBuf[:], uint32(n))
			if _, err := conn.Write(lenBuf[:]); err != nil {
				return Result{Verdict: Failed, Detail: "发送数据失败"}, err
			}
			if _, err := conn.Write(buf[:n]); err != nil {
				return Result{Verdict: Failed, Detail: "发送数据失败"}, err
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return Result{Verdict: Failed, Detail: "读取待扫描内容失败"}, rerr
		}
	}
	// 结束标记
	binary.BigEndian.PutUint32(lenBuf[:], 0)
	if _, err := conn.Write(lenBuf[:]); err != nil {
		return Result{Verdict: Failed, Detail: "发送结束标记失败"}, err
	}

	reply, err := io.ReadAll(io.LimitReader(conn, 4096))
	if err != nil {
		return Result{Verdict: Failed, Detail: "读取扫描结果失败"}, err
	}
	return parseReply(string(reply)), nil
}

// parseReply 解析 clamd 的返回。
//
// fail-closed：既不是 OK 也不是 FOUND 的回复一律视为 Failed，
// 绝不"看不懂就当通过"。
func parseReply(s string) Result {
	s = strings.TrimSpace(strings.Trim(s, "\x00"))
	lower := strings.ToLower(s)
	switch {
	case strings.Contains(lower, "found"):
		// 形如 "stream: Eicar-Test-Signature FOUND"
		sig := s
		if i := strings.Index(s, ":"); i >= 0 {
			sig = strings.TrimSpace(s[i+1:])
		}
		sig = strings.TrimSuffix(strings.TrimSuffix(sig, "FOUND"), "found")
		sig = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(sig), ":"))
		return Result{Verdict: Infected, Signature: sig, Detail: s}
	case strings.HasSuffix(lower, "ok"):
		return Result{Verdict: Clean, Detail: s}
	default:
		return Result{Verdict: Failed, Detail: "无法识别的扫描响应: " + s}
	}
}
