package notify

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestValidateRejectsBadAddressPermanently(t *testing.T) {
	bad := []Message{
		{To: "", Subject: "x"},
		{To: "no-at-sign", Subject: "x"},
		{To: "a@b", Subject: "x"},   // 缺少顶级域
		{To: "someone@example.com"}, // 主题为空
	}
	for i, m := range bad {
		if err := validate(m); !errors.Is(err, ErrPermanent) {
			t.Fatalf("第 %d 个应判为永久失败，实际 %v", i+1, err)
		}
	}
	// 合法地址（含 + 标签与子域）必须通过
	if err := validate(Message{To: "user+tag@mail.example.com", Subject: "hi"}); err != nil {
		t.Fatalf("合法地址不应被拒: %v", err)
	}
}

func TestBuildMIMEEncodesNonASCIISubject(t *testing.T) {
	raw := string(BuildMIME("noreply@example.com", Message{
		To: "user@example.com", Subject: "文档访问邀请：报价单", Text: "正文内容",
	}))

	if !strings.Contains(raw, "Subject: =?UTF-8?b?") {
		t.Fatalf("中文主题应做 RFC 2047 编码，实际头部: %s", firstLine(raw, "Subject:"))
	}
	if !strings.Contains(raw, "\r\n") {
		// 用 LF 而非 CRLF 会让部分老邮件网关把整封邮件当成头部
		t.Fatal("必须使用 CRLF 换行")
	}
	// 正文 base64 必须可解码回原文
	idx := strings.Index(raw, "Content-Transfer-Encoding: base64\r\n\r\n")
	if idx < 0 {
		t.Fatal("缺少 base64 正文段")
	}
	body := strings.TrimSpace(raw[idx+len("Content-Transfer-Encoding: base64\r\n\r\n"):])
	body = strings.ReplaceAll(body, "\r\n", "")
	dec, err := base64.StdEncoding.DecodeString(body)
	if err != nil {
		t.Fatalf("正文 base64 无法解码: %v", err)
	}
	if string(dec) != "正文内容" {
		t.Fatalf("正文解码不符: %q", string(dec))
	}
}

func firstLine(s, prefix string) string {
	for _, line := range strings.Split(s, "\r\n") {
		if strings.HasPrefix(line, prefix) {
			return line
		}
	}
	return ""
}

func TestBuildMIMEMultipartWhenHTMLPresent(t *testing.T) {
	raw := string(BuildMIME("noreply@example.com", Message{
		To: "user@example.com", Subject: "hi", Text: "text part", HTML: "<p>html part</p>",
	}))
	if !strings.Contains(raw, "multipart/alternative") {
		t.Fatal("同时有纯文本与 HTML 时必须用 multipart/alternative")
	}
	if strings.Count(raw, "Content-Type: text/") != 2 {
		t.Fatal("multipart 应包含 text/plain 与 text/html 两段")
	}
}

type fakeSender struct {
	name string
	err  error
	got  []Message
}

func (f *fakeSender) Name() string { return f.name }
func (f *fakeSender) Send(_ context.Context, m Message) error {
	f.got = append(f.got, m)
	return f.err
}

func TestDispatcherFallsBackWhenPrimaryFails(t *testing.T) {
	primary := &fakeSender{name: "smtp", err: errors.New("连接被拒绝")}
	fallback := &fakeSender{name: "graph"}
	d := NewDispatcher(primary, fallback)

	if err := d.Send(context.Background(), Message{To: "a@example.com", Subject: "s"}); err != nil {
		t.Fatalf("备用通道成功时应返回 nil: %v", err)
	}
	if len(primary.got) != 1 || len(fallback.got) != 1 {
		t.Fatalf("两个通道都应被尝试，实际 primary=%d fallback=%d", len(primary.got), len(fallback.got))
	}
}

func TestDispatcherDoesNotFallbackOnPermanent(t *testing.T) {
	primary := &fakeSender{name: "smtp", err: Permanent(errors.New("收件人不存在"))}
	fallback := &fakeSender{name: "graph"}
	d := NewDispatcher(primary, fallback)

	err := d.Send(context.Background(), Message{To: "a@example.com", Subject: "s"})
	if !errors.Is(err, ErrPermanent) {
		t.Fatalf("应返回永久失败，实际 %v", err)
	}
	if len(fallback.got) != 0 {
		t.Fatal("永久失败不应切备用通道（换通道也发不到不存在的地址）")
	}
}

func TestBackoffGrowsAndCaps(t *testing.T) {
	if backoff(1) != 30*time.Second {
		t.Fatalf("首次重试应 30s，实际 %v", backoff(1))
	}
	if backoff(3) != 2*time.Minute {
		t.Fatalf("第 3 次应 2m，实际 %v", backoff(3))
	}
	if backoff(20) != 30*time.Minute {
		t.Fatalf("应封顶 30m，实际 %v", backoff(20))
	}
}

// ---------------- Graph 通道 ----------------

func TestGraphSenderSendsMailAndCachesToken(t *testing.T) {
	var tokenCalls, sendCalls int
	var gotBody, gotPath string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/oauth2/v2.0/token"):
			tokenCalls++
			_ = r.ParseForm()
			if r.Form.Get("grant_type") != "client_credentials" {
				t.Errorf("应使用 client_credentials，实际 %s", r.Form.Get("grant_type"))
			}
			_, _ = w.Write([]byte(`{"access_token":"tok-1","expires_in":3600}`))
		case strings.Contains(r.URL.Path, "/sendMail"):
			sendCalls++
			gotPath = r.URL.Path
			if r.Header.Get("Authorization") != "Bearer tok-1" {
				t.Errorf("缺少 Bearer 令牌，实际 %s", r.Header.Get("Authorization"))
			}
			buf := make([]byte, 4096)
			n, _ := r.Body.Read(buf)
			gotBody = string(buf[:n])
			w.WriteHeader(http.StatusAccepted)
		default:
			t.Errorf("未预期的路径: %s", r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()

	g, err := NewGraphSender(GraphConfig{
		TenantID: "t", ClientID: "c", ClientSecret: "s", Sender: "docvault@example.com",
		LoginBase: srv.URL, GraphBase: srv.URL,
	})
	if err != nil {
		t.Fatal(err)
	}

	msg := Message{To: "user@example.com", Subject: "邀请", HTML: "<p>hi</p>", Text: "hi"}
	if err := g.Send(context.Background(), msg); err != nil {
		t.Fatalf("发送失败: %v", err)
	}
	// 第二封必须复用令牌：否则每封信换一次令牌会撞上 Graph 限流
	if err := g.Send(context.Background(), msg); err != nil {
		t.Fatalf("第二次发送失败: %v", err)
	}
	if tokenCalls != 1 {
		t.Fatalf("令牌应被缓存，实际请求了 %d 次", tokenCalls)
	}
	if sendCalls != 2 {
		t.Fatalf("应发送 2 次，实际 %d", sendCalls)
	}
	// 发件人在 URL 路径里（/users/{sender}/sendMail），正文类型在 body 里
	if !strings.Contains(gotPath, "docvault@example.com") {
		t.Fatalf("请求路径应包含发件邮箱，实际 %s", gotPath)
	}
	if !strings.Contains(gotBody, "HTML") || !strings.Contains(gotBody, "user@example.com") {
		t.Fatalf("请求体缺少正文类型或收件人: %s", gotBody)
	}
}

func TestGraphSenderClassifiesErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "token") {
			_, _ = w.Write([]byte(`{"access_token":"t","expires_in":3600}`))
			return
		}
		if strings.Contains(r.URL.Path, "sendMail") {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error":{"code":"ErrorAccessDenied"}}`))
			return
		}
		w.WriteHeader(404)
	}))
	defer srv.Close()

	g, _ := NewGraphSender(GraphConfig{
		TenantID: "t", ClientID: "c", ClientSecret: "s", Sender: "a@example.com",
		LoginBase: srv.URL, GraphBase: srv.URL,
	})
	err := g.Send(context.Background(), Message{To: "b@example.com", Subject: "x"})
	if !errors.Is(err, ErrPermanent) {
		t.Fatalf("403 应判为永久失败（权限问题重试无益），实际 %v", err)
	}
}

func TestGraphTokenFailureIsPermanent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"invalid_client"}`))
	}))
	defer srv.Close()

	g, _ := NewGraphSender(GraphConfig{
		TenantID: "t", ClientID: "c", ClientSecret: "bad", Sender: "a@example.com",
		LoginBase: srv.URL, GraphBase: srv.URL,
	})
	err := g.Send(context.Background(), Message{To: "b@example.com", Subject: "x"})
	if !errors.Is(err, ErrPermanent) {
		t.Fatalf("令牌获取失败应判为永久失败，实际 %v", err)
	}
}

// ---------------- SMTP 通道 ----------------

// fakeSMTPServer 是一个只够验证协议交互的最小 SMTP 服务端。
// 用它而不是 mock 发送函数，是为了让"DATA 内容真的被传输"这件事被验证到。
type fakeSMTPServer struct {
	addr              string
	gotData           chan string
	advertiseStartTLS bool
}

func startFakeSMTP(t *testing.T) *fakeSMTPServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &fakeSMTPServer{addr: ln.Addr().String(), gotData: make(chan string, 4)}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go s.handle(conn)
		}
	}()
	return s
}

func (s *fakeSMTPServer) handle(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	r := bufio.NewReader(conn)
	w := func(line string) { _, _ = conn.Write([]byte(line + "\r\n")) }

	w("220 fake ESMTP")
	inData := false
	var data strings.Builder
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return
		}
		trimmed := strings.TrimRight(line, "\r\n")

		if inData {
			if trimmed == "." {
				inData = false
				select {
				case s.gotData <- data.String():
				default:
				}
				w("250 OK queued")
				continue
			}
			// 点号转义：以 . 开头的行在传输时被加了一个点
			data.WriteString(strings.TrimPrefix(trimmed, ".") + "\r\n")
			continue
		}

		upper := strings.ToUpper(trimmed)
		switch {
		case strings.HasPrefix(upper, "EHLO"), strings.HasPrefix(upper, "HELO"):
			ext := "250-fake\r\n"
			if s.advertiseStartTLS {
				ext += "250-STARTTLS\r\n"
			}
			w(ext + "250 8BITMIME")
		case strings.HasPrefix(upper, "MAIL FROM"), strings.HasPrefix(upper, "RCPT TO"):
			w("250 OK")
		case upper == "DATA":
			inData = true
			w("354 send data")
		case upper == "QUIT":
			w("221 bye")
			return
		default:
			w("250 OK")
		}
	}
}

func TestSMTPSenderDeliversMessage(t *testing.T) {
	srv := startFakeSMTP(t)
	host, portStr, _ := net.SplitHostPort(srv.addr)
	var port int
	_, _ = fmt.Sscanf(portStr, "%d", &port)

	s, err := NewSMTPSender(SMTPConfig{
		Host: host, Port: port, From: "noreply@example.com", TLSMode: "none",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Send(context.Background(), Message{
		To: "user@example.com", Subject: "验证码", Text: "您的验证码是 123456",
	}); err != nil {
		t.Fatalf("发送失败: %v", err)
	}

	select {
	case data := <-srv.gotData:
		if !strings.Contains(data, "Subject: =?UTF-8?b?") {
			t.Fatalf("主题未编码: %s", data)
		}
		if !strings.Contains(data, "To: user@example.com") {
			t.Fatalf("缺少收件人头: %s", data)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("服务端未收到邮件数据")
	}
}

// 声明 starttls 但服务端不支持时必须失败，不能静默降级为明文。
func TestSMTPSenderRefusesDowngrade(t *testing.T) {
	srv := startFakeSMTP(t)
	host, portStr, _ := net.SplitHostPort(srv.addr)
	var port int
	_, _ = fmt.Sscanf(portStr, "%d", &port)

	s, err := NewSMTPSender(SMTPConfig{
		Host: host, Port: port, From: "noreply@example.com", TLSMode: "starttls",
	})
	if err != nil {
		t.Fatal(err)
	}
	err = s.Send(context.Background(), Message{To: "user@example.com", Subject: "x"})
	if err == nil || !strings.Contains(err.Error(), "STARTTLS") {
		t.Fatalf("应因缺少 STARTTLS 而失败，实际 %v", err)
	}
}
