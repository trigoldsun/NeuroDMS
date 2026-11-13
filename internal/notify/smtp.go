package notify

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"mime"
	"net"
	"net/smtp"
	"strconv"
	"strings"
	"time"
)

// SMTPConfig 是 SMTP 通道配置。
type SMTPConfig struct {
	Host     string
	Port     int
	Username string
	Password string
	From     string
	// TLSMode: none | starttls | tls（隐式 TLS，常见于 465 端口）
	TLSMode string
	// InsecureSkipVerify 仅用于自签名证书的内网邮件网关。
	// 默认 false：关闭校验等于放弃中间人防护，必须由部署方显式开启。
	InsecureSkipVerify bool
	Timeout            time.Duration
}

// SMTPSender 通过 SMTP 发送。
type SMTPSender struct {
	cfg SMTPConfig
}

// NewSMTPSender 构造 SMTP 通道。
func NewSMTPSender(cfg SMTPConfig) (*SMTPSender, error) {
	if cfg.Host == "" || cfg.From == "" {
		return nil, errors.New("SMTP 需要 host 与 from")
	}
	if cfg.Port == 0 {
		cfg.Port = 587
	}
	if cfg.TLSMode == "" {
		cfg.TLSMode = "starttls"
	}
	switch cfg.TLSMode {
	case "none", "starttls", "tls":
	default:
		return nil, fmt.Errorf("未知 TLSMode: %s", cfg.TLSMode)
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 20 * time.Second
	}
	return &SMTPSender{cfg: cfg}, nil
}

// Name 实现 Sender。
func (s *SMTPSender) Name() string { return "smtp" }

// Send 发送一封邮件。
func (s *SMTPSender) Send(ctx context.Context, m Message) error {
	if err := validate(m); err != nil {
		return err
	}
	raw := BuildMIME(s.cfg.From, m)

	addr := net.JoinHostPort(s.cfg.Host, strconv.Itoa(s.cfg.Port))
	dialer := &net.Dialer{Timeout: s.cfg.Timeout}

	var conn net.Conn
	var err error
	if s.cfg.TLSMode == "tls" {
		conn, err = tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
			ServerName:         s.cfg.Host,
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: s.cfg.InsecureSkipVerify,
		})
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return err
	}
	// 连接级超时：防止对端半开连接把 worker 挂住
	_ = conn.SetDeadline(time.Now().Add(s.cfg.Timeout))
	defer func() { _ = conn.Close() }()

	c, err := smtp.NewClient(conn, s.cfg.Host)
	if err != nil {
		return err
	}
	defer func() { _ = c.Close() }()

	if s.cfg.TLSMode == "starttls" {
		if ok, _ := c.Extension("STARTTLS"); !ok {
			// 声明要 STARTTLS 但服务端不支持时必须失败：
			// 降级为明文会把口令与邮件内容暴露在链路上
			return errors.New("服务端不支持 STARTTLS，已中止（不允许明文降级）")
		}
		if err := c.StartTLS(&tls.Config{
			ServerName:         s.cfg.Host,
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: s.cfg.InsecureSkipVerify,
		}); err != nil {
			return err
		}
	}

	if s.cfg.Username != "" {
		if ok, _ := c.Extension("AUTH"); ok {
			if err := c.Auth(smtp.PlainAuth("", s.cfg.Username, s.cfg.Password, s.cfg.Host)); err != nil {
				return err
			}
		}
	}
	if err := c.Mail(s.cfg.From); err != nil {
		return err
	}
	if err := c.Rcpt(m.To); err != nil {
		return err
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	if _, err := w.Write(raw); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}

// BuildMIME 组装一封符合 RFC 5322 的邮件（必要时用 multipart/alternative）。
//
// 单独暴露成函数是为了能对"非 ASCII 主题编码""点号开头转义"这些细节做单测——
// 这些地方写错不会报错，只会让用户在 Outlook 里看到一堆乱码或被截断。
func BuildMIME(from string, m Message) []byte {
	var b strings.Builder
	b.WriteString("From: " + from + "\r\n")
	b.WriteString("To: " + m.To + "\r\n")
	b.WriteString("Subject: " + encodeHeader(m.Subject) + "\r\n")
	b.WriteString("Date: " + time.Now().Format(time.RFC1123Z) + "\r\n")
	b.WriteString("MIME-Version: 1.0\r\n")

	body := m.Text
	if m.HTML != "" {
		boundary := "=_docvault_" + strconv.FormatInt(time.Now().UnixNano(), 36)
		b.WriteString("Content-Type: multipart/alternative; boundary=\"" + boundary + "\"\r\n\r\n")

		b.WriteString("--" + boundary + "\r\n")
		b.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
		b.WriteString("Content-Transfer-Encoding: base64\r\n\r\n")
		b.WriteString(wrap76(base64.StdEncoding.EncodeToString([]byte(m.Text))))
		b.WriteString("\r\n--" + boundary + "\r\n")
		b.WriteString("Content-Type: text/html; charset=UTF-8\r\n")
		b.WriteString("Content-Transfer-Encoding: base64\r\n\r\n")
		b.WriteString(wrap76(base64.StdEncoding.EncodeToString([]byte(m.HTML))))
		b.WriteString("\r\n--" + boundary + "--\r\n")
		return []byte(b.String())
	}

	b.WriteString("Content-Type: text/plain; charset=UTF-8\r\n")
	b.WriteString("Content-Transfer-Encoding: base64\r\n\r\n")
	b.WriteString(wrap76(base64.StdEncoding.EncodeToString([]byte(body))))
	b.WriteString("\r\n")
	return []byte(b.String())
}

// encodeHeader 对非 ASCII 头做 RFC 2047 编码。
func encodeHeader(s string) string {
	for _, r := range s {
		if r > 127 {
			return mime.BEncoding.Encode("UTF-8", s)
		}
	}
	return s
}

// wrap76 按 76 字符换行（base64 的标准行宽）。
func wrap76(s string) string {
	const width = 76
	var b strings.Builder
	for len(s) > width {
		b.WriteString(s[:width])
		b.WriteString("\r\n")
		s = s[width:]
	}
	b.WriteString(s)
	return b.String()
}
