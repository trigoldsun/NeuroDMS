package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// GraphConfig 是 Microsoft 365 / Exchange Online 通道配置。
//
// 为什么用 Graph 而不是 SMTP AUTH：
// 微软已对 Exchange Online 停用 SMTP AUTH 的基本认证，很多租户默认关闭 AUTH，
// 继续依赖它会在客户现场出现"本地能发、上云发不出去"的差异。
// Graph 的应用权限（Mail.Send）是官方长期支持路径。
type GraphConfig struct {
	TenantID     string
	ClientID     string
	ClientSecret string
	// Sender 是发件邮箱（必须是租户内存在的邮箱）
	Sender string
	// LoginBase / GraphBase 可覆盖，便于指向测试服务器或 21Vianet 等主权云
	LoginBase string
	GraphBase string
	Timeout   time.Duration
}

// GraphSender 通过 Microsoft Graph sendMail 发信。
type GraphSender struct {
	cfg  GraphConfig
	http *http.Client

	mu       sync.Mutex
	token    string
	tokenExp time.Time
	now      func() time.Time
}

// NewGraphSender 构造 Graph 通道。
func NewGraphSender(cfg GraphConfig) (*GraphSender, error) {
	if cfg.TenantID == "" || cfg.ClientID == "" || cfg.ClientSecret == "" || cfg.Sender == "" {
		return nil, errors.New("Graph 通道需要 tenantId / clientId / clientSecret / sender")
	}
	if cfg.LoginBase == "" {
		cfg.LoginBase = "https://login.microsoftonline.com"
	}
	if cfg.GraphBase == "" {
		cfg.GraphBase = "https://graph.microsoft.com"
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 20 * time.Second
	}
	return &GraphSender{
		cfg:  cfg,
		http: &http.Client{Timeout: cfg.Timeout},
		now:  time.Now,
	}, nil
}

// Name 实现 Sender。
func (s *GraphSender) Name() string { return "graph" }

// Send 调用 Graph sendMail。
func (s *GraphSender) Send(ctx context.Context, m Message) error {
	if err := validate(m); err != nil {
		return err
	}
	tok, err := s.accessToken(ctx)
	if err != nil {
		return err
	}

	payload := map[string]any{
		"message": map[string]any{
			"subject": m.Subject,
			"body": map[string]any{
				"contentType": pickContentType(m),
				"content":     pickContent(m),
			},
			"toRecipients": []map[string]any{
				{"emailAddress": map[string]any{"address": m.To}},
			},
		},
		"saveToSentItems": true,
	}
	body, _ := json.Marshal(payload)

	endpoint := fmt.Sprintf("%s/v1.0/users/%s/sendMail",
		strings.TrimRight(s.cfg.GraphBase, "/"), url.PathEscape(s.cfg.Sender))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+tok)

	resp, err := s.http.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode/100 == 2 {
		return nil
	}

	// 读取错误体便于排障，但限制长度：对端返回大页面时不该把日志撑爆
	msg, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
	err = fmt.Errorf("graph sendMail 失败: %d %s", resp.StatusCode, strings.TrimSpace(string(msg)))
	// 4xx（除 429）视为永久失败：配置/权限/地址问题，重试无益
	if resp.StatusCode >= 400 && resp.StatusCode < 500 && resp.StatusCode != http.StatusTooManyRequests {
		return Permanent(err)
	}
	return err
}

func pickContentType(m Message) string {
	if m.HTML != "" {
		return "HTML"
	}
	return "Text"
}

func pickContent(m Message) string {
	if m.HTML != "" {
		return m.HTML
	}
	return m.Text
}

// accessToken 取应用令牌并缓存到过期前 60 秒。
//
// 缓存是必须的：每封信换一次令牌会让 Graph 的限流迅速吃掉配额
// （同一 client 的 token 请求也有速率限制）。
func (s *GraphSender) accessToken(ctx context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.token != "" && s.now().Before(s.tokenExp) {
		return s.token, nil
	}

	form := url.Values{
		"client_id":     {s.cfg.ClientID},
		"client_secret": {s.cfg.ClientSecret},
		"scope":         {"https://graph.microsoft.com/.default"},
		"grant_type":    {"client_credentials"},
	}
	endpoint := fmt.Sprintf("%s/%s/oauth2/v2.0/token",
		strings.TrimRight(s.cfg.LoginBase, "/"), url.PathEscape(s.cfg.TenantID))

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := s.http.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()

	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
	if resp.StatusCode != http.StatusOK {
		// 令牌请求失败几乎都是配置错误（密钥过期、权限未授权），归为永久失败
		return "", Permanent(fmt.Errorf("获取 Graph 令牌失败: %d %s", resp.StatusCode, strings.TrimSpace(string(raw))))
	}
	var out struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return "", err
	}
	if out.AccessToken == "" {
		return "", errors.New("Graph 令牌响应缺少 access_token")
	}

	ttl := time.Duration(out.ExpiresIn) * time.Second
	if ttl > time.Minute {
		ttl -= time.Minute
	}
	s.token = out.AccessToken
	s.tokenExp = s.now().Add(ttl)
	return s.token, nil
}
