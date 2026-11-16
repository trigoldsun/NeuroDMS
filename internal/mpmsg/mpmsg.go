// Package mpmsg 发送微信小程序订阅消息（目前只用于「审批提醒」）。
//
// 三个前提，缺一不可（缺了就整体关闭，不半开）：
//  1. 平台侧配置了 DOCVAULT_WX_APPID / DOCVAULT_WX_APPSECRET / DOCVAULT_WX_TODO_TEMPLATE；
//  2. 账号绑定过 openid（客户端 wx.login 换 code，服务端换 openid）；
//  3. 用户点过「开启提醒」——一次性订阅，授权一次只能发一条（mp_subscription.remaining）。
//
// 为什么不在业务事务里直接发：微信接口会超时、会限流、会因为模板被删而报错。
// 把外呼放在事务里，一次网络抖动就能让"创建分享"整体失败。
// 所以这里的语义是：**通知失败不影响业务成功**，失败只记日志与审计。
package mpmsg

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

	"docvault/internal/db"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// 三种"发不出去"的原因。调用方据此决定日志级别，不要把"没配置"当故障刷屏。
var (
	ErrDisabled  = errors.New("未配置小程序消息通道")
	ErrNoOpenID  = errors.New("账号未绑定微信")
	ErrNoConsent = errors.New("用户未授权或授权次数已用完")
)

// Config 是平台级配置。全部来自环境变量，不允许写死。
type Config struct {
	AppID          string
	AppSecret      string
	TodoTemplateID string
	// Fields 是「模板字段名 → 语义键」的映射；nil 表示用 DefaultFields。
	// 由公众平台上实际选用的模板决定，见 fields.go。
	Fields map[string]string
	// MPState 是点击通知后跳转的小程序版本：developer / trial / formal。
	MPState string
	// BaseURL 可指向测试服务器（默认 https://api.weixin.qq.com）
	BaseURL string
	// Page 是点击消息后跳转的小程序页面（不带前导斜杠）
	Page string
	HTTP *http.Client
	// Now 便于测试控制 access_token 过期
	Now func() time.Time
}

// Service 同时承担"绑定 openid"与"发送订阅消息"。
type Service struct {
	cfg  Config
	pool *pgxpool.Pool

	mu       sync.Mutex
	token    string
	tokenExp time.Time
}

// New 构造服务。cfg 不完整时返回的服务 Enabled()=false，调用方无需判空。
func New(cfg Config, pool *pgxpool.Pool) *Service {
	if cfg.BaseURL == "" {
		cfg.BaseURL = "https://api.weixin.qq.com"
	}
	if cfg.Page == "" {
		cfg.Page = "pages/approvals/approvals"
	}
	if cfg.HTTP == nil {
		cfg.HTTP = &http.Client{Timeout: 8 * time.Second}
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.MPState == "" {
		cfg.MPState = StateFormal
	}
	if len(cfg.Fields) == 0 {
		cfg.Fields = DefaultFields
	}
	return &Service{cfg: cfg, pool: pool}
}

// Enabled 表示三要素齐全。缺一个就整体关闭：
// 只配了一半的通道会表现成"界面上有开关、点了永远收不到"。
func (s *Service) Enabled() bool {
	return s != nil && s.cfg.AppID != "" && s.cfg.AppSecret != "" && s.cfg.TodoTemplateID != ""
}

func (s *Service) TemplateID() string {
	if s == nil {
		return ""
	}
	return s.cfg.TodoTemplateID
}

// wxResp 是微信通用返回。errcode=0 表示成功。
type wxResp struct {
	ErrCode      int    `json:"errcode"`
	ErrMsg       string `json:"errmsg"`
	AccessToken  string `json:"access_token"`
	ExpiresIn    int    `json:"expires_in"`
	OpenID       string `json:"openid"`
	SessionKey   string `json:"session_key"`
	ErrorCode    int    `json:"errorCode"`
	ErrorMessage string `json:"errorMessage"`
}

func (r wxResp) err() error {
	code := r.ErrCode
	msg := r.ErrMsg
	if code == 0 && r.ErrorCode != 0 { // jscode2session 用 errorCode
		code, msg = r.ErrorCode, r.ErrorMessage
	}
	if code == 0 {
		return nil
	}
	return fmt.Errorf("微信接口错误 %d：%s", code, msg)
}

// accessToken 取（并缓存）接口调用凭据。
//
// 提前 120 秒过期：微信侧 token 有效期 7200 秒，且**新 token 会让旧 token 在
// 5 分钟后失效**——卡在边界上会出现"刚取到就 40001"的偶发失败。
func (s *Service) accessToken(ctx context.Context) (string, error) {
	s.mu.Lock()
	if s.token != "" && s.cfg.Now().Before(s.tokenExp) {
		t := s.token
		s.mu.Unlock()
		return t, nil
	}
	s.mu.Unlock()

	q := url.Values{}
	q.Set("grant_type", "client_credential")
	q.Set("appid", s.cfg.AppID)
	q.Set("secret", s.cfg.AppSecret)
	var out wxResp
	if err := s.getJSON(ctx, "/cgi-bin/token?"+q.Encode(), &out); err != nil {
		return "", err
	}
	if e := out.err(); e != nil {
		return "", e
	}
	if out.AccessToken == "" {
		return "", errors.New("微信未返回 access_token")
	}
	ttl := time.Duration(out.ExpiresIn) * time.Second
	if ttl <= 0 {
		ttl = 7200 * time.Second
	}
	if ttl > 120*time.Second {
		ttl -= 120 * time.Second
	}

	s.mu.Lock()
	s.token = out.AccessToken
	s.tokenExp = s.cfg.Now().Add(ttl)
	s.mu.Unlock()
	return out.AccessToken, nil
}

func (s *Service) getJSON(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.cfg.BaseURL+path, nil)
	if err != nil {
		return err
	}
	resp, err := s.cfg.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("微信接口 HTTP %d", resp.StatusCode)
	}
	return json.Unmarshal(body, out)
}

// Bind 用 wx.login 的 code 换 openid 并落库。
//
// 换不到就报错（不要静默成功）：调用方要能告诉用户"提醒功能没开起来"，
// 而不是让人以为开了却永远收不到。
func (s *Service) Bind(ctx context.Context, tenantID, userID, jsCode string) (string, error) {
	if !s.Enabled() {
		return "", ErrDisabled
	}
	if strings.TrimSpace(jsCode) == "" {
		return "", errors.New("code 不能为空")
	}
	q := url.Values{}
	q.Set("appid", s.cfg.AppID)
	q.Set("secret", s.cfg.AppSecret)
	q.Set("js_code", jsCode)
	q.Set("grant_type", "authorization_code")
	var out wxResp
	if err := s.getJSON(ctx, "/sns/jscode2session?"+q.Encode(), &out); err != nil {
		return "", err
	}
	if e := out.err(); e != nil {
		return "", e
	}
	if out.OpenID == "" {
		return "", errors.New("微信未返回 openid")
	}
	err := db.WithTenant(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		ct, e := tx.Exec(ctx,
			`UPDATE app_user SET mp_openid = $1, mp_openid_at = now(), updated_at = now()
			  WHERE id = $2 AND deleted_at IS NULL`, out.OpenID, userID)
		if e != nil {
			return e
		}
		if ct.RowsAffected() == 0 {
			return errors.New("账号不存在")
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	return out.OpenID, nil
}

// Grant 记录一次用户授权（一次性订阅可能一次给多条）。
//
// 上限 10 条：微信一次授权最多返回一条（accept），但客户端可能连点多次；
// 不设上限会累积成"永远发不完"的余额，等于把一次性订阅当成长期授权。
func (s *Service) Grant(ctx context.Context, tenantID, userID, templateID string, n int) (int, error) {
	if !s.Enabled() {
		return 0, ErrDisabled
	}
	if templateID == "" {
		templateID = s.cfg.TodoTemplateID
	}
	if templateID != s.cfg.TodoTemplateID {
		return 0, errors.New("模板不属于当前小程序")
	}
	if n <= 0 {
		n = 1
	}
	var remaining int
	err := db.WithTenant(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
			INSERT INTO mp_subscription (tenant_id, user_id, template_id, remaining, updated_at)
			VALUES ($1, $2, $3, LEAST($4, 10), now())
			ON CONFLICT (tenant_id, user_id, template_id) DO UPDATE
			   SET remaining = LEAST(mp_subscription.remaining + $4, 10), updated_at = now()
			RETURNING remaining`, tenantID, userID, templateID, n).Scan(&remaining)
	})
	return remaining, err
}

// Remaining 返回当前账号的授权余额；未绑定/未授权都是 0。
func (s *Service) Remaining(ctx context.Context, tenantID, userID string) (int, bool, error) {
	var remaining int
	var openid *string
	err := db.WithTenant(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		if e := tx.QueryRow(ctx, `SELECT mp_openid FROM app_user WHERE id = $1`, userID).Scan(&openid); e != nil {
			return e
		}
		return tx.QueryRow(ctx,
			`SELECT remaining FROM mp_subscription WHERE tenant_id = $1 AND user_id = $2 AND template_id = $3`,
			tenantID, userID, s.TemplateID()).Scan(&remaining)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, openid != nil && *openid != "", nil
	}
	if err != nil {
		return 0, false, err
	}
	return remaining, openid != nil && *openid != "", nil
}

// Todo 是一条审批提醒的内容。
type Todo struct {
	FileName  string
	Requester string
	ShareID   string
	CreatedAt time.Time
}

// NotifyApproval 给审批人发一条「有新的外发申请」。
//
// 返回值只用于日志/审计，**调用方不得据此回滚业务**：
// 分享已经建好了，通知失败不该让用户白填一遍表单。
func (s *Service) NotifyApproval(ctx context.Context, tenantID, approverID string, t Todo) error {
	if !s.Enabled() {
		return ErrDisabled
	}
	var openid *string
	err := db.WithTenant(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT mp_openid FROM app_user WHERE id = $1`, approverID).Scan(&openid)
	})
	if err != nil {
		return err
	}
	if openid == nil || *openid == "" {
		return ErrNoOpenID
	}

	// 先占额度再发：两个并发的分享创建不会把同一条授权用两次。
	// 发失败只退不退额度都有代价，这里选择"不退"—— 宁可少发一条，
	// 也不要在微信已经报错的情况下继续消耗用户信任。
	var left int
	err = db.WithTenant(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
			UPDATE mp_subscription SET remaining = remaining - 1, updated_at = now()
			 WHERE tenant_id = $1 AND user_id = $2 AND template_id = $3 AND remaining > 0
			 RETURNING remaining`, tenantID, approverID, s.cfg.TodoTemplateID).Scan(&left)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNoConsent
	}
	if err != nil {
		return err
	}

	token, err := s.accessToken(ctx)
	if err != nil {
		return err
	}
	// data 必须与公众平台上那个模板的字段逐字对应：多一个、少一个、
	// 类型不对都会被微信拒绝（47003/47004）。字段名因此来自配置，不写死。
	data := make(map[string]any, len(s.cfg.Fields))
	for field, semantic := range s.cfg.Fields {
		data[field] = map[string]string{"value": clipByField(field, valueOf(semantic, t))}
	}
	payload := map[string]any{
		"touser":            *openid,
		"template_id":       s.cfg.TodoTemplateID,
		"page":              s.cfg.Page + "?id=" + url.QueryEscape(t.ShareID),
		"data":              data,
		"miniprogram_state": s.cfg.MPState,
		"lang":              "zh_CN",
	}
	body, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		s.cfg.BaseURL+"/cgi-bin/message/subscribe/send?access_token="+url.QueryEscape(token),
		bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("content-type", "application/json")
	resp, err := s.cfg.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	var out wxResp
	if err := json.Unmarshal(raw, &out); err != nil {
		return fmt.Errorf("微信返回无法解析：%s", clip(string(raw), 120))
	}
	return out.err()
}

// clip 按"字符"截断（微信字段有长度上限，按字节截会把汉字截成半个）。
func clip(s string, n int) string {
	r := []rune(strings.TrimSpace(s))
	if len(r) <= n {
		return string(r)
	}
	return string(r[:n])
}
