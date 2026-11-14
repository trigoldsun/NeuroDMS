// Package idp 是外部身份认证的 P0 验证实现（尚未接入产品流程）。
//
// 这一版只做**最小可验证内核**：OIDC RP 的取令牌与校验、一次性 state/nonce、
// PKCE。它的用途是回答"这套协议在我们的栈里能不能被正确校验"，
// 而不是"登录页怎么排"。接入产品（P1）时，本包会被 handlers 复用。
//
// 三条刻意的取舍：
//  1. 校验全部交给 `coreos/go-oidc`：id_token 的签名、iss/aud/exp 校验是
//     安全边界，自己写就是在重新发明已知的坑；
//  2. state/nonce/verifier 一次性消费（Take 即删除）：重放必须失败；
//  3. 只接受 `sub` 作为身份键，邮箱仅作为属性（可改、可空、可不唯一）。
package idp

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// ErrStateInvalid 表示回调里的 state 不存在、已用过或已过期。
var ErrStateInvalid = errors.New("登录状态已失效，请重新登录")

// ErrNoIDToken 表示令牌端点没有返回 id_token（OAuth2-only 提供商会这样）。
var ErrNoIDToken = errors.New("身份提供方未返回 id_token")

// Claims 是从 id_token 里取出的最小身份信息。
type Claims struct {
	Subject       string
	Email         string
	EmailVerified bool
	Name          string
}

// OIDCConfig 是一个认证源的配置。
type OIDCConfig struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	RedirectURL  string
	Scopes       []string
}

// OIDC 是一个已发现端点的 RP。
type OIDC struct {
	cfg      OIDCConfig
	oauth    *oauth2.Config
	verifier *oidc.IDTokenVerifier
}

// NewOIDC 通过 discovery 初始化。
//
// 生产上要把 discovery 结果落库并把 issuer/endpoint 与"管理员配置的值"比对：
// 否则 IdP 的 discovery 被投毒，等于把认证交给了攻击者。P0 先只做严格校验。
func NewOIDC(ctx context.Context, cfg OIDCConfig) (*OIDC, error) {
	provider, err := oidc.NewProvider(ctx, strings.TrimRight(cfg.Issuer, "/"))
	if err != nil {
		return nil, err
	}
	scopes := cfg.Scopes
	if len(scopes) == 0 {
		scopes = []string{oidc.ScopeOpenID, "profile", "email"}
	}
	return &OIDC{
		cfg: cfg,
		oauth: &oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			Endpoint:     provider.Endpoint(),
			RedirectURL:  cfg.RedirectURL,
			Scopes:       scopes,
		},
		verifier: provider.Verifier(&oidc.Config{ClientID: cfg.ClientID}),
	}, nil
}

// AuthCodeURL 生成授权地址（强制 PKCE + S256）。
func (o *OIDC) AuthCodeURL(state, nonce, codeVerifier string) string {
	return o.oauth.AuthCodeURL(state,
		oauth2.SetAuthURLParam("nonce", nonce),
		oauth2.SetAuthURLParam("code_challenge", codeChallenge(codeVerifier)),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)
}

// Exchange 用授权码换 id_token，并校验签名、iss、aud、exp 与 nonce。
func (o *OIDC) Exchange(ctx context.Context, code, codeVerifier, nonce string) (Claims, error) {
	tok, err := o.oauth.Exchange(ctx, code, oauth2.SetAuthURLParam("code_verifier", codeVerifier))
	if err != nil {
		return Claims{}, err
	}
	raw, ok := tok.Extra("id_token").(string)
	if !ok || raw == "" {
		return Claims{}, ErrNoIDToken
	}
	idt, err := o.verifier.Verify(ctx, raw)
	if err != nil {
		return Claims{}, err
	}
	// nonce 不在库的默认校验里：必须自己比对（缺了它 id_token 可被重放）
	if idt.Nonce != nonce {
		return Claims{}, errors.New("nonce 不匹配")
	}
	var c struct {
		Email         string `json:"email"`
		EmailVerified bool   `json:"email_verified"`
		Name          string `json:"name"`
	}
	if err := idt.Claims(&c); err != nil {
		return Claims{}, err
	}
	return Claims{Subject: idt.Subject, Email: c.Email, EmailVerified: c.EmailVerified, Name: c.Name}, nil
}

// Pending 是一次"已发起、等回调"的登录状态。
type Pending struct {
	State    string
	Nonce    string
	Verifier string
	Provider string
	Next     string // 登录后要回到的站内地址
	Expires  time.Time
}

// StateStore 保存待回调的登录状态（P0 用内存；P1 换 Redis 以支持多实例）。
type StateStore struct {
	mu  sync.Mutex
	m   map[string]Pending
	ttl time.Duration
	now func() time.Time
}

// NewStateStore 构造一个带 TTL 的存储。
func NewStateStore(ttl time.Duration) *StateStore {
	if ttl <= 0 {
		ttl = 10 * time.Minute
	}
	return &StateStore{m: map[string]Pending{}, ttl: ttl, now: time.Now}
}

// Put 写入一条待回调状态。
func (s *StateStore) Put(p Pending) {
	if p.Expires.IsZero() {
		p.Expires = s.now().Add(s.ttl)
	}
	s.mu.Lock()
	s.m[p.State] = p
	s.mu.Unlock()
}

// Take 取出并删除（一次性）。过期或不存在都返回 false。
func (s *StateStore) Take(state string) (Pending, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.m[state]
	if !ok {
		return Pending{}, false
	}
	delete(s.m, state)
	if s.now().After(p.Expires) {
		return Pending{}, false
	}
	return p, true
}

// Sweep 清掉过期项（后台定时调用，避免内存无限增长）。
func (s *StateStore) Sweep() int {
	now := s.now()
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for k, v := range s.m {
		if now.After(v.Expires) {
			delete(s.m, k)
			n++
		}
	}
	return n
}
