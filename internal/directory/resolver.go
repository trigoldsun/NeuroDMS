package directory

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

// Resolver 按租户解析目录连接，并在内存里做短时缓存。
//
// 为什么需要它：配置现在存在数据库里，可以随时改。若登录时每次都新建连接，
// 每次登录都要重新 TCP+TLS 握手（几十到上百毫秒），并且配置错时会反复打域控。
// 缓存 60 秒是折中：改配置后最迟 1 分钟生效，同时保存时可以主动失效。
type Resolver struct {
	store *Store
	// env 是环境变量配置的回退值（数据库里没有记录时使用）。
	// 保留它是为了兼容既有部署：升级后不改任何东西，原来的域账号仍能登录。
	env *Settings

	ttl time.Duration

	mu    sync.Mutex
	cache map[string]cacheEntry
}

type cacheEntry struct {
	settings Settings
	dir      *LDAPDirectory
	err      error
	exp      time.Time
}

func NewResolver(store *Store, env *Settings) *Resolver {
	return &Resolver{store: store, env: env, ttl: time.Minute, cache: map[string]cacheEntry{}}
}

// Effective 返回该租户当前生效的配置：数据库优先，其次环境变量。
func (r *Resolver) Effective(ctx context.Context, tenantID string) (Settings, error) {
	s, err := r.store.Load(ctx, tenantID)
	if err != nil {
		return Settings{}, err
	}
	if s.Source == "database" {
		return s, nil
	}
	if r.env != nil && r.env.URL != "" && r.env.BaseDN != "" {
		env := *r.env
		env.Source = "env"
		env.Enabled = true
		return env, nil
	}
	return Settings{Source: "none"}, nil
}

// For 返回可用的目录连接；未配置或已停用时返回 (nil, nil)。
//
// 返回 nil 而不是错误：调用方（登录）对"没接目录"的处理是拒登，
// 这与"目录连不上"在界面上是同一句话，但日志里需要区分。
func (r *Resolver) For(ctx context.Context, tenantID string) (*LDAPDirectory, error) {
	r.mu.Lock()
	if e, ok := r.cache[tenantID]; ok && time.Now().Before(e.exp) {
		r.mu.Unlock()
		return e.dir, e.err
	}
	r.mu.Unlock()

	s, err := r.Effective(ctx, tenantID)
	var dir *LDAPDirectory
	if err == nil && s.Enabled && s.URL != "" {
		// 建连超时压到 8 秒：登录路径上不能等 15 秒默认超时
		bctx, cancel := context.WithTimeout(ctx, 8*time.Second)
		dir, err = NewLDAP(bctx, s.ToLDAPConfig())
		cancel()
		if err != nil {
			dir = nil
		}
	}

	r.mu.Lock()
	if len(r.cache) > 10000 {
		r.cache = map[string]cacheEntry{}
	}
	r.cache[tenantID] = cacheEntry{settings: s, dir: dir, err: err, exp: time.Now().Add(r.ttl)}
	r.mu.Unlock()
	return dir, err
}

// Invalidate 在配置保存后调用，让下一次登录立刻用新配置。
func (r *Resolver) Invalidate(tenantID string) {
	r.mu.Lock()
	delete(r.cache, tenantID)
	r.mu.Unlock()
}

// Build 按给定配置立即构造一个连接（用于"测试连接"，不写缓存）。
//
// 测试连接必须用**表单里的值**，而不是已保存的值：
// 管理员点测试就是想在上线前验证，若读库里的旧配置，测了个寂寞。
func Build(ctx context.Context, s Settings) (*LDAPDirectory, error) {
	if s.URL == "" || s.BaseDN == "" {
		return nil, errors.New("请先填写目录地址与 BaseDN")
	}
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	return NewLDAP(ctx, s.ToLDAPConfig())
}

// ProbeResult 是测试连接的结论。
//
// 分两步：先匿名连（验证网络、证书、端口），再绑定（验证服务账号）。
// 只报一个 false 的话，管理员无法判断是"网不通"还是"密码错"——这是现场最容易卡住的地方。
type ProbeResult struct {
	Anonymous bool `json:"anonymous"`
	Bind      bool `json:"bind"`
	// BindSkipped 表示"没填 BindDN，压根没做绑定"。
	//
	// 必须单独标出来：原实现会把"跳过绑定"算作成功，
	// 于是界面显示"服务账号绑定：成功"，而 AD 其实从未收到绑定请求——
	// 直到下一步读目录报 "successful bind must be completed" 才发现是假绿。
	BindSkipped bool   `json:"bindSkipped"`
	BaseRead    bool   `json:"baseRead"`
	Reason      string `json:"reason,omitempty"`
}

// Probe 执行测试连接。
func Probe(ctx context.Context, s Settings) ProbeResult {
	var out ProbeResult
	if s.URL == "" || s.BaseDN == "" {
		out.Reason = "缺少目录地址或 BaseDN"
		return out
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	// 匿名：只验证连通与 TLS，不做绑定
	anon := s
	anon.BindDN, anon.BindPassword = "", ""
	anon.AllowPlaintext = true // 匿名不做绑定，不涉及口令过网
	if d, err := NewLDAP(ctx, anon.ToLDAPConfig()); err != nil {
		// NewLDAP 的错误已带上下文（连接目录失败/CA 无可用证书…），不再重复加前缀
		out.Reason = err.Error()
		return out
	} else {
		_ = d.Close()
		out.Anonymous = true
	}

	if strings.TrimSpace(s.BindDN) == "" {
		out.BindSkipped = true
		out.Reason = "未填写 BindDN：AD 默认禁止匿名读取目录，请填写服务账号后再测"
		return out
	}

	d, err := NewLDAP(ctx, s.ToLDAPConfig())
	if err != nil {
		out.Reason = err.Error()
		return out
	}
	defer func() { _ = d.Close() }()
	out.Bind = true

	// 绑定成功后再读一次 BaseDN：服务账号存在但无权读目录是很常见的情况，
	// 此时"绑定成功"却没有一个用户能同步进来。
	if _, err := d.Fetch(ctx, "20000101000000Z"); err != nil {
		out.Reason = fmt.Sprintf("绑定成功，但读取 BaseDN 失败：%v", err)
		return out
	}
	out.BaseRead = true
	return out
}
