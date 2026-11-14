package notify

// 按租户选择邮件通道。
//
// 为什么需要这一层：通道以前是进程级单例（环境变量装配），
// 而 notification 表里每条消息都带 tenant_id——每个租户用自己邮箱发信
// 是完全合理的诉求（域名、退信、SPF/DKIM 都归租户自己）。
//
// 三条纪律：
//  1. 租户没配（mode=inherit）→ 用平台默认通道，升级不移交行为；
//  2. 租户配了自己的通道 → 失败就失败，**不静默回落到平台邮箱**，
//     否则邮件会从一个"意料之外"的域名发出，既难排查也像钓鱼；
//  3. 配置按租户缓存（默认 60 秒），保存时主动失效，避免每封信查一次库。

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"time"
)

// Mailer 是"按租户发信"的抽象。
//
// *Dispatcher（进程级通道）与 *Router（按租户路由）都实现它，
// 因此 Outbox / DirectSender 不需要知道到底有没有多租户配置。
type Mailer interface {
	// SendFor 发送并返回实际使用的通道名（smtp/graph）；空串表示未知。
	SendFor(ctx context.Context, tenantID string, m Message) (string, error)
}

// SettingsLoader 读取某租户的邮件配置。Router 不直接依赖 Store，
// 便于测试注入内存实现，也避免 notify 包与数据库强绑定。
type SettingsLoader func(ctx context.Context, tenantID string) (Settings, error)

// Router 按租户解析通道。
type Router struct {
	fallback *Dispatcher
	load     SettingsLoader
	log      *slog.Logger
	ttl      time.Duration

	mu    sync.Mutex
	cache map[string]cacheEntry
}

type cacheEntry struct {
	disp    *Dispatcher
	replyTo string
	channel string
	at      time.Time
}

// NewRouter 构造路由器。fallback 可为 nil（此时 inherit 的租户发信会明确报错）。
func NewRouter(fallback *Dispatcher, load SettingsLoader, log *slog.Logger) *Router {
	if log == nil {
		log = slog.Default()
	}
	return &Router{fallback: fallback, load: load, log: log, ttl: time.Minute, cache: map[string]cacheEntry{}}
}

// Invalidate 丢弃某租户的缓存。保存/测试配置后调用，下一次发送立即生效。
func (r *Router) Invalidate(tenantID string) {
	r.mu.Lock()
	delete(r.cache, tenantID)
	r.mu.Unlock()
}

// Fallback 返回平台默认通道（可能为 nil），供启动日志与界面展示。
func (r *Router) Fallback() *Dispatcher { return r.fallback }

// SendFor 实现 Mailer。
func (r *Router) SendFor(ctx context.Context, tenantID string, m Message) (string, error) {
	entry, err := r.resolve(ctx, tenantID)
	if err != nil {
		return "", err
	}
	if m.ReplyTo == "" {
		m.ReplyTo = entry.replyTo
	}
	ch, sendErr := entry.disp.send(ctx, m)
	if ch == "" {
		// 平台默认通道自己知道用了哪条；租户自有通道直接就是它
		ch = entry.channel
	}
	return ch, sendErr
}

func (r *Router) resolve(ctx context.Context, tenantID string) (cacheEntry, error) {
	r.mu.Lock()
	if e, ok := r.cache[tenantID]; ok && time.Since(e.at) < r.ttl {
		r.mu.Unlock()
		return e, nil
	}
	r.mu.Unlock()

	s, err := r.load(ctx, tenantID)
	if err != nil {
		// 读不到配置时不缓存：数据库抖动的下一封应该立刻重试，
		// 而不是被一个 60 秒的错误缓存挡住。
		return cacheEntry{}, err
	}
	disp, derr := s.Dispatcher()
	if derr != nil {
		return cacheEntry{}, derr
	}

	e := cacheEntry{at: time.Now(), replyTo: s.ReplyTo}
	switch {
	case disp != nil:
		e.disp = disp
		e.channel = s.Mode
	case r.fallback != nil:
		e.disp = r.fallback
		// inherit 时 Reply-To 由平台配置决定（当前平台配置没有该字段）
		e.replyTo = ""
	default:
		// 既没配自己的通道、平台也没配：明确失败。
		// 不返回 "no-op 成功"，否则"用户没收到"会变成静默事实。
		return cacheEntry{}, Permanent(errors.New("未配置邮件通道，请在管理台「邮件服务」中配置，或联系平台管理员"))
	}

	r.mu.Lock()
	r.cache[tenantID] = e
	r.mu.Unlock()
	return e, nil
}

// Describe 返回一段可读描述，用于启动日志（不含任何凭据）。
func (r *Router) Describe() string {
	if r == nil {
		return "未启用"
	}
	if r.fallback == nil {
		return "仅租户配置"
	}
	return "默认 " + strings.Join(r.fallback.Channels(), "+")
}
