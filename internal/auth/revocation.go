package auth

import (
	"context"
	"sync"
	"time"

	"docvault/internal/db"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// 吊销语义说明（这段是设计约束，改代码前先读）
//
// 访问令牌是无状态 HS256，验签不查库，因此"停用账号 / 修改口令 / 登出"
// 这件事必须靠一个有状态的检查点来收敛，否则最长要等到 AccessTTL（15 分钟）才失效，
// 与 PRD 要求的"30 秒内失效"不符。
//
// 做法：短 TTL 的进程内缓存 + 数据库作为唯一真源。
//   - 缓存命中：不查库（这是性能的关键，否则每个请求一次 JOIN 查询）
//   - 缓存未命中：查一次 session ⋈ app_user，把 (session_epoch, revoked, status) 缓存起来
//   - 时间上界：最坏情况 = cacheTTL，所以 cacheTTL 必须 < PRD 的 30 秒
//
// 为什么不用 Redis 存吊销列表：单机私有化交付不该为了这个多一个依赖；
// 多实例部署时各实例各自缓存 ≤TTL，收敛延迟仍然是 TTL 量级，结论不变。
// 若将来要"零延迟踢下线"，正确做法是让 Redis 发布失效事件（缓存本身不变），
// 而不是把缓存删掉——删掉就变成每请求一次库查询。

// DefaultRevocationTTL 是吊销检查的缓存有效期。
// 取 10 秒：PRD 要求 30 秒内生效，留 3 倍余量应对时钟抖动与查询排队。
const DefaultRevocationTTL = 10 * time.Second

type sessionState struct {
	epoch   int
	revoked bool
	// tenantBlocked 表示租户已停用/删除（与账号停用同等处理）
	tenantBlocked bool
	expiresAt     time.Time
	checkedAt     time.Time
}

// Guard 负责校验访问令牌是否仍然有效（会话未吊销、用户未被停用、epoch 未变）。
type Guard struct {
	pool *pgxpool.Pool
	ttl  time.Duration
	now  func() time.Time

	mu   sync.RWMutex
	sess map[string]sessionState
}

// NewGuard 构造吊销检查器。ttl <= 0 时使用 DefaultRevocationTTL。
func NewGuard(pool *pgxpool.Pool, ttl time.Duration) *Guard {
	if ttl <= 0 {
		ttl = DefaultRevocationTTL
	}
	return &Guard{pool: pool, ttl: ttl, now: time.Now, sess: make(map[string]sessionState)}
}

// Check 校验令牌对应会话是否仍可用。
//
// 返回 ErrSessionInvalid 表示必须重新登录；返回其它错误表示"无法判定"，
// 调用方必须按 fail-closed 处理（拒绝请求），不能放行。
func (g *Guard) Check(ctx context.Context, c Claims) error {
	if c.SessionID == "" {
		return ErrSessionInvalid
	}

	if st, ok := g.lookup(c.SessionID); ok {
		if !st.usable(c.Epoch) {
			return ErrSessionInvalid
		}
		return nil
	}

	st, err := g.load(ctx, c.TenantID, c.SessionID)
	if err != nil {
		return err
	}
	g.store(c.SessionID, st)
	if !st.usable(c.Epoch) {
		return ErrSessionInvalid
	}
	return nil
}

func (s sessionState) usable(claimEpoch int) bool {
	if s.revoked {
		return false
	}
	if s.expiresAt.Before(time.Now()) {
		return false
	}
	// epoch 只增不减：令牌里的 epoch 必须等于当前值，
	// 小于说明令牌签发后被改密/停用（踢下线），大于说明是伪造或数据被回滚
	return claimEpoch == s.epoch
}

func (g *Guard) lookup(sessionID string) (sessionState, bool) {
	g.mu.RLock()
	st, ok := g.sess[sessionID]
	g.mu.RUnlock()
	if !ok || g.now().Sub(st.checkedAt) > g.ttl {
		return sessionState{}, false
	}
	return st, true
}

func (g *Guard) store(sessionID string, st sessionState) {
	g.mu.Lock()
	defer g.mu.Unlock()
	// 简单容量护栏：缓存条目数超过 10 万时整体清空。
	// 单机场景下会话数远小于此；真到了这个量级应该换成带淘汰的缓存，
	// 但在那之前，"清空"只造成一次性回源，不会出错。
	if len(g.sess) > 100_000 {
		g.sess = make(map[string]sessionState)
	}
	st.checkedAt = g.now()
	g.sess[sessionID] = st
}

func (g *Guard) load(ctx context.Context, tenantID, sessionID string) (sessionState, error) {
	var st sessionState
	var status string

	// 查询本身也走租户事务，保证不会跨租户读到会话
	err := db.WithTenant(ctx, g.pool, tenantID, func(tx pgx.Tx) error {
		var revokedAt *time.Time
		var expiresAt time.Time
		var epoch int
		var tenantStatus string
		// 注意：权威 epoch 是 app_user.session_epoch，不是 session.epoch。
		// session.epoch 记录的是"签发时的快照"，永不变化；
		// 用它做比较会导致"停用账号后已签发的令牌依然有效"——这是最容易写错的一行。
		//
		// 同时把租户状态带出来：租户被停用/删除时，会话必须一并失效。
		// 数据库层已经在改状态时吊销了全部会话（platform_tenant_set_status），
		// 这里再查一次是为了兜住"吊销之前刚好签发的令牌"与多实例的时间窗。
		if err := tx.QueryRow(ctx, `
			SELECT u.session_epoch, s.revoked_at, s.expires_at, u.status, t.status
			  FROM session s
			  JOIN app_user u ON u.id = s.user_id
			  JOIN tenant t ON t.id = u.tenant_id
			 WHERE s.id = $1`, sessionID).
			Scan(&epoch, &revokedAt, &expiresAt, &status, &tenantStatus); err != nil {
			return err
		}
		st = sessionState{epoch: epoch, revoked: revokedAt != nil, expiresAt: expiresAt,
			tenantBlocked: tenantStatus == "suspended" || tenantStatus == "deleted"}
		return nil
	})
	if err != nil {
		if err == pgx.ErrNoRows {
			// 会话不存在：缓存成"吊销"，避免用不存在的 sid 反复打库
			return sessionState{revoked: true, checkedAt: g.now()}, nil
		}
		return sessionState{}, err
	}
	// 租户不可用与账号停用同等对待：都表现为"会话立刻不可用"，
	// 而不是"登录被拒但老令牌还能用"。
	st.revoked = st.revoked || status != "active" || st.tenantBlocked
	return st, nil
}

// InvalidateSession 主动清掉某会话的缓存（本实例立即生效）。
//
// 登出、改密、停用账号后调用它，可以让本进程"零延迟"收敛；
// 其它实例仍受 TTL 约束，这是有意的取舍（多一轮广播的复杂度换不到业务价值）。
func (g *Guard) InvalidateSession(sessionID string) {
	g.mu.Lock()
	delete(g.sess, sessionID)
	g.mu.Unlock()
}

// InvalidateAll 清空缓存。仅用于测试与配置变更（如密钥轮换）。
func (g *Guard) InvalidateAll() {
	g.mu.Lock()
	g.sess = make(map[string]sessionState)
	g.mu.Unlock()
}

// Size 返回当前缓存条目数（诊断用）。
func (g *Guard) Size() int {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return len(g.sess)
}
