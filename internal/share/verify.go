package share

// 分享的邮箱验证与白名单（AC-50 / AC-51）。
//
// 安全链条必须完整，缺任何一环都等于没做：
//   1. 只有白名单内的邮箱能**申请**验证码（否则任何人都能拿别人的链接刷验证码）；
//   2. 验证码按"链接 + 邮箱"隔离，错误次数落库（AC-51：连错 6 次即锁定）；
//   3. 验证通过后落一条短期记录，兑换时**必须**消费它——
//      否则客户端跳过验证直接兑换，验证就成了纯装饰。

import (
	"context"
	"errors"
	"strings"
	"time"

	"docvault/internal/db"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrVerifyRequired 表示该链接要求邮箱验证，但当前请求没有有效的验证记录。
var ErrVerifyRequired = errors.New("该链接需要邮箱验证")

// ErrEmailNotAllowed 表示申请邮箱不在白名单内。
var ErrEmailNotAllowed = errors.New("该邮箱不在允许访问的范围内")

// ErrVerifyNotNeeded 表示该链接不需要邮箱验证。
var ErrVerifyNotNeeded = errors.New("该链接无需邮箱验证")

// VerifyPolicy 是验证流程需要的分享策略（不包含 token 摘要等敏感字段）。
type VerifyPolicy struct {
	TenantID      string
	ShareID       string
	RequireVerify bool
	Whitelist     []string
}

// DefaultVerifyTTL 是验证通过后允许兑换的时间窗口。
//
// 取 10 分钟而不是"跟链接同寿命"：验证的是"此刻这个人控制该邮箱"，
// 不是"这个人永久可信"。窗口越长，被代打开的风险越大。
const DefaultVerifyTTL = 10 * time.Minute

// LookupVerifyPolicy 按 token 查策略。token 不存在返回 ErrUnavailable（与兑换一致，避免枚举）。
func LookupVerifyPolicy(ctx context.Context, pool *pgxpool.Pool, token string) (VerifyPolicy, error) {
	if token == "" {
		return VerifyPolicy{}, ErrUnavailable
	}
	hash := hashOf(token)

	var (
		p       VerifyPolicy
		revoked *time.Time
		expires *time.Time
	)
	// token 全局唯一，因此这里先跨租户定位（不带 tenant 上下文），
	// 拿到 tenant 后再用租户上下文读策略——两步都在同一函数里，避免调用方忘记。
	err := pool.QueryRow(ctx, `
		SELECT tenant_id::text, id::text, require_verify, email_whitelist, revoked_at, expires_at
		  FROM share WHERE token_hash = $1`, hash).
		Scan(&p.TenantID, &p.ShareID, &p.RequireVerify, &p.Whitelist, &revoked, &expires)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return VerifyPolicy{}, ErrUnavailable
		}
		return VerifyPolicy{}, err
	}
	now := time.Now()
	if revoked != nil || (expires != nil && !expires.After(now)) {
		return VerifyPolicy{}, ErrUnavailable
	}
	return p, nil
}

// EmailAllowed 判断邮箱是否满足白名单。
//
// 支持两种写法：
//   - 完整邮箱：alice@example.com（精确匹配）
//   - 域名：@example.com（该域任意邮箱）
//
// 白名单为空表示不限——此时"验证码"仍然生效，只是不限制谁可以申请。
func EmailAllowed(email string, whitelist []string) bool {
	if len(whitelist) == 0 {
		return true // 未配置白名单 = 不限制
	}
	email = strings.ToLower(strings.TrimSpace(email))
	at := strings.LastIndexByte(email, '@')
	if at <= 0 {
		return false
	}
	domain := email[at:] // 含 @
	for _, item := range whitelist {
		it := strings.ToLower(strings.TrimSpace(item))
		if it == "" {
			continue
		}
		if strings.HasPrefix(it, "@") {
			if domain == it {
				return true
			}
			continue
		}
		if it == email {
			return true
		}
	}
	return false
}

// RecordVerify 记录一次验证通过。
func RecordVerify(ctx context.Context, pool *pgxpool.Pool, p VerifyPolicy, email, ip string, ttl time.Duration) (string, time.Time, error) {
	if ttl <= 0 {
		ttl = DefaultVerifyTTL
	}
	email = strings.ToLower(strings.TrimSpace(email))
	expires := time.Now().Add(ttl)

	var id string
	err := db.WithTenant(ctx, pool, p.TenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
			INSERT INTO share_verify (id, tenant_id, share_id, email, expires_at, ip)
			VALUES (gen_random_uuid(), $1, $2, $3, $4, nullif($5,'')::inet)
			RETURNING id::text`,
			p.TenantID, p.ShareID, email, expires, ip).Scan(&id)
	})
	if err != nil {
		return "", time.Time{}, err
	}
	return id, expires, nil
}

// ConsumeVerify 在兑换时消费验证记录。
//
// 用一条 UPDATE ... RETURNING 完成"检查 + 消费"，避免并发下同一个验证记录被用两次
// （例如把验证结果分享给别人，两人同时兑换）。
func ConsumeVerify(ctx context.Context, pool *pgxpool.Pool, tenantID, shareID, email string) error {
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" {
		return ErrVerifyRequired
	}
	var id string
	err := db.WithTenant(ctx, pool, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
			UPDATE share_verify SET consumed_at = now()
			 WHERE id = (
			        SELECT id FROM share_verify
			         WHERE share_id = $1 AND lower(email) = $2
			           AND consumed_at IS NULL AND expires_at > now()
			         ORDER BY verified_at DESC LIMIT 1
			         FOR UPDATE SKIP LOCKED)
			 RETURNING id::text`, shareID, email).Scan(&id)
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrVerifyRequired
		}
		return err
	}
	return nil
}

// RedeemWithVerify 是"需要邮箱验证"版本的兑换。
//
// 为什么不改 Redeem 的签名：Redeem 的现有调用方与测试都是"不需要验证"的场景，
// 改签名会把验证语义扩散到所有调用点；单独一个入口让"必须验证"这件事
// 在调用方一眼可见，也更难被漏用。
func RedeemWithVerify(ctx context.Context, pool *pgxpool.Pool, token, password, email, ip, ua string) (Redeemed, error) {
	p, err := LookupVerifyPolicy(ctx, pool, token)
	if err != nil {
		return Redeemed{}, err
	}
	if !p.RequireVerify {
		return Redeemed{}, ErrVerifyNotNeeded
	}
	if !EmailAllowed(email, p.Whitelist) {
		return Redeemed{}, ErrEmailNotAllowed
	}
	// 先消费验证记录，再走正常兑换：顺序反过来会出现
	// "链接已用掉但验证记录还没消费"的窗口
	if err := ConsumeVerify(ctx, pool, p.TenantID, p.ShareID, email); err != nil {
		return Redeemed{}, err
	}
	// 走同一个 redeem 实现并显式声明"验证已完成"。
	// 不能直接调 Redeem：那条路径会把 require_verify=true 的链接判成"需要验证"，
	// 于是刚验证通过的人也兑换不了。
	return redeem(ctx, pool, token, password, ip, ua, true)
}
