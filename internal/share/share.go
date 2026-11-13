// Package share 实现安全分享与一次性链接。
//
// 核心不是"生成一个随机串"，而是三件事同时成立：
//  1. token 只存摘要，库被读走也拿不到可用链接；
//  2. 消费用单条原子 UPDATE（不是先查后改），并发下只有一个请求能成功；
//  3. 失效原因统一，避免通过页面差异枚举链接状态。
package share

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"docvault/internal/auth"
	"docvault/internal/db"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrUnavailable 是唯一对外暴露的失败原因：不存在 / 已用尽 / 已过期 / 已撤销
// 对外表现必须完全一致，否则可被用来枚举链接状态。
var ErrUnavailable = errors.New("链接不可用")

// 策略性失败原因：这些必须与 ErrUnavailable 区分，因为访问者需要知道"该做什么"，
// 而不是被含糊地告知"链接无效"——尤其口令错误要被明确指出，否则用户会以为链接坏了。
// 它们仍然不泄漏链接是否存在：只有持有有效 token 的人才会看到这些提示。
var (
	ErrPasswordRequired = errors.New("该链接需要访问口令")
	ErrPasswordWrong    = errors.New("访问口令不正确")
	ErrIPNotAllowed     = errors.New("当前网络不在允许范围内")
	ErrPendingApproval  = errors.New("分享正在审批中，暂时无法访问")
	// ErrLinkLocked 表示口令连续错误过多，链接被临时锁定。
	// 与"链接无效"区分：用户已知链接存在（都被要求输口令了），
	// 假装无效只会让人反复重试。
	ErrLinkLocked       = errors.New("口令错误次数过多，链接已临时锁定")
	ErrApprovalRejected = errors.New("分享审批未通过")

	// ErrSelfApproval 表示发起人试图审批自己创建的分享。
	//
	// 双人复核的全部意义在于"另一个人看过"。允许自批时，审批只是多一次点击，
	// 却让审计上出现一条"已审批"的记录——比没有审批更糟，因为它会让人相信
	// 这道控制生效了。
	ErrSelfApproval = errors.New("不能审批自己发起的分享")

	// ErrSpaceNotShareable 表示该空间不适合整体外发。
	//
	// 触发条件：空间内存在发起人自己也无权查看/密级更高的内容，
	// 或存在显式拒绝条目（说明子树里做过例外配置）。
	// 这两种情况下，空间级外链会把发起人本就看不到的东西一起交出去，
	// 因此拒绝并提示改为分享具体文件/目录。
	ErrSpaceNotShareable = errors.New("空间内含你无权访问或密级更高的内容，请改为分享具体文件或目录")
)

// Options 是创建分享时的策略。策略会被快照，后续修改不追溯已发出的链接。
type Options struct {
	MaxUses       *int       // nil = 不限；1 = 一次性
	ExpiresAt     *time.Time // nil = 不过期
	AllowDownload bool
	Watermark     bool
	PasswordHash  string
	RequireVerify bool
	// IPAllowlist 为空表示不限制；非空时访问者来源必须在其中（CIDR 或单 IP 均可）。
	IPAllowlist []string
	// RequireApproval 为真时链接先进入 pending，审批通过后才可用。
	RequireApproval bool
	// EmailWhitelist 限定可申请验证码的邮箱或域名（@example.com）。
	// 为空表示不限制（验证码仍然生效，只是不限制谁可以申请）。
	EmailWhitelist []string
}

// Created 是创建结果。Token 明文只在此处返回一次。
type Created struct {
	ID    string
	Token string
	// Approval 是审批状态（not_required / pending）。
	//
	// 必须回给调用方：密级触发的审批是服务端决定，前端不知道；
	// 不返回的话界面会显示"链接已可用"，用户转发出去才发现打不开。
	Approval string
	// ObjectClass 是触发审批的那个密级（对象与标签策略取最大值）。
	// 上层用它判断"是否还有密级足够的审批人"，避免造出无人可批的死链。
	ObjectClass int
}

// Redeemed 是兑换成功后的上下文，供上层签发短期票据。
type Redeemed struct {
	ShareID       string
	TenantID      string
	ObjectType    string
	ObjectID      string
	AllowDownload bool
	Watermark     bool
	IsOneTime     bool
	// MaxClass 是发起人创建分享时的密级快照。
	//
	// 为什么需要快照：密级强制门（MAC）要求"访问者不得看到高于其密级的内容"，
	// 而外链访客没有账号、没有密级，只能用**发起人**的密级作为上界。
	// 不在创建时冻结的话，发起人后来被降级，已发出的链接仍然能取到高密文件。
	MaxClass int
}

// Create 创建分享链接。
//
// creatorClass 是发起人当前密级，作为分享内容的上界一并落库（见 Redeemed.MaxClass）。
func Create(ctx context.Context, pool *pgxpool.Pool, tenantID, creatorID, objectType, objectID string,
	creatorClass int, opt Options) (Created, error) {
	if opt.MaxUses != nil && *opt.MaxUses <= 0 {
		return Created{}, errors.New("max_uses 必须大于 0")
	}
	if creatorClass < 0 {
		creatorClass = 0
	}
	token, hash, err := newToken()
	if err != nil {
		return Created{}, err
	}

	var (
		id          string
		approval    string
		objClassOut int
	)
	err = db.WithTenant(ctx, pool, tenantID, func(tx pgx.Tx) error {
		// 空间级外链的前置闸门：整个空间会被一并开放，因此必须确认
		// 空间里没有"发起人自己也看不到"的东西。
		//
		// 只在 objectType=space 时检查。单文件分享已经在创建前对该对象
		// 做过 share_external 判定（含密级门），不需要重复。
		if objectType == "space" {
			var risky int
			if err := tx.QueryRow(ctx, `
				SELECT COUNT(*) FROM node n
				 WHERE n.space_id = $1 AND n.deleted_at IS NULL
				   AND (
				     n.classification > $2
				     -- 显式拒绝意味着子树里有例外配置；整体外发会绕过它
				     OR EXISTS (SELECT 1 FROM ace x
				                 WHERE x.object_type = 'node' AND x.object_id = n.id
				                   AND COALESCE(x.deny_bits, 0) <> 0)
				   )`, objectID, creatorClass).Scan(&risky); err != nil {
				return err
			}
			if risky > 0 {
				return ErrSpaceNotShareable
			}
		}

		// 密级驱动审批（AC-43）：达到租户阈值的外发链接一律进 pending。
		//
		// 刻意**不**给安全管理员开豁免：自审自批是审批流程最常见的失效形态，
		// 而"高密文件外发必须有人复核"这条要求不该有角色例外。
		// 阈值默认 3（秘密级），由租户配置；标签策略下限一并计入。
		var minClass int
		if err := tx.QueryRow(ctx,
			`SELECT share_approval_min_class FROM tenant WHERE id = $1`, tenantID).Scan(&minClass); err != nil {
			return err
		}
		var objClass int
		if err := tx.QueryRow(ctx, `
			SELECT GREATEST(
			  COALESCE((SELECT classification FROM node WHERE id = $1), 0),
			  COALESCE((SELECT classification FROM space WHERE id = $1), 0),
			  COALESCE((SELECT max(lp.min_level)
			              FROM node_label nl
			              JOIN label_policy lp ON lp.tenant_id = nl.tenant_id AND lp.label = nl.label
			             WHERE nl.node_id = $1), 0)
			)`, objectID).Scan(&objClass); err != nil {
			return err
		}

		objClassOut = objClass
		approval = "not_required"
		requireApproval := opt.RequireApproval || objClass >= minClass
		if requireApproval {
			approval = "pending"
		}
		return tx.QueryRow(ctx, `
			INSERT INTO share
				(id, tenant_id, object_type, object_id, creator_id, kind,
				 token_hash, token_hint, password_hash, max_uses, expires_at,
				 allow_download, watermark, require_verify,
				 ip_allowlist, require_approval, approval_status, email_whitelist,
				 max_class)
			VALUES
				(gen_random_uuid(), $1, $2, $3, $4, 'link',
				 $5, $6, nullif($7,''), $8, $9, $10, $11, $12,
				 $13::cidr[], $14, $15, $16::text[],
				 $17)
			RETURNING id`,
			tenantID, objectType, objectID, creatorID,
			hash, hint(token), opt.PasswordHash, opt.MaxUses, opt.ExpiresAt,
			opt.AllowDownload, opt.Watermark, opt.RequireVerify,
			normalizeCIDRs(opt.IPAllowlist), requireApproval, approval,
			normalizeEmails(opt.EmailWhitelist), creatorClass).Scan(&id)
	})
	if err != nil {
		return Created{}, fmt.Errorf("创建分享失败: %w", err)
	}
	return Created{ID: id, Token: token, Approval: approval, ObjectClass: objClassOut}, nil
}

// Redeem 校验策略并消费一次链接，返回换取票据所需的上下文。
//
// 关键：整个"检查 + 计数"由一条 UPDATE 完成。
// 两个并发请求会串行化在同一行锁上，第二个看到的 used_count 已经递增，
// 因此 max_uses=1 时必然只有一个成功。
//
// 策略检查（口令、网段、审批）在消费之前做，但**失败时不消费**——
// 否则输错一次口令就把一次性链接作废了，这是用户最容易踩到的坑。
func Redeem(ctx context.Context, pool *pgxpool.Pool, token, password, ip, ua string) (Redeemed, error) {
	return redeem(ctx, pool, token, password, ip, ua, false)
}

// redeem 是兑换的唯一实现。
//
// emailVerified 由 RedeemWithVerify 在**消费掉验证记录之后**传 true。
// 这个参数存在的唯一理由：把"要不要验证邮箱"变成兑换事务内部的一个断言，
// 而不是依赖调用方记得先走验证接口。
//
// 历史缺陷：Redeem 曾完全不看 share.require_verify，于是
// GET /v1/public/shares/{token} 可以直接拿到票据，验证接口成了纯装饰——
// 白名单、一次性验证码、连错锁定全部可绕过。判定放进事务内后，
// 任何新增的兑换入口都不可能再漏掉这一步。
func redeem(ctx context.Context, pool *pgxpool.Pool, token, password, ip, ua string,
	emailVerified bool) (Redeemed, error) {
	hash := hashOf(token)

	// 先用平台身份解析租户（token 是能力凭证，持有者本就已获访问权）
	var tenantID string
	err := pool.QueryRow(ctx, `SELECT tenant_id FROM share WHERE token_hash = $1`, hash).Scan(&tenantID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Redeemed{}, ErrUnavailable
		}
		return Redeemed{}, err
	}

	var out Redeemed
	// pending 用于"在事务内改了状态、但对外要返回错误"的情形。
	//
	// 不能直接 return error：WithTenant 会回滚事务，
	// 刚写进去的失败计数与访问流水会一起消失——攻击者可以无限重试。
	var pending error
	err = db.WithTenant(ctx, pool, tenantID, func(tx pgx.Tx) error {
		var (
			shareID       string
			maxUses       *int
			used          int
			objectType    string
			objectID      string
			allowDownload bool
			watermark     bool
			revokedAt     *time.Time
			expiresAt     *time.Time
			passwordHash  *string
			approval      string
			ipAllowlist   []string
			failed        int
			lockedUntil   *time.Time
			requireVerify bool
			maxClass      int
		)

		// 先读一次做策略判定（不加锁：真正的并发保护在下面的原子 UPDATE）
		err := tx.QueryRow(ctx, `
			SELECT id::text, object_type, object_id, allow_download, watermark, max_uses, used_count,
			       revoked_at, expires_at, password_hash, approval_status,
			       COALESCE((SELECT array_agg(c::text) FROM unnest(ip_allowlist) AS c), '{}'),
			       failed_attempts, locked_until, require_verify, max_class
			  FROM share WHERE token_hash = $1`, hash).
			Scan(&shareID, &objectType, &objectID, &allowDownload, &watermark, &maxUses, &used,
				&revokedAt, &expiresAt, &passwordHash, &approval, &ipAllowlist, &failed, &lockedUntil,
				&requireVerify, &maxClass)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrUnavailable
			}
			return err
		}

		// 1) 状态类失败：统一 ErrUnavailable，不区分原因
		now := time.Now()
		if revokedAt != nil || (expiresAt != nil && expiresAt.Before(now)) ||
			(maxUses != nil && used >= *maxUses) {
			return ErrUnavailable
		}

		// 2) 审批态
		switch approval {
		case "pending":
			return ErrPendingApproval
		case "rejected":
			return ErrApprovalRejected
		}

		// 3) 来源网段
		if len(ipAllowlist) > 0 && !ipAllowed(ipAllowlist, ip) {
			_ = recordVisit(ctx, tx, tenantID, objectID, "denied", "ip_not_allowed", ip, ua, hash)
			return ErrIPNotAllowed
		}

		// 4) 口令锁定（先判锁，再判口令——否则锁定期间还能继续尝试）
		//
		// 两级：
		//   - 按来源（share_attempt）：单个人爆破，锁他一个来源；
		//   - 全局（share.locked_until）：换 IP 分布式爆破的兜底，阈值高得多。
		//
		// 之前只有"按链接"一级，等于任何人拿到链接输错 6 次就能锁掉这条链接，
		// 不需要知道口令——一次零成本的拒绝服务。
		srcKey := ipPrefix(ip)
		var (
			srcFailed int
			srcLocked *time.Time
		)
		if srcKey != "" {
			qerr := tx.QueryRow(ctx, `
				SELECT failed_attempts, locked_until FROM share_attempt
				 WHERE share_id = $1 AND ip_prefix = $2 FOR UPDATE`, shareID, srcKey).
				Scan(&srcFailed, &srcLocked)
			if qerr != nil && !errors.Is(qerr, pgx.ErrNoRows) {
				return qerr
			}
			// 来源锁已过期：计数归零，重新给满额机会
			if srcLocked != nil && !srcLocked.After(now) {
				srcFailed, srcLocked = 0, nil
				if _, uerr := tx.Exec(ctx, `
					UPDATE share_attempt SET failed_attempts = 0, locked_until = NULL, updated_at = now()
					 WHERE share_id = $1 AND ip_prefix = $2`, shareID, srcKey); uerr != nil {
					return uerr
				}
			}
			if srcLocked != nil && srcLocked.After(now) {
				_ = recordVisit(ctx, tx, tenantID, objectID, "denied", "link_locked_source", ip, ua, hash)
				return ErrLinkLocked
			}
		}
		if lockedUntil != nil && lockedUntil.After(now) {
			_ = recordVisit(ctx, tx, tenantID, objectID, "denied", "link_locked", ip, ua, hash)
			return ErrLinkLocked
		}
		// 锁已过期：把计数归零，重新给满额机会。
		//
		// 不归零的话，锁定到期后 failed 仍然是阈值，用户第一次输错就立刻再次锁定，
		// 表现为"明明说等 30 分钟，等完还是锁着"。
		if lockedUntil != nil && !lockedUntil.After(now) && failed > 0 {
			failed = 0
			if _, uerr := tx.Exec(ctx,
				`UPDATE share SET failed_attempts = 0, locked_until = NULL WHERE token_hash = $1`, hash); uerr != nil {
				return uerr
			}
		}

		// 5) 访问口令
		if passwordHash != nil && *passwordHash != "" {
			if password == "" {
				return ErrPasswordRequired
			}
			if err := auth.VerifyPassword(*passwordHash, password); err != nil {
				// 5.1 按来源计数（主闸门）
				lockedNow := false
				if srcKey != "" {
					srcFailed++
					var srcLockArg any
					if srcFailed >= perSourceMaxAttempts {
						srcLockArg = now.Add(passwordLockDuration)
						lockedNow = true
					}
					// GREATEST：并发下两个请求都读到 5 时不能都写 6 后被对方覆盖成更小
					if _, uerr := tx.Exec(ctx, `
						INSERT INTO share_attempt (tenant_id, share_id, ip_prefix, failed_attempts, locked_until, updated_at)
						VALUES ($1, $2, $3::cidr, $4, $5, now())
						ON CONFLICT (share_id, ip_prefix) DO UPDATE
						   SET failed_attempts = GREATEST(share_attempt.failed_attempts, EXCLUDED.failed_attempts),
						       locked_until = COALESCE(EXCLUDED.locked_until, share_attempt.locked_until),
						       updated_at = now()`,
						tenantID, shareID, srcKey, srcFailed, srcLockArg); uerr != nil {
						return uerr
					}
				}

				// 5.2 全局兜底计数（阈值高得多，只为了拦住换 IP 的分布式爆破）
				failed++
				var lockArg any
				if failed >= globalMaxAttempts {
					lockArg = now.Add(passwordLockDuration)
					lockedNow = true
				}
				if _, uerr := tx.Exec(ctx, `
					UPDATE share
					   SET failed_attempts = GREATEST(failed_attempts, $2),
					       locked_until = COALESCE($3, locked_until)
					 WHERE token_hash = $1`, hash, failed, lockArg); uerr != nil {
					return uerr
				}

				// 触发锁定的这一次就要告诉用户"已锁定"，
				// 否则第 6 次仍显示"口令错误"，第 7 次才变成锁定，
				// 用户会以为系统在乱报错。
				if lockedNow {
					pending = ErrLinkLocked
				} else {
					pending = ErrPasswordWrong
				}
				_ = recordVisit(ctx, tx, tenantID, objectID, "denied", "bad_password", ip, ua, hash)
				return nil
			}
			// 口令正确：清零计数，避免"之前错几次"影响后续正常访问
			if failed > 0 {
				if _, uerr := tx.Exec(ctx,
					`UPDATE share SET failed_attempts = 0, locked_until = NULL WHERE token_hash = $1`, hash); uerr != nil {
					return uerr
				}
			}
			// 来源计数行没有保留价值：口令已验证通过，下次从零开始
			if srcKey != "" && srcFailed > 0 {
				if _, uerr := tx.Exec(ctx,
					`DELETE FROM share_attempt WHERE share_id = $1 AND ip_prefix = $2`,
					shareID, srcKey); uerr != nil {
					return uerr
				}
			}
		}

		// 6) 邮箱验证：没走验证流程的兑换一律拒绝。
		//
		// 位置在口令之后，是刻意的。理由有两条：
		//   1. 若验证在口令之前，用户会先拿到"请验证"，验证通过后又撞上"请输口令"——
		//      而此时验证记录已被消费，只能重新发码，形成死循环；
		//   2. 口令锁定（6 次）本身就能挡住暴力尝试，先判口令不会削弱验证强度。
		//
		// 用 pending 而不是直接返回 error：直接返回会让整个事务回滚，
		// 连"有人试图绕过验证"这条访问流水都留不下来。
		if requireVerify && !emailVerified {
			_ = recordVisit(ctx, tx, tenantID, objectID, "denied", "verify_required", ip, ua, hash)
			pending = ErrVerifyRequired
			return nil
		}

		// 7) 原子消费
		err = tx.QueryRow(ctx, `
			UPDATE share
			   SET used_count = used_count + 1,
			       first_used_at = COALESCE(first_used_at, now())
			 WHERE token_hash = $1
			   AND revoked_at IS NULL
			   AND (expires_at IS NULL OR expires_at > now())
			   AND (max_uses IS NULL OR used_count < max_uses)
			   AND approval_status IN ('not_required','approved')
			RETURNING id, max_uses, used_count`,
			hash).Scan(&out.ShareID, &maxUses, &used)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrUnavailable
			}
			return err
		}

		out.TenantID = tenantID
		out.ObjectType = objectType
		out.ObjectID = objectID
		out.AllowDownload = allowDownload
		out.Watermark = watermark
		out.MaxClass = maxClass
		out.IsOneTime = maxUses != nil && *maxUses == 1

		// 访问流水：消费与访问分开记录
		_, err = tx.Exec(ctx, `
			INSERT INTO share_visit (id, tenant_id, share_id, action, result, ip, user_agent)
			VALUES (gen_random_uuid(), $1, $2, 'redeem', 'ok', nullif($3,'')::inet, nullif($4,''))`,
			tenantID, out.ShareID, ip, ua)
		return err
	})
	if err != nil {
		return Redeemed{}, err
	}
	if pending != nil {
		return Redeemed{}, pending
	}
	return out, nil
}

// 口令爆破防护参数。锁定 30 分钟与 PRD 一致。
const (
	// perSourceMaxAttempts 是单个来源（/24 或 /64）对单条链接的容错次数。
	// 6 次与 PRD 一致；超过即只锁这个来源，不影响其他人访问同一链接。
	perSourceMaxAttempts = 6
	// globalMaxAttempts 是整条链接的兜底阈值，用于拦住"换 IP 分布式爆破"。
	// 取 10 倍：正常误操作远到不了，而分布式爆破每人 6 次会在第 60 次被整体封死。
	globalMaxAttempts    = 60
	passwordLockDuration = 30 * time.Minute
)

// recordVisit 记录被拒访问。失败不影响主流程（审计有独立链路，不该因流水写失败改变用户可见结果）。
func recordVisit(ctx context.Context, tx pgx.Tx, tenantID, _ /*objectID*/, action, result, ip, ua string, tokenHash []byte) error {
	var shareID string
	if err := tx.QueryRow(ctx, `SELECT id FROM share WHERE token_hash = $1`, tokenHash).Scan(&shareID); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `
		INSERT INTO share_visit (id, tenant_id, share_id, action, result, ip, user_agent)
		VALUES (gen_random_uuid(), $1, $2, $3, $4, nullif($5,'')::inet, nullif($6,''))`,
		tenantID, shareID, action, result, ip, ua)
	return err
}

// Approve 审批外发分享：通过或拒绝。
//
// 调用方仍需校验审批人对对象有 manage_acl；本函数只负责一件上层查不到的事：
// **发起人不能审批自己创建的分享**。
//
// 这条以前只写在注释里（"由上层 check 保证"），但上层只能保证"有权管理该对象的
// 授权"——而空间所有者对自己创建的外链恰好就有这个权限。结果是高密文件外发
// 的审批可以自己点过，审批记录齐全但控制完全失效。
func Approve(ctx context.Context, pool *pgxpool.Pool, tenantID, shareID, approverID string, ok bool) error {
	return db.WithTenant(ctx, pool, tenantID, func(tx pgx.Tx) error {
		// 锁住待审批那一行：并发下两个人同时点"通过/拒绝"时，
		// 后到的那个必须看到状态已经变了，而不是各自写一次。
		var creatorID string
		err := tx.QueryRow(ctx, `
			SELECT creator_id::text FROM share
			 WHERE id = $1 AND approval_status = 'pending' FOR UPDATE`, shareID).Scan(&creatorID)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrUnavailable
			}
			return err
		}
		if creatorID == approverID {
			return ErrSelfApproval
		}

		status := "rejected"
		if ok {
			status = "approved"
		}
		ct, err := tx.Exec(ctx, `
			UPDATE share SET approval_status = $2, approved_by = $3, approved_at = now()
			 WHERE id = $1 AND approval_status = 'pending'`, shareID, status, approverID)
		if err != nil {
			return err
		}
		if ct.RowsAffected() == 0 {
			return ErrUnavailable
		}
		return nil
	})
}

// Revoke 撤销分享，立即生效，并让已发出的票据一并失效。
func Revoke(ctx context.Context, pool *pgxpool.Pool, tenantID, shareID, by string) error {
	return db.WithTenant(ctx, pool, tenantID, func(tx pgx.Tx) error {
		ct, err := tx.Exec(ctx, `
			UPDATE share SET revoked_at = now(), revoked_by = nullif($2,'')::uuid
			 WHERE id = $1 AND tenant_id = $3 AND revoked_at IS NULL`, shareID, by, tenantID)
		if err != nil {
			return err
		}
		if ct.RowsAffected() == 0 {
			return ErrUnavailable
		}
		// 票据必须同时失效：否则"已撤销"的分享在票据有效期内还能继续下载
		return RevokeTickets(ctx, tx, shareID)
	})
}

// normalizeCIDRs 把用户输入的单 IP 或 CIDR 统一成 CIDR 数组，非法项直接丢弃。
func normalizeCIDRs(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if !strings.Contains(s, "/") {
			if ip := net.ParseIP(s); ip != nil {
				if ip.To4() != nil {
					s += "/32"
				} else {
					s += "/128"
				}
			}
		}
		if _, _, err := net.ParseCIDR(s); err == nil {
			out = append(out, s)
		}
	}
	return out
}

func ipAllowed(allow []string, ip string) bool {
	addr := net.ParseIP(ip)
	if addr == nil {
		return false
	}
	for _, c := range allow {
		if _, netw, err := net.ParseCIDR(c); err == nil && netw.Contains(addr) {
			return true
		}
	}
	return false
}

func newToken() (token string, hash []byte, err error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", nil, err
	}
	token = base64.RawURLEncoding.EncodeToString(b)
	return token, hashOf(token), nil
}

func hashOf(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}

// hint 只保留前 6 位，供用户在列表里辨认是哪条链接，不能用于访问。
func hint(token string) string {
	if len(token) < 6 {
		return token
	}
	return token[:6]
}

// normalizeEmails 规范化白名单：去空、转小写、去重（保持顺序）。
//
// 不去空会导致白名单里出现 "" 元素；若匹配逻辑把空串当"匹配所有"，
// 白名单就静默失效了。这里先清理，匹配逻辑再严格判空。
func normalizeEmails(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.ToLower(strings.TrimSpace(s))
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}
