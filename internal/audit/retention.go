package audit

import (
	"context"
	"log/slog"
	"time"

	"docvault/internal/db"
	"docvault/internal/tenant"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// 保留期清理。
//
// 三条硬约束决定了这里不能写成一句 DELETE：
//
//  1. 哈希链：直接删中间的行会让 Verify 从"前序哈希不匹配"开始报错，
//     运维看到"审计链断裂"会当成被篡改——这比不删更糟。因此只删
//     **已经被日结锚点完整覆盖**的前缀，且 Verify 支持从锚点边界起算。
//  2. 可验证性：删掉的每一天都留有锚点（merkle 根 + 链头 + HMAC 签名），
//     所以"那段时间存在过、且当时没被改过"仍然可证；删的是明细，不是证据。
//  3. 可追溯：清理动作本身写一条 audit.purge 事件（写在删除之后，不会被自己删掉）。
//
// 没有锚点覆盖时一律不删：宁可多占磁盘，也不制造一段无法解释的空白。

// PurgeStats 是一次清理的结果，用于日志与响应。
type PurgeStats struct {
	Deleted    int64     // 实际删除条数
	ThroughSeq int64     // 删到哪一条（含），0 表示未删
	Cutoff     time.Time // 保留期截止时间
	Anchored   bool      // 是否有锚点覆盖到截止时间之前
}

// retentionCutoff 计算保留期截止时间。
//
// 抽成纯函数是为了能单测：这里算错一天，就等于多删或少删一整天的日志。
func retentionCutoff(now time.Time, days int) time.Time {
	return now.UTC().AddDate(0, 0, -tenant.NormalizeRetention(days))
}

// PurgeExpired 按租户保留期清理已被锚定的历史事件。
func PurgeExpired(ctx context.Context, pool *pgxpool.Pool, tenantID string, retentionDays int) (PurgeStats, error) {
	days := tenant.NormalizeRetention(retentionDays)
	st := PurgeStats{Cutoff: retentionCutoff(time.Now(), days)}

	err := db.WithTenant(ctx, pool, tenantID, func(tx pgx.Tx) error {
		// 删除必须走 SECURITY DEFINER 函数：应用角色对 audit_event 只有
		// INSERT/SELECT（防篡改），直接 DELETE 会被数据库拒绝。
		// 边界也在函数里推导，应用层只能传"保留天数"，无法指定删到哪一条。
		if err := tx.QueryRow(ctx,
			`SELECT deleted, through_seq FROM audit_purge($1::uuid, $2)`,
			tenantID, days).Scan(&st.Deleted, &st.ThroughSeq); err != nil {
			return err
		}
		st.Anchored = st.ThroughSeq > 0
		if st.Deleted == 0 {
			return nil
		}
		// 与删除同事务：审计写失败则整笔回滚，不会留下"删了但没记录"的空白
		return Append(ctx, tx, tenantID, Event{
			ActorType: "system",
			Action:    "audit.purge",
			Result:    "ok",
			Detail: map[string]any{
				"retentionDays": days,
				"cutoff":        st.Cutoff.Format(time.RFC3339),
				"throughSeq":    st.ThroughSeq,
				"deleted":       st.Deleted,
			},
		})
	})
	return st, err
}

// retentionSQL 读取各租户的保留期。
//
// 用正则先判形状再转型：policy 是人工可改的 jsonb，
// 一个 "30d" 这样的值会让整个 ::int 转换报错，进而**所有租户**都清不了。
const retentionSQL = `
	SELECT t.id::text,
	       CASE WHEN coalesce(c.policy->>'auditRetentionDays','') ~ '^[0-9]{1,4}$'
	            THEN (c.policy->>'auditRetentionDays')::int ELSE 0 END
	  FROM tenant t
	  LEFT JOIN tenant_config c ON c.tenant_id = t.id
	 WHERE t.deleted_at IS NULL AND t.status = 'active'`

// RunRetention 周期性执行保留期清理。
//
// 间隔默认 6 小时：清理是维护动作，没必要更频繁；
// 但要保证"配置改小之后当天就能生效"，所以也不能做成一天一次。
func RunRetention(ctx context.Context, pool *pgxpool.Pool, log *slog.Logger, interval time.Duration) {
	if interval <= 0 {
		interval = 6 * time.Hour
	}
	tick := time.NewTicker(interval)
	defer tick.Stop()

	purgeAll(ctx, pool, log)
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			purgeAll(ctx, pool, log)
		}
	}
}

func purgeAll(ctx context.Context, pool *pgxpool.Pool, log *slog.Logger) {
	rows, err := pool.Query(ctx, retentionSQL)
	if err != nil {
		log.Error("读取保留期配置失败（日志清理跳过本轮）", "err", err.Error())
		return
	}
	type target struct {
		id   string
		days int
	}
	var targets []target
	for rows.Next() {
		var t target
		if err := rows.Scan(&t.id, &t.days); err != nil {
			rows.Close()
			log.Error("读取保留期配置失败", "err", err.Error())
			return
		}
		targets = append(targets, t)
	}
	rows.Close()

	for _, t := range targets {
		st, err := PurgeExpired(ctx, pool, t.id, t.days)
		switch {
		case err != nil:
			log.Error("日志清理失败", "tenant", t.id, "err", err.Error())
		case st.Deleted > 0:
			log.Info("日志清理完成", "tenant", t.id,
				"days", tenant.NormalizeRetention(t.days),
				"throughSeq", st.ThroughSeq, "deleted", st.Deleted)
		}
	}
}
