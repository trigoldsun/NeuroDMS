package audit

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// RunDailyAnchors 周期性给所有租户结算"昨天"的锚点。
//
// 为什么只结算昨天：今天的链还在增长，此刻算出的根几分钟后就不成立了。
// 结算已结束的自然日，才是稳定可比对的对象。
//
// 幂等：同一租户同一天只写一条（ON CONFLICT DO NOTHING），
// 因此进程重启/多实例并行都不会产生重复锚点。
func RunDailyAnchors(ctx context.Context, pool *pgxpool.Pool, secret []byte, log *slog.Logger, interval time.Duration) {
	if interval <= 0 {
		interval = time.Hour
	}
	tick := time.NewTicker(interval)
	defer tick.Stop()

	// 启动时先跑一次：避免"部署当天没跑，第二天的锚点也缺失"
	anchorAll(ctx, pool, secret, log)

	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			anchorAll(ctx, pool, secret, log)
		}
	}
}

func anchorAll(ctx context.Context, pool *pgxpool.Pool, secret []byte, log *slog.Logger) {
	rows, err := pool.Query(ctx, `SELECT id::text FROM tenant WHERE deleted_at IS NULL AND status = 'active'`)
	if err != nil {
		log.Error("读取租户列表失败（日结锚点）", "err", err.Error())
		return
	}
	var tenants []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			log.Error("读取租户失败", "err", err.Error())
			return
		}
		tenants = append(tenants, id)
	}
	rows.Close()

	yesterday := time.Now().UTC().AddDate(0, 0, -1)
	for _, t := range tenants {
		a, err := AnchorDay(ctx, pool, t, yesterday, secret)
		switch {
		case errors.Is(err, ErrNoEvents):
			// 昨天没业务，正常
		case err != nil:
			log.Error("日结锚点失败", "tenant", t, "err", err.Error())
		default:
			log.Info("日结锚点已生成", "tenant", t, "day", a.Day,
				"count", a.Count, "root", short(a.MerkleRoot))
		}
	}
}
