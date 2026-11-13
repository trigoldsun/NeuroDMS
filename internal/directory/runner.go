package directory

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"docvault/internal/db"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// 同步的运行控制与可观测（PRD-IAM-20）。

// ErrSyncRunning 表示该租户已有同步在跑。
var ErrSyncRunning = errors.New("该租户已有同步任务在运行，请等待完成")

// ErrNotConfigured 表示目录未启用或缺少必要字段。
var ErrNotConfigured = errors.New("目录认证未启用或配置不完整")

// RunRow 是同步运行记录（读模型）。
type RunRow struct {
	ID            string     `json:"id"`
	StartedAt     time.Time  `json:"startedAt"`
	FinishedAt    *time.Time `json:"finishedAt,omitempty"`
	Status        string     `json:"status"`
	Watermark     string     `json:"watermark"`
	UsersSeen     int        `json:"usersSeen"`
	UsersCreated  int        `json:"usersCreated"`
	UsersUpdated  int        `json:"usersUpdated"`
	UsersDisabled int        `json:"usersDisabled"`
	UsersRestored int        `json:"usersRestored"`
	GroupsSynced  int        `json:"groupsSynced"`
	MembersLinked int        `json:"membersLinked"`
	// Conflicts 与冲突账号：同步"看到了但没进来"的原因必须能直接看到
	Conflicts     int      `json:"conflicts"`
	ConflictUsers []string `json:"conflictUsers"`
	Error         string   `json:"error,omitempty"`
}

// Runner 负责触发同步与调度。
type Runner struct {
	pool *pgxpool.Pool
	res  *Resolver
	log  *slog.Logger

	mu   sync.Mutex
	busy map[string]bool
}

func NewRunner(pool *pgxpool.Pool, res *Resolver, log *slog.Logger) *Runner {
	return &Runner{pool: pool, res: res, log: log, busy: map[string]bool{}}
}

// Trigger 异步触发一次同步，立即返回。
//
// 为什么不做成同步等待：一次同步在大目录上要几分钟，
// HTTP 请求早超时了；而且中途断开连接不应中断同步。
// 前端通过 Runs 轮询进度。
func (r *Runner) Trigger(ctx context.Context, tenantID, mode string) error {
	if mode != "full" {
		mode = "incremental"
	}

	r.mu.Lock()
	if r.busy[tenantID] {
		r.mu.Unlock()
		return ErrSyncRunning
	}
	// 多实例部署时进程内标记拦不住另一个实例，再用库里的 running 记录兜一层。
	// 30 分钟的窗口用于兜底"进程被杀导致记录卡在 running"。
	var running int
	if err := db.WithTenant(ctx, r.pool, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
			SELECT count(*) FROM directory_sync
			 WHERE tenant_id = $1 AND status = 'running'
			   AND started_at > now() - interval '30 minutes'`, tenantID).Scan(&running)
	}); err != nil {
		r.mu.Unlock()
		return err
	}
	if running > 0 {
		r.mu.Unlock()
		return ErrSyncRunning
	}
	r.busy[tenantID] = true
	r.mu.Unlock()

	go func() {
		defer func() {
			r.mu.Lock()
			delete(r.busy, tenantID)
			r.mu.Unlock()
		}()
		// 与请求上下文解绑：请求返回后同步要继续跑
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
		defer cancel()
		res, err := r.RunOnce(ctx, tenantID, mode)
		if err != nil {
			r.log.Error("目录同步失败", "tenant", tenantID, "mode", mode, "err", err.Error())
			return
		}
		r.log.Info("目录同步完成", "tenant", tenantID, "mode", mode,
			"seen", res.Seen, "created", res.Created, "updated", res.Updated,
			"disabled", res.Disabled, "restored", res.Restored,
			"groups", res.GroupsSynced, "members", res.MembersLinked)
	}()
	return nil
}

// RunOnce 同步执行一次（供 Trigger 与测试使用）。
func (r *Runner) RunOnce(ctx context.Context, tenantID, mode string) (Result, error) {
	s, err := r.res.Effective(ctx, tenantID)
	if err != nil {
		return Result{}, err
	}
	if !s.Enabled || s.URL == "" || s.BaseDN == "" {
		return Result{}, ErrNotConfigured
	}
	dir, err := r.res.For(ctx, tenantID)
	if err != nil || dir == nil {
		// 连不上目录时也要落一条失败记录：现场排障第一句话就是
		// "同步到底跑了没、报了什么"，只在服务端日志里留着等于没有。
		if err != nil {
			recordFailure(ctx, r.pool, tenantID, err)
		}
		if err != nil {
			return Result{}, err
		}
		return Result{}, ErrNotConfigured
	}

	since := ""
	if mode == "incremental" {
		since, _ = r.LastWatermark(ctx, tenantID)
	}
	return Sync(ctx, r.pool, tenantID, dir, since, Options{
		// 离职回收默认开启：域里没有的人不应该还能登录。
		// 空快照由 Sync 内部拦截（见 ErrEmptySnapshot）。
		DisableMissing:  true,
		ExcludeAccounts: s.ExcludeAccounts,
	})
}

// LastWatermark 取最近一次成功同步的水位。
func (r *Runner) LastWatermark(ctx context.Context, tenantID string) (string, error) {
	var w *string
	err := db.WithTenant(ctx, r.pool, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
			SELECT watermark FROM directory_sync
			 WHERE tenant_id = $1 AND status = 'ok'
			 ORDER BY started_at DESC LIMIT 1`, tenantID).Scan(&w)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	if w == nil {
		return "", nil
	}
	return *w, nil
}

// Runs 读取最近的同步记录。
func (r *Runner) Runs(ctx context.Context, tenantID string, limit int) ([]RunRow, error) {
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	var out []RunRow
	err := db.WithTenant(ctx, r.pool, tenantID, func(tx pgx.Tx) error {
		rows, e := tx.Query(ctx, `
			SELECT id::text, started_at, finished_at, status, coalesce(watermark,''),
			       users_seen, users_created, users_updated, users_disabled, users_restored,
			       groups_synced, members_linked, conflicts, conflict_users, coalesce(error,'')
			  FROM directory_sync WHERE tenant_id = $1
			 ORDER BY started_at DESC LIMIT $2`, tenantID, limit)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var x RunRow
			if e := rows.Scan(&x.ID, &x.StartedAt, &x.FinishedAt, &x.Status, &x.Watermark,
				&x.UsersSeen, &x.UsersCreated, &x.UsersUpdated, &x.UsersDisabled,
				&x.UsersRestored, &x.GroupsSynced, &x.MembersLinked,
				&x.Conflicts, &x.ConflictUsers, &x.Error); e != nil {
				return e
			}
			out = append(out, x)
		}
		return rows.Err()
	})
	if out == nil {
		out = []RunRow{}
	}
	return out, err
}

// RunScheduler 按各租户配置的间隔自动同步。
//
// 每 5 分钟检查一次：间隔最小是 5 分钟级需求（PRD 要求增量 5 分钟内生效），
// 但没必要更密——调度本身的成本要低于它带来的价值。
func (r *Runner) RunScheduler(ctx context.Context, tick time.Duration) {
	if tick <= 0 {
		tick = 5 * time.Minute
	}
	t := time.NewTicker(tick)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			r.tick(ctx)
		}
	}
}

func (r *Runner) tick(ctx context.Context) {
	rows, err := r.pool.Query(ctx, `
		SELECT c.tenant_id::text
		  FROM directory_config c
		  JOIN tenant t ON t.id = c.tenant_id
		 WHERE c.enabled AND c.sync_interval_minutes > 0
		   AND t.deleted_at IS NULL AND t.status = 'active'
		   AND coalesce((SELECT max(s.started_at) FROM directory_sync s
		                  WHERE s.tenant_id = c.tenant_id AND s.status = 'ok'),
		                to_timestamp(0))
		       < now() - make_interval(mins => c.sync_interval_minutes)`)
	if err != nil {
		r.log.Error("读取自动同步计划失败", "err", err.Error())
		return
	}
	var tenants []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err == nil {
			tenants = append(tenants, id)
		}
	}
	rows.Close()

	for _, id := range tenants {
		if err := r.Trigger(ctx, id, "incremental"); err != nil && !errors.Is(err, ErrSyncRunning) {
			r.log.Error("自动同步触发失败", "tenant", id, "err", err.Error())
		}
	}
}
