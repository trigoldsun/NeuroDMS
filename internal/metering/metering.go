// Package metering 负责用量计量、配额判定与对账。
//
// 三层职责，边界清楚：
//   - 账本（usage_event / usage_daily）：可累加量，幂等写入；
//   - 瞬时量（tenant_usage）：由数据库触发器维护，本包只读；
//   - 判定（State / OverQuota）：把"用量 vs 配额"翻译成可执行的结论。
//
// 准确性从哪来（这也是对外解释"为什么可信"的答案）：
//  1. 存储与用户数不进应用层算术，触发器与业务写入同事务，不回滚不漂移；
//  2. 可累加量靠唯一约束去重，重试不会重复计费；
//  3. 仍然提供 reconcile：用事实值重算并与账本比对，偏差可见、可修。
//     任何声称"绝对准确"的系统，如果没有这条，只是在赌自己不出错。
package metering

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"docvault/internal/db"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// 计量指标。与 usage_event 的 CHECK 约束保持一致。
const (
	MetricAPICalls       = "api_calls"
	MetricTranscodeSecs  = "transcode_seconds"
	MetricShareViews     = "share_views"
	MetricPreviewRenders = "preview_renders"
	MetricEgressBytes    = "egress_bytes"
)

// Service 是计量入口。
type Service struct {
	pool *pgxpool.Pool

	// API 调用的分钟桶（见 FlushAPICalls 的说明）
	mu    sync.Mutex
	calls map[string]int64 // tenantID -> 未落库的计数
	now   func() time.Time
}

// New 构造服务。
func New(pool *pgxpool.Pool) *Service {
	return &Service{pool: pool, calls: make(map[string]int64), now: time.Now}
}

// Record 记一条用量事件。返回 false 表示 dedupeKey 已存在（重复提交）。
//
// 必须走**租户上下文**：usage_event 有 RLS，且这样做能顺带保证
// "不能替别的租户记账"。
func (s *Service) Record(ctx context.Context, tenantID, metric string,
	quantity int64, dedupeKey string, meta map[string]any) (bool, error) {

	if quantity < 0 {
		return false, fmt.Errorf("用量不能为负: %d", quantity)
	}
	if strings.TrimSpace(dedupeKey) == "" {
		return false, errors.New("dedupeKey 不能为空（否则同一事件会被重复计费）")
	}
	if meta == nil {
		meta = map[string]any{}
	}

	var fresh bool
	err := db.WithTenant(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT usage_record($1, $2, $3, $4, $5::jsonb)`,
			tenantID, metric, quantity, dedupeKey, mustJSON(meta)).Scan(&fresh)
	})
	return fresh, err
}

// ---------------- 状态与配额判定 ----------------

// State 是某租户当前的用量与限额快照。
type State struct {
	StorageBytes    int64  `json:"storageBytes"`
	ActiveUsers     int    `json:"activeUsers"`
	TranscodeSecs   int64  `json:"transcodeSecondsMonth"`
	APICallsToday   int64  `json:"apiCallsToday"`
	MaxStorageBytes *int64 `json:"maxStorageBytes"`
	MaxUsers        *int   `json:"maxUsers"`
	MaxTranscode    *int64 `json:"maxTranscodeSeconds"`
	MaxAPICallsDay  *int64 `json:"maxApiCallsDay"`
	OnExceed        string `json:"onExceed"`
}

// LoadState 读取用量与配额（一次查询，租户上下文）。
func (s *Service) LoadState(ctx context.Context, tenantID string) (State, error) {
	var st State
	err := db.WithTenant(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		e := tx.QueryRow(ctx, `
			SELECT us.storage_bytes, us.active_users,
			       q.max_storage_bytes, q.max_users, q.max_transcode_seconds,
			       q.max_api_calls_day, COALESCE(q.on_exceed, 'reject'),
			       COALESCE((SELECT sum(quantity) FROM usage_daily d
			                  WHERE d.tenant_id = us.tenant_id AND d.metric = 'transcode_seconds'
			                    AND d.day >= date_trunc('month', current_date)::date), 0),
			       COALESCE((SELECT sum(quantity) FROM usage_daily d
			                  WHERE d.tenant_id = us.tenant_id AND d.metric = 'api_calls'
			                    AND d.day = current_date), 0)
			  FROM tenant_usage us
			  LEFT JOIN tenant_quota q ON q.tenant_id = us.tenant_id
			 WHERE us.tenant_id = $1`, tenantID).
			Scan(&st.StorageBytes, &st.ActiveUsers,
				&st.MaxStorageBytes, &st.MaxUsers, &st.MaxTranscode,
				&st.MaxAPICallsDay, &st.OnExceed, &st.TranscodeSecs, &st.APICallsToday)
		return e
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return State{OnExceed: "reject"}, nil
		}
		return State{}, err
	}
	if st.OnExceed == "" {
		st.OnExceed = "reject"
	}
	return st, nil
}

// Exceeded 返回已经超限的维度名（空表示未超）。
//
// 只说"超了没有"，不说"能不能继续"——后者由调用方按 onExtend 策略决定，
// 因为同一份超额在"上传"和"读文件"两个场景下的处理完全不同。
func (st State) Exceeded() []string {
	var out []string
	if st.MaxStorageBytes != nil && st.StorageBytes >= *st.MaxStorageBytes {
		out = append(out, "storage")
	}
	if st.MaxUsers != nil && st.ActiveUsers >= *st.MaxUsers {
		out = append(out, "users")
	}
	if st.MaxTranscode != nil && st.TranscodeSecs >= *st.MaxTranscode {
		out = append(out, "transcode")
	}
	if st.MaxAPICallsDay != nil && st.APICallsToday >= *st.MaxAPICallsDay {
		out = append(out, "api_calls")
	}
	return out
}

// Verdict 是一次配额判定的结论。
type Verdict struct {
	Allowed bool
	// Reason 用于审计与错误信息，如 "storage" / "users"
	Reason string
	// Policy 是触发的超限策略（reject/readonly/warn）
	Policy string
}

// Check 判断"再做一次 addBytes 的存储写入"是否允许。
//
// 说明：数据库触发器已经对 on_exceed=reject 做了硬拦截，这里的判断是为了
// 在**写入之前**给出可读的错误，并且处理 readonly/warn 两种软策略。
// 两处都判不是重复，而是分工：触发器保证"绝不会超"，这里保证"超了要说清楚"。
func (s *Service) Check(ctx context.Context, tenantID string, metric string, add int64) (Verdict, error) {
	st, err := s.LoadState(ctx, tenantID)
	if err != nil {
		// 读不到配额时**放行**：配额是运营约束，不是安全边界。
		// 因为一次数据库抖动就把上传全拒掉，造成的损失比超一点配额大得多。
		// 真正的安全性由存储配额之外的机制保证（密级、ACL）。
		return Verdict{Allowed: true, Policy: "unknown"}, nil
	}
	policy := st.OnExceed
	if policy == "warn" {
		return Verdict{Allowed: true, Policy: policy}, nil
	}

	switch metric {
	case "storage":
		if st.MaxStorageBytes != nil && st.StorageBytes+add > *st.MaxStorageBytes {
			return Verdict{Allowed: policy != "reject" && policy != "readonly", Reason: "storage", Policy: policy}, nil
		}
	case "users":
		if st.MaxUsers != nil && st.ActiveUsers+int(add) > *st.MaxUsers {
			return Verdict{Allowed: policy != "reject" && policy != "readonly", Reason: "users", Policy: policy}, nil
		}
	case "transcode":
		if st.MaxTranscode != nil && st.TranscodeSecs+add > *st.MaxTranscode {
			return Verdict{Allowed: policy != "reject" && policy != "readonly", Reason: "transcode", Policy: policy}, nil
		}
	}
	return Verdict{Allowed: true, Policy: policy}, nil
}

// WritesBlocked 判断该租户是否因配额降级为只读。
//
// 供中间件在每个写请求上调用（带 TTL 缓存，见 CachedState）。
func (st State) WritesBlocked() (bool, string) {
	if st.OnExceed != "readonly" {
		return false, ""
	}
	if ex := st.Exceeded(); len(ex) > 0 {
		return true, ex[0]
	}
	return false, ""
}

// ---------------- 读账（平台与租户共用） ----------------

// Point 是某天的某项用量。
type Point struct {
	Day      string `json:"day"`
	Metric   string `json:"metric"`
	Quantity int64  `json:"quantity"`
}

// Series 返回区间内的日聚合（平台侧，跨租户）。
func (s *Service) Series(ctx context.Context, slug string, from, to time.Time) ([]Point, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT day, metric, quantity FROM platform_tenant_usage($1, $2::date, $3::date)`,
		slug, from.Format("2006-01-02"), to.Format("2006-01-02"))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Point
	for rows.Next() {
		var p Point
		var day time.Time
		if err := rows.Scan(&day, &p.Metric, &p.Quantity); err != nil {
			return nil, err
		}
		p.Day = day.Format("2006-01-02")
		out = append(out, p)
	}
	return out, rows.Err()
}

// MonthTotals 返回某月各指标合计（租户上下文，供客户自查与账单确认）。
func (s *Service) MonthTotals(ctx context.Context, tenantID, month string) (map[string]int64, error) {
	first, err := time.Parse("2006-01", month)
	if err != nil {
		return nil, fmt.Errorf("月份格式需为 YYYY-MM: %w", err)
	}
	last := first.AddDate(0, 1, -1)
	out := map[string]int64{}
	err = db.WithTenant(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		rows, e := tx.Query(ctx, `
			SELECT metric, sum(quantity) FROM usage_daily
			 WHERE tenant_id = $1 AND day BETWEEN $2::date AND $3::date
			 GROUP BY metric`, tenantID, first.Format("2006-01-02"), last.Format("2006-01-02"))
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var m string
			var q int64
			if e := rows.Scan(&m, &q); e != nil {
				return e
			}
			out[m] = q
		}
		return rows.Err()
	})
	return out, err
}

// ---------------- 对账 ----------------

// Drift 是一个租户的账实偏差。
type Drift struct {
	Slug            string `json:"slug"`
	StorageRecorded int64  `json:"storageRecorded"`
	StorageActual   int64  `json:"storageActual"`
	StorageDrift    int64  `json:"storageDrift"`
	UsersRecorded   int    `json:"usersRecorded"`
	UsersActual     int    `json:"usersActual"`
	UsersDrift      int    `json:"usersDrift"`
}

// Reconcile 对账。repair 为真时同时修正账本。
func (s *Service) Reconcile(ctx context.Context, repair bool) ([]Drift, error) {
	rows, err := s.pool.Query(ctx, `SELECT * FROM platform_usage_reconcile($1)`, repair)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Drift
	for rows.Next() {
		var d Drift
		if err := rows.Scan(&d.Slug, &d.StorageRecorded, &d.StorageActual, &d.StorageDrift,
			&d.UsersRecorded, &d.UsersActual, &d.UsersDrift); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Slug < out[j].Slug })
	return out, nil
}

// ---------------- API 调用计数（进程内聚合） ----------------

// CountAPICall 累加一次 API 调用（内存，不落库）。
//
// 为什么不在每个请求上写库：那是每个请求一次小事务，代价远大于收益。
// 这里的取舍必须说清楚：API 调用是**运营观察指标**，不是计费口径
// （计费按存储与用户数，两者由触发器保证精确）。
// 进程被强杀时最多丢一个 flush 周期（默认 10 秒）的计数。
func (s *Service) CountAPICall(tenantID string) {
	if tenantID == "" {
		return
	}
	s.mu.Lock()
	s.calls[tenantID]++
	s.mu.Unlock()
}

// FlushAPICalls 把内存计数写成 usage_event（每个租户每分钟一条）。
//
// 用"租户 + 分钟"作为 dedupeKey：即使两实例同时 flush，也只有一条落库，
// 另一条被唯一约束吞掉——宁可少记一次两者之一，也不重复计费。
func (s *Service) FlushAPICalls(ctx context.Context) error {
	s.mu.Lock()
	pending := s.calls
	s.calls = make(map[string]int64)
	s.mu.Unlock()

	if len(pending) == 0 {
		return nil
	}
	bucket := s.now().UTC().Truncate(time.Minute).Format("200601021504")

	var firstErr error
	for tenantID, n := range pending {
		if n == 0 {
			continue
		}
		if _, err := s.Record(ctx, tenantID, MetricAPICalls, n,
			"api:"+tenantID+":"+bucket, map[string]any{"window": "1m"}); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			// 写失败就把计数放回去，下一轮再试（不丢）
			s.mu.Lock()
			s.calls[tenantID] += n
			s.mu.Unlock()
		}
	}
	return firstErr
}

func mustJSON(v map[string]any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		return []byte("{}")
	}
	return b
}
