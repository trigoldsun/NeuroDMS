// Package feature 实现按租户的灰度开关。
//
// 求值顺序（固定，不可调换）：
//  1. 租户显式覆盖——运营已经对这个租户做了决定，不该再被百分比覆盖一次；
//  2. 全局总开关 default_enabled 为假 → 一律关闭（一键止血）；
//  3. rollout_percent：100 全量、0 关闭，其余按稳定分桶。
//
// 分桶用 SHA-256(tenantID + "|" + code)，**不用** PG 的 hashtext：
// hashtext 的实现不保证跨大版本稳定，数据库升级会让所有租户突然换桶，
// 表现为"某天全体用户的功能同时变了"。这种问题极难定位。
package feature

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"docvault/internal/db"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// 内置开关编码。与迁移里的种子保持一致。
const (
	// ShareExternal 对外分享链接
	ShareExternal = "share.external"
	// CustomDomain 租户绑定自有域名
	CustomDomain = "branding.custom_domain"
	// ShareEmailVerify 分享访客邮箱验证码
	ShareEmailVerify = "share.email_verify"
	// MediaTranscode 音视频转码
	MediaTranscode = "media.transcode"
)

// ErrUnknownFlag 表示开关不存在（防止拼写错误被当成"关闭"）。
var ErrUnknownFlag = errors.New("未知的开关编码")

// Def 是开关定义。
type Def struct {
	Code        string    `json:"code"`
	Description string    `json:"description"`
	Default     bool      `json:"defaultEnabled"`
	Rollout     int       `json:"rolloutPercent"`
	UpdatedAt   time.Time `json:"updatedAt"`
}

// Service 提供开关求值。
//
// 缓存策略：开关定义与租户覆盖都缓存 TTL，改动后主动失效。
// 开关不是安全边界（关闭一个开关不能代替权限校验），因此 30 秒的收敛延迟
// 是可接受的；反过来，每个请求查一次库是不可接受的。
type Service struct {
	pool *pgxpool.Pool
	ttl  time.Duration
	now  func() time.Time

	mu       sync.RWMutex
	defs     map[string]Def
	defsAt   time.Time
	override map[string]overrideSet // tenantID -> 覆盖
}

type overrideSet struct {
	values map[string]bool
	at     time.Time
}

// New 构造服务。
func New(pool *pgxpool.Pool) *Service {
	return &Service{pool: pool, ttl: 30 * time.Second, now: time.Now,
		defs: map[string]Def{}, override: map[string]overrideSet{}}
}

// Enabled 判断某租户是否启用某开关。
//
// 出错时返回 false 并带错误：开关读到一半失败就"当作开启"会让未发布的功能
// 意外暴露；当作关闭只是功能少一块，可控。
func (s *Service) Enabled(ctx context.Context, tenantID, code string) (bool, error) {
	if tenantID == "" {
		return false, errors.New("租户上下文为空")
	}
	defs, err := s.loadDefs(ctx)
	if err != nil {
		return false, err
	}
	def, ok := defs[code]
	if !ok {
		return false, fmt.Errorf("%w: %s", ErrUnknownFlag, code)
	}

	ov, err := s.loadOverrides(ctx, tenantID)
	if err != nil {
		return false, err
	}
	if v, ok := ov[code]; ok {
		return v, nil
	}
	return eval(def, tenantID), nil
}

// MustEnabled 是给"开关读不到就当作关闭"的场景用的便捷方法。
// 只用于非关键路径（例如界面展示），业务拦截必须用 Enabled 并显式处理错误。
func (s *Service) MustEnabled(ctx context.Context, tenantID, code string) bool {
	ok, err := s.Enabled(ctx, tenantID, code)
	return err == nil && ok
}

// Effective 返回该租户所有开关的最终取值（含来源），供前端决定显示什么。
func (s *Service) Effective(ctx context.Context, tenantID string) ([]EffectiveFlag, error) {
	defs, err := s.loadDefs(ctx)
	if err != nil {
		return nil, err
	}
	ov, err := s.loadOverrides(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	out := make([]EffectiveFlag, 0, len(defs))
	for code, def := range defs {
		var op *bool
		if v, ok := ov[code]; ok {
			v := v
			op = &v
		}
		out = append(out, evalFlag(def, tenantID, op))
	}
	// 稳定顺序，便于前端 diff 与测试断言
	for i := 0; i < len(out); i++ {
		for j := i + 1; j < len(out); j++ {
			if out[j].Code < out[i].Code {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out, nil
}

// EffectiveFlag 是开关的最终取值与来源。
type EffectiveFlag struct {
	Code        string `json:"code"`
	Description string `json:"description"`
	Enabled     bool   `json:"enabled"`
	// Source 说明这个取值由谁决定：default（总开关）| rollout（放量分桶）| override（租户覆盖）。
	Source string `json:"source"`
	// DefaultEnabled 与 RolloutPercent 一并返回，让界面能解释"为什么是关的"。
	// 只给一个布尔值时，运营看到"已开启"却全员不可用，无从判断。
	DefaultEnabled bool `json:"defaultEnabled"`
	RolloutPercent int  `json:"rolloutPercent"`
}

// evalFlag 是单条求值的唯一实现，Effective 与 Evaluate 共用。
//
// 关键在来源标注：放量 <100（含 0）时实际取值由分桶决定，来源必须标 rollout。
// 之前只在 0 < rollout < 100 时标 rollout，于是"总开关开启 + 放量 0%"被标成
// default/已开启——界面显示一切正常，功能对所有人关闭，运营查不到原因。
func evalFlag(def Def, tenantID string, override *bool) EffectiveFlag {
	f := EffectiveFlag{
		Code:           def.Code,
		Description:    def.Description,
		Enabled:        eval(def, tenantID),
		Source:         "default",
		DefaultEnabled: def.Default,
		RolloutPercent: def.Rollout,
	}
	if def.Rollout < 100 {
		f.Source = "rollout"
	}
	if override != nil {
		f.Enabled, f.Source = *override, "override"
	}
	return f
}

// Evaluate 返回单个开关对某租户的有效值与来源。
//
// 拦截点用它而不是 Enabled，是为了在拒绝时能说清"是谁关的"：
// 租户覆盖、平台放量、还是读不到。只说"未开启，请联系运营"，
// 运营打开控制台看到"已开启"，双方都无从下手。
func (s *Service) Evaluate(ctx context.Context, tenantID, code string) (EffectiveFlag, error) {
	if tenantID == "" {
		return EffectiveFlag{}, errors.New("租户上下文为空")
	}
	defs, err := s.loadDefs(ctx)
	if err != nil {
		return EffectiveFlag{}, err
	}
	def, ok := defs[strings.TrimSpace(code)]
	if !ok {
		return EffectiveFlag{}, fmt.Errorf("%w: %s", ErrUnknownFlag, code)
	}
	ov, err := s.loadOverrides(ctx, tenantID)
	if err != nil {
		return EffectiveFlag{}, err
	}
	var op *bool
	if v, ok := ov[code]; ok {
		v := v
		op = &v
	}
	return evalFlag(def, tenantID, op), nil
}

// List 返回全部开关定义（平台侧）。
func (s *Service) List(ctx context.Context) ([]Def, error) {
	s.mu.RLock()
	defs := make(map[string]Def, len(s.defs))
	for k, v := range s.defs {
		defs[k] = v
	}
	fresh := s.now().Sub(s.defsAt) <= s.ttl
	s.mu.RUnlock()

	if !fresh {
		var err error
		if defs, err = s.loadDefs(ctx); err != nil {
			return nil, err
		}
	}

	out := make([]Def, 0, len(defs))
	for _, d := range defs {
		out = append(out, d)
	}
	for i := 0; i < len(out); i++ {
		for j := i + 1; j < len(out); j++ {
			if out[j].Code < out[i].Code {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out, nil
}

// SetFlag 修改开关定义（平台侧）。
func (s *Service) SetFlag(ctx context.Context, code string, def bool, rollout int) error {
	code = strings.TrimSpace(code)
	if rollout < 0 || rollout > 100 {
		return fmt.Errorf("放量比例需在 0-100 之间")
	}
	ct, err := s.pool.Exec(ctx, `
		UPDATE feature_flag SET default_enabled = $2, rollout_percent = $3, updated_at = now()
		 WHERE code = $1`, code, def, rollout)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return fmt.Errorf("%w: %s", ErrUnknownFlag, code)
	}
	s.Invalidate()
	return nil
}

// SetOverride 给某租户设置显式开关值（平台侧）。
func (s *Service) SetOverride(ctx context.Context, tenantID, code string, enabled bool) error {
	// 先确认开关存在：外键会挡住，但提前给出清楚的错误
	var n int
	if err := s.pool.QueryRow(ctx,
		`SELECT count(*) FROM feature_flag WHERE code = $1`, code).Scan(&n); err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("%w: %s", ErrUnknownFlag, code)
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO tenant_feature (tenant_id, code, enabled, updated_at)
		VALUES ($1, $2, $3, now())
		ON CONFLICT (tenant_id, code) DO UPDATE SET enabled = EXCLUDED.enabled, updated_at = now()`,
		tenantID, code, enabled)
	if err != nil {
		return err
	}
	s.Invalidate()
	return nil
}

// ClearOverride 删除显式覆盖，回到全局策略。
func (s *Service) ClearOverride(ctx context.Context, tenantID, code string) error {
	_, err := s.pool.Exec(ctx,
		`DELETE FROM tenant_feature WHERE tenant_id = $1 AND code = $2`, tenantID, code)
	if err != nil {
		return err
	}
	s.Invalidate()
	return nil
}

// TenantOverrides 返回某租户的显式覆盖（平台侧展示用）。
func (s *Service) TenantOverrides(ctx context.Context, slug string) ([]map[string]any, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT code, enabled, updated_at FROM platform_tenant_features($1)`, slug)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]map[string]any, 0, 4)
	for rows.Next() {
		var code string
		var enabled bool
		var at time.Time
		if err := rows.Scan(&code, &enabled, &at); err != nil {
			return nil, err
		}
		out = append(out, map[string]any{
			"code": code, "enabled": enabled, "updatedAt": at.UTC().Format(time.RFC3339),
		})
	}
	return out, rows.Err()
}

// Invalidate 清空缓存（改动后调用）。
func (s *Service) Invalidate() {
	s.mu.Lock()
	s.defs = map[string]Def{}
	s.defsAt = time.Time{}
	s.override = map[string]overrideSet{}
	s.mu.Unlock()
}

func (s *Service) loadDefs(ctx context.Context) (map[string]Def, error) {
	s.mu.RLock()
	if len(s.defs) > 0 && s.now().Sub(s.defsAt) <= s.ttl {
		out := make(map[string]Def, len(s.defs))
		for k, v := range s.defs {
			out[k] = v
		}
		s.mu.RUnlock()
		return out, nil
	}
	s.mu.RUnlock()

	rows, err := s.pool.Query(ctx,
		`SELECT code, description, default_enabled, rollout_percent, updated_at FROM feature_flag`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	defs := map[string]Def{}
	for rows.Next() {
		var d Def
		if err := rows.Scan(&d.Code, &d.Description, &d.Default, &d.Rollout, &d.UpdatedAt); err != nil {
			return nil, err
		}
		defs[d.Code] = d
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	s.mu.Lock()
	s.defs = defs
	s.defsAt = s.now()
	s.mu.Unlock()
	return defs, nil
}

func (s *Service) loadOverrides(ctx context.Context, tenantID string) (map[string]bool, error) {
	s.mu.RLock()
	if set, ok := s.override[tenantID]; ok && s.now().Sub(set.at) <= s.ttl {
		out := make(map[string]bool, len(set.values))
		for k, v := range set.values {
			out[k] = v
		}
		s.mu.RUnlock()
		return out, nil
	}
	s.mu.RUnlock()

	vals := map[string]bool{}
	// 走租户上下文：即使查询写错也读不到别的租户的覆盖
	err := db.WithTenant(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		rows, e := tx.Query(ctx,
			`SELECT code, enabled FROM tenant_feature WHERE tenant_id = $1`, tenantID)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var code string
			var enabled bool
			if e := rows.Scan(&code, &enabled); e != nil {
				return e
			}
			vals[code] = enabled
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	s.override[tenantID] = overrideSet{values: vals, at: s.now()}
	s.mu.Unlock()
	return vals, nil
}

// eval 是求值核心（纯函数，便于单测）。
func eval(d Def, tenantID string) bool {
	if !d.Default {
		return false
	}
	if d.Rollout >= 100 {
		return true
	}
	if d.Rollout <= 0 {
		return false
	}
	return bucket(tenantID, d.Code) < d.Rollout
}

// bucket 返回 [0,100) 的稳定分桶值。
func bucket(tenantID, code string) int {
	sum := sha256.Sum256([]byte(tenantID + "|" + code))
	n := binary.BigEndian.Uint32(sum[:4])
	return int(n % 100)
}
