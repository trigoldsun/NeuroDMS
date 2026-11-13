// Package tenant 负责租户生命周期、租户级配置（品牌/策略）与配额。
//
// 边界（刻意划清）：
//   - 跨租户操作（开通、停用、列表、配额的写入）只以 SECURITY DEFINER 的
//     SQL 函数存在，Go 侧只是薄封装。跨租户能力越少越好，且必须能被 SQL 审计。
//   - 租户内的业务初始化（部门、首个管理员、角色）走正常的 WithTenant，
//     因为这些数据本来就属于该租户，不需要绕过隔离。
//
// 不在这里做的事：给某个用户"平台权限"。平台能力由独立令牌承载，
// 与租户内的账号体系完全分离（见 httpapi 的 requirePlatform）。
package tenant

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"docvault/internal/auth"
	"docvault/internal/db"
	"docvault/internal/edition"
	"docvault/internal/rbac"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// 业务错误。HTTP 层据此映射状态码，不靠字符串匹配。
var (
	ErrNotFound      = errors.New("租户不存在")
	ErrSlugTaken     = errors.New("租户标识已被占用")
	ErrInvalidInput  = errors.New("参数不合法")
	ErrInvalidStatus = errors.New("状态不合法")
)

// 状态取值与数据库 CHECK 一致。
const (
	StatusActive    = "active"
	StatusTrial     = "trial"
	StatusReadonly  = "readonly"
	StatusSuspended = "suspended"
	StatusDeleted   = "deleted"
)

// 超限行为。
const (
	OnExceedReject   = "reject"
	OnExceedReadonly = "readonly"
	OnExceedWarn     = "warn"
)

var (
	// 2-40 位小写字母/数字/连字符，且不能以连字符结尾：
	// 结尾的连字符在 URL 与主机名里都容易被误读（"acme-" 看起来像被截断）。
	slugRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,38}[a-z0-9]$`)
	// 颜色只接受 #rrggbb。不接受 rgb()/命名色：它们能被塞进 CSS 变量，
	// 而命名色在不同浏览器渲染不一致，会让"品牌色"变成"每台机器不一样"。
	colorRe = regexp.MustCompile(`^#[0-9a-fA-F]{6}$`)
	// 域名：小写、无协议、无端口、无路径
	hostRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$`)
)

// Service 是租户相关操作的入口。
type Service struct {
	pool *pgxpool.Pool
	// now 便于测试注入
	now func() time.Time
}

// New 构造服务。
func New(pool *pgxpool.Pool) *Service {
	return &Service{pool: pool, now: time.Now}
}

// Tenant 是平台视角的租户视图（只含规模与状态，不含业务明细）。
type Tenant struct {
	Slug           string     `json:"slug"`
	Name           string     `json:"name"`
	Status         string     `json:"status"`
	Plan           string     `json:"plan"`
	CreatedAt      time.Time  `json:"createdAt"`
	TrialEndsAt    *time.Time `json:"trialEndsAt"`
	SuspendedAt    *time.Time `json:"suspendedAt"`
	RetentionUntil *time.Time `json:"retentionUntil"`
	ContactEmail   string     `json:"contactEmail"`
	Users          int64      `json:"users"`
	StorageBytes   int64      `json:"storageBytes"`
	Files          int64      `json:"files"`

	// Edition 是真实档位。Plan 是历史字段，库里由触发器强制等于 Edition，
	// 这里仍返回是为了兼容尚未切换的调用方；新代码一律读 Edition。
	Edition          string     `json:"edition"`
	EditionExpiresAt *time.Time `json:"editionExpiresAt"`
}

// CreateInput 是开通租户的输入。
type CreateInput struct {
	Slug string `json:"slug"`
	Name string `json:"name"`

	// Edition 决定这个租户开通后能用什么。
	//
	// 开通与授权合成一步，是 0036 的核心改动：此前开通完是 basic，
	// 运营必须再进详情页改档，漏做就是"客户拿专业版合同用基础版"。
	// 空值按 basic 处理——与列默认值一致，不制造第三种默认。
	Edition string `json:"edition"`
	// EditionExpiresAt 是档位到期日（RFC3339 或 YYYY-MM-DD），空表示不限期。
	EditionExpiresAt string `json:"editionExpiresAt"`

	// Plan 已废弃：库里的 plan 是 edition 的镜像，传什么都会被覆盖。
	// 保留字段只为兼容旧版运营台，新代码不要传。
	Plan         string `json:"plan"`
	TrialDays    int    `json:"trialDays"`
	ContactEmail string `json:"contactEmail"`

	// 首个管理员。开通接口必须能直接交付一个可登录的账号，
	// 否则运营还要手工建人，容易漏配置导致"租户存在但没人能进"。
	AdminUsername string `json:"adminUsername"`
	AdminPassword string `json:"adminPassword"`
	AdminEmail    string `json:"adminEmail"`
	AdminDisplay  string `json:"adminDisplayName"`
}

// Created 是开通结果。
type Created struct {
	Slug        string `json:"slug"`
	TenantID    string `json:"tenantId"`
	AdminUserID string `json:"adminUserId"`
	Status      string `json:"status"`
}

const minAdminPasswordLen = 12

// Create 开通租户并创建首个系统管理员。
//
// 分成两步：先在平台函数里建 tenant 行，再切到该租户的上下文建业务数据。
// 不让一个 SECURITY DEFINER 函数把业务表也写掉——那样"跨租户能力"的
// 面积会从 1 张表扩大到 4 张表。
func (s *Service) Create(ctx context.Context, in CreateInput) (Created, error) {
	in.Slug = strings.ToLower(strings.TrimSpace(in.Slug))
	in.Name = strings.TrimSpace(in.Name)
	in.AdminUsername = strings.TrimSpace(in.AdminUsername)
	in.Plan = strings.TrimSpace(in.Plan)

	if !slugRe.MatchString(in.Slug) {
		return Created{}, fmt.Errorf("%w: 标识需为 2-41 位小写字母/数字/连字符，且以字母或数字开头", ErrInvalidInput)
	}
	if in.Name == "" || len([]rune(in.Name)) > 80 {
		return Created{}, fmt.Errorf("%w: 名称需为 1-80 字符", ErrInvalidInput)
	}
	if in.AdminUsername == "" || len(in.AdminUsername) > 64 {
		return Created{}, fmt.Errorf("%w: 管理员账号需为 1-64 字符", ErrInvalidInput)
	}
	// 口令强度与登录侧一致：开通时放松等于给自己留一个弱口令入口
	if len([]rune(in.AdminPassword)) < minAdminPasswordLen {
		return Created{}, fmt.Errorf("%w: 管理员口令至少 %d 位", ErrInvalidInput, minAdminPasswordLen)
	}
	if in.TrialDays < 0 || in.TrialDays > 365 {
		return Created{}, fmt.Errorf("%w: 试用天数需在 0-365 之间", ErrInvalidInput)
	}

	ed, expires, err := normalizeEditionInput(in.Edition, in.EditionExpiresAt)
	if err != nil {
		return Created{}, err
	}

	hash, err := auth.HashPassword(in.AdminPassword)
	if err != nil {
		return Created{}, err
	}

	var tenantID string
	var status string
	// 档位与开通放在同一事务语义里（函数内部 UPDATE），不会出现"租户建了、档位没设"。
	if err := s.pool.QueryRow(ctx,
		`SELECT platform_tenant_create($1, $2, $3, $4, $5, $6, $7)::text`,
		in.Slug, in.Name, in.Plan, in.TrialDays, in.ContactEmail, ed, expires).Scan(&tenantID); err != nil {
		if isDup(err) {
			return Created{}, ErrSlugTaken
		}
		if isCode(err, "DV002") {
			return Created{}, fmt.Errorf("%w: %s", ErrInvalidInput, err.Error())
		}
		return Created{}, fmt.Errorf("创建租户失败: %w", err)
	}
	if in.TrialDays > 0 {
		status = StatusTrial
	} else {
		status = StatusActive
	}

	var adminID string
	err = db.WithTenant(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		var deptID string
		if e := tx.QueryRow(ctx, `
			INSERT INTO dept (id, tenant_id, path, name)
			VALUES (gen_random_uuid(), $1, 'root'::ltree, $2)
			RETURNING id::text`, tenantID, "总部").Scan(&deptID); e != nil {
			return e
		}
		display := strings.TrimSpace(in.AdminDisplay)
		if display == "" {
			display = in.AdminUsername
		}
		if e := tx.QueryRow(ctx, `
			INSERT INTO app_user (id, tenant_id, username, display_name, password_hash,
			                      email, dept_id, status, classification)
			VALUES (gen_random_uuid(), $1, $2, $3, $4, nullif($5,''), $6, 'active', 1)
			RETURNING id::text`,
			tenantID, in.AdminUsername, display, hash, in.AdminEmail, deptID).Scan(&adminID); e != nil {
			return e
		}
		// 先把角色表补齐（Bootstrap 幂等），再显式授予 sysadmin。
		// 不依赖 Bootrap 的"取最早用户"逻辑：那在存在历史数据时会授错人。
		if e := rbac.Bootstrap(ctx, tx, tenantID); e != nil {
			return e
		}
		return rbac.Grant(ctx, tx, tenantID, adminID, rbac.SysAdmin, adminID)
	})
	if err != nil {
		// 业务初始化失败必须回滚租户行，否则留下一个"没人能登录"的空租户。
		// 这里用逻辑删除收尾（物理删除会连带审计痕迹，且并发下不安全）。
		_, _ = s.pool.Exec(ctx,
			`SELECT platform_tenant_set_status($1, 'deleted')`, in.Slug)
		return Created{}, fmt.Errorf("初始化租户数据失败: %w", err)
	}

	return Created{Slug: in.Slug, TenantID: tenantID, AdminUserID: adminID, Status: status}, nil
}

// StatusChange 是一次状态变更的结果。
type StatusChange struct {
	TenantID   string `json:"tenantId"`
	PrevStatus string `json:"prevStatus"`
	CurStatus  string `json:"curStatus"`
}

// SetStatus 变更租户状态。停用/删除会在同一事务里吊销全部会话。
func (s *Service) SetStatus(ctx context.Context, slug, status string) (StatusChange, error) {
	slug = strings.ToLower(strings.TrimSpace(slug))
	switch status {
	case StatusActive, StatusTrial, StatusReadonly, StatusSuspended, StatusDeleted:
	default:
		return StatusChange{}, ErrInvalidStatus
	}

	var out StatusChange
	err := s.pool.QueryRow(ctx,
		`SELECT tid::text, prev_status, cur_status FROM platform_tenant_set_status($1, $2)`,
		slug, status).Scan(&out.TenantID, &out.PrevStatus, &out.CurStatus)
	if err != nil {
		if isCode(err, "DV404") || errors.Is(err, pgx.ErrNoRows) {
			return StatusChange{}, ErrNotFound
		}
		if isCode(err, "DV002") {
			return StatusChange{}, ErrInvalidStatus
		}
		return StatusChange{}, fmt.Errorf("变更租户状态失败: %w", err)
	}
	return out, nil
}

// List 返回全部未删除租户（按创建时间）。
func (s *Service) List(ctx context.Context) ([]Tenant, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT slug, name, status, plan, created_at, trial_ends_at, suspended_at,
		       retention_until, contact_email, users, storage_bytes, files,
		       edition, edition_expires_at
		  FROM platform_tenant_list()`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanTenants(rows)
}

// Get 返回单个租户。
func (s *Service) Get(ctx context.Context, slug string) (Tenant, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT slug, name, status, plan, created_at, trial_ends_at, suspended_at,
		       retention_until, contact_email, users, storage_bytes, files,
		       edition, edition_expires_at
		  FROM platform_tenant_get($1)`, strings.ToLower(strings.TrimSpace(slug)))
	if err != nil {
		return Tenant{}, err
	}
	defer rows.Close()
	list, err := scanTenants(rows)
	if err != nil {
		return Tenant{}, err
	}
	if len(list) == 0 {
		return Tenant{}, ErrNotFound
	}
	return list[0], nil
}

// ResolveID 把 slug 换成租户 ID（不存在时返回 ErrNotFound）。
func (s *Service) ResolveID(ctx context.Context, slug string) (string, error) {
	var id *string
	if err := s.pool.QueryRow(ctx,
		`SELECT platform_resolve_tenant($1)::text`, strings.ToLower(strings.TrimSpace(slug))).
		Scan(&id); err != nil {
		return "", err
	}
	if id == nil || *id == "" {
		return "", ErrNotFound
	}
	return *id, nil
}

// ---------------- 配额 ----------------

// Quota 是租户配额。指针为 nil 表示"不限"。
type Quota struct {
	MaxUsers            *int   `json:"maxUsers"`
	MaxStorageBytes     *int64 `json:"maxStorageBytes"`
	MaxTranscodeSeconds *int64 `json:"maxTranscodeSeconds"`
	MaxAPICallsDay      *int64 `json:"maxApiCallsDay"`
	OnExceed            string `json:"onExceed"`
}

// SetQuota 由平台设置配额。
func (s *Service) SetQuota(ctx context.Context, slug string, q Quota) error {
	if q.OnExceed == "" {
		q.OnExceed = OnExceedReject
	}
	switch q.OnExceed {
	case OnExceedReject, OnExceedReadonly, OnExceedWarn:
	default:
		return fmt.Errorf("%w: onExceed 仅支持 reject/readonly/warn", ErrInvalidInput)
	}
	// 函数返回 void，用 Exec（QueryRow 会多一列 NULL，反而要处理扫描）
	_, err := s.pool.Exec(ctx,
		`SELECT platform_tenant_set_quota($1, $2, $3, $4, $5, $6)`,
		slug, q.MaxUsers, q.MaxStorageBytes, q.MaxTranscodeSeconds,
		q.MaxAPICallsDay, q.OnExceed)
	if err != nil {
		if isCode(err, "DV404") {
			return ErrNotFound
		}
		if isCode(err, "DV002") {
			return fmt.Errorf("%w: %s", ErrInvalidInput, err.Error())
		}
		return err
	}
	return nil
}

// GetQuota 由平台读取配额。
func (s *Service) GetQuota(ctx context.Context, slug string) (Quota, error) {
	var q Quota
	err := s.pool.QueryRow(ctx,
		`SELECT max_users, max_storage_bytes, max_transcode_seconds, max_api_calls_day, on_exceed
		   FROM platform_tenant_quota($1)`, slug).
		Scan(&q.MaxUsers, &q.MaxStorageBytes, &q.MaxTranscodeSeconds,
			&q.MaxAPICallsDay, &q.OnExceed)
	if err != nil {
		if isCode(err, "DV404") || errors.Is(err, pgx.ErrNoRows) {
			return Quota{}, ErrNotFound
		}
		return Quota{}, err
	}
	if q.OnExceed == "" {
		q.OnExceed = OnExceedReject
	}
	return q, nil
}

// SelfQuota 在租户上下文里读取自己的配额（客户管理台用）。
func SelfQuota(ctx context.Context, tx pgx.Tx, tenantID string) (Quota, error) {
	var q Quota
	err := tx.QueryRow(ctx, `
		SELECT max_users, max_storage_bytes, max_transcode_seconds, max_api_calls_day, on_exceed
		  FROM tenant_quota WHERE tenant_id = $1`, tenantID).
		Scan(&q.MaxUsers, &q.MaxStorageBytes, &q.MaxTranscodeSeconds,
			&q.MaxAPICallsDay, &q.OnExceed)
	if errors.Is(err, pgx.ErrNoRows) {
		return Quota{OnExceed: OnExceedReject}, nil
	}
	if q.OnExceed == "" {
		q.OnExceed = OnExceedReject
	}
	return q, err
}

// SelfUsage 在租户上下文里读取自己的用量快照。
func SelfUsage(ctx context.Context, tx pgx.Tx, tenantID string) (storage int64, users int, err error) {
	err = tx.QueryRow(ctx,
		`SELECT storage_bytes, active_users FROM tenant_usage WHERE tenant_id = $1`, tenantID).
		Scan(&storage, &users)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, 0, nil
	}
	return storage, users, err
}

func scanTenants(rows pgx.Rows) ([]Tenant, error) {
	var out []Tenant
	for rows.Next() {
		var t Tenant
		if err := rows.Scan(&t.Slug, &t.Name, &t.Status, &t.Plan, &t.CreatedAt,
			&t.TrialEndsAt, &t.SuspendedAt, &t.RetentionUntil, &t.ContactEmail,
			&t.Users, &t.StorageBytes, &t.Files, &t.Edition, &t.EditionExpiresAt); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// normalizeEditionInput 校验开通时指定的档位与到期日。
//
// 这里**不**用 edition.Normalize：那个函数会把未知值静默收敛为基础版，
// 适合读取库里的脏数据，不适合校验用户输入——运营把 professional 打成
// "pro" 应该看到报错，而不是"开通成功了但客户是基础版"。
func normalizeEditionInput(rawEdition, rawExpires string) (string, *time.Time, error) {
	ed := strings.ToLower(strings.TrimSpace(rawEdition))
	if ed == "" {
		ed = string(edition.Basic) // 与列默认值一致，不制造第三种默认
	}
	switch edition.Edition(ed) {
	case edition.Basic, edition.Professional, edition.Business:
	default:
		return "", nil, fmt.Errorf("%w: 档位必须是 basic / professional / business", ErrInvalidInput)
	}

	s := strings.TrimSpace(rawExpires)
	if s == "" {
		return ed, nil, nil
	}
	// 日期形式按当地时区的当日 23:59:59 解释。
	// 若按零点解释，运营填 2027-12-31 实际会在 12-30 夜里失效，差一天且很难解释。
	if t, err := time.ParseInLocation("2006-01-02", s, time.Local); err == nil {
		end := t.AddDate(0, 0, 1).Add(-time.Second)
		return ed, &end, nil
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return ed, &t, nil
	}
	return "", nil, fmt.Errorf("%w: 到期日格式需为 YYYY-MM-DD 或 RFC3339", ErrInvalidInput)
}

// isDup 判断唯一约束冲突。
func isDup(err error) bool { return isCode(err, "23505") }

// isCode 判断 SQLSTATE。自定义码（DVxxx）用于把业务错误从 SQL 提到 HTTP。
func isCode(err error, code string) bool {
	var pe *pgconn.PgError
	return errors.As(err, &pe) && pe.Code == code
}
