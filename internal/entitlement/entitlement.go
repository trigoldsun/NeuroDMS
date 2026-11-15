// Package entitlement 解算"某租户此刻有没有某项能力"。
//
// 为什么要有这一层（docs/47 §4.1）：在此之前，能力只有两个来源——
// 档位常量（edition.Spec）和灰度开关（feature）。于是"基础版客户单买了
// 自定义域名"只能靠整档升级实现，连带把 AD、邮件、短信一起送出去。
//
// 求值链固定为：
//
//	entitled = !locked && (override 有效 ? override : 档位默认)
//
// 三条不可违反的规矩：
//  1. 任一层读不到 → 当作没有（fail-closed）。这里刻意不提供"读失败就用默认值"
//     的便捷方法：授权读不到却按开通处理，等于把付费能力白送。
//  2. 平台强制关不受授权影响。合规下线不需要"先给客户降档"。
//  3. 过期覆盖按"没有覆盖"处理，但保留原因（grant_expired），
//     否则界面只能说"没有"，客服无法解释"合同里明明买了"。
//
// 数值型配额（版本保留数、上传上限、席位、容量）**不**在这里：
// 上限由 edition.Spec 给、单租户覆盖由 tenant_quota 给，再搬一份进来
// 就会有三处事实，而配额触发器和计量已经在读前两处了。
package entitlement

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"docvault/internal/db"
	"docvault/internal/edition"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// 能力编码。与 0052 的种子、前端 capabilities 的键保持一致。
const (
	ShareExternal    = "share.external"
	Classification   = "classification"
	DirAuth          = "dir.auth"
	MailOutbound     = "mail.outbound"
	UploadFolder     = "upload.folder"
	SMSLogin         = "sms.login"
	ShareEmailVerify = "share.email_verify"
	CollabExternal   = "collab.external"
	CustomDomain     = "branding.custom_domain"
	SSO              = "sso"
	AuditExport      = "audit.export"
	Watermark        = "watermark"
	EditOnline       = "edit.online"
	MediaTranscode   = "media.transcode"
)

// 来源。界面据此给出不同的文案，客服据此回答"为什么没有"。
const (
	SourcePlan    = "plan"    // 档位默认
	SourceGrant   = "grant"   // 租户特批（单项加购/试用）
	SourceLocked  = "locked"  // 平台强制关
	SourceExpired = "expired" // 特批已过期，回落档位默认
)

var (
	// ErrNotFound 租户或能力不存在。
	ErrNotFound = errors.New("租户不存在")
	// ErrUnknownCode 能力编码拼错（防"拼错当成没有"）。
	ErrUnknownCode = errors.New("未知能力编码")
	// ErrInvalidState 状态只能是 inherit / on / off。
	ErrInvalidState = errors.New("授权状态只能是 inherit / on / off")
)

// Def 是一条能力定义。
type Def struct {
	Code             string   `json:"code"`
	Name             string   `json:"name"`
	Description      string   `json:"description"`
	BasicDefault     bool     `json:"basicDefault"`
	ProDefault       bool     `json:"proDefault"`
	FlagshipDefault  bool     `json:"flagshipDefault"`
	TenantSettable   bool     `json:"tenantSettable"`
	PlatformLockable bool     `json:"platformLockable"`
	Metered          bool     `json:"metered"`
	Requires         []string `json:"requires"`
	Sort             int      `json:"sort"`
}

// Value 是单条能力的授权结论（不含租户自管与资源就绪——
// 那两层由调用方叠加，见 httpapi 的 capabilities）。
type Value struct {
	Code     string `json:"code"`
	Entitled bool   `json:"entitled"`
	// PlanDefault 是档位默认值，用于界面区分"档位就有"与"额外买的"。
	PlanDefault bool   `json:"planDefault"`
	Source      string `json:"source"`
	// Reason 是特批或强制关的原因，可直接展示给运营/客服。
	Reason    string     `json:"reason"`
	ExpiresAt *time.Time `json:"expiresAt,omitempty"`
}

// Item 是平台侧的一行（定义 + 覆盖 + 锁）。
type Item struct {
	Def
	State      string     `json:"state"` // ""(跟随档位) / on / off
	Reason     string     `json:"reason"`
	ExpiresAt  *time.Time `json:"expiresAt,omitempty"`
	UpdatedBy  string     `json:"updatedBy"`
	Locked     bool       `json:"locked"`
	LockReason string     `json:"lockReason"`
	// Expired 表示这条覆盖已过期（按"没有覆盖"处理）。
	// 不标出来，运营台会把一条过期特批显示成"已开通"。
	Expired bool `json:"expired"`
}

// Change 是一次授权变更的前后值，供 auditDiff 记录。
type Change struct {
	PrevState   string     `json:"prevState"`
	PrevReason  string     `json:"prevReason"`
	PrevExpires *time.Time `json:"prevExpires,omitempty"`
	CurState    string     `json:"curState"`
	CurReason   string     `json:"curReason"`
	CurExpires  *time.Time `json:"curExpires,omitempty"`
}

// Service 提供求值与平台侧读写。
type Service struct {
	pool *pgxpool.Pool
	now  func() time.Time
}

// New 构造服务。
func New(pool *pgxpool.Pool) *Service {
	return &Service{pool: pool, now: time.Now}
}

// SetNow 供测试注入时钟（特批过期是时间相关逻辑，必须可测）。
func (s *Service) SetNow(fn func() time.Time) {
	if fn != nil {
		s.now = fn
	}
}

// Resolve 解算某租户全部能力的授权结论。
//
// ed 必须是**生效**档位（edition.Resolve 的结果），不能是库里声明的值：
// 到期后仍按原档位算，等于宽限期永久有效。
func (s *Service) Resolve(ctx context.Context, tenantID string, ed edition.Edition) (map[string]Value, error) {
	if tenantID == "" {
		return nil, errors.New("租户上下文为空")
	}
	type row struct {
		code                 string
		basic, pro, flagship bool
		state, reason        string
		expires              *time.Time
		locked               bool
		lockReason           string
	}
	rows := make([]row, 0, 16)
	err := db.WithTenant(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		r, e := tx.Query(ctx, `
			SELECT d.code, d.basic_default, d.pro_default, d.flagship_default,
			       COALESCE(en.state, ''), COALESCE(en.reason, ''), en.expires_at,
			       COALESCE(l.locked, false), COALESCE(l.reason, '')
			  FROM entitlement_def d
			  LEFT JOIN tenant_entitlement en ON en.code = d.code AND en.tenant_id = $1
			  LEFT JOIN entitlement_lock    l  ON l.code = d.code
			 ORDER BY d.sort_order, d.code`, tenantID)
		if e != nil {
			return e
		}
		defer r.Close()
		for r.Next() {
			var x row
			if e := r.Scan(&x.code, &x.basic, &x.pro, &x.flagship,
				&x.state, &x.reason, &x.expires, &x.locked, &x.lockReason); e != nil {
				return e
			}
			rows = append(rows, x)
		}
		return r.Err()
	})
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		// 种子没跑或者表被清空：不能返回空 map 让调用方"什么都没有"却不知道为什么。
		return nil, fmt.Errorf("能力定义缺失（entitlement_def 为空），迁移 0052 是否执行？")
	}

	now := s.now()
	out := make(map[string]Value, len(rows))
	for _, x := range rows {
		v := Value{Code: x.code, PlanDefault: planFor(x.basic, x.pro, x.flagship, ed)}
		v.Entitled = v.PlanDefault
		v.Source = SourcePlan

		// 特批：有行且未过期才生效。过期行回落档位，但原因要能解释。
		if x.state == "on" || x.state == "off" {
			if x.expires != nil && !now.Before(*x.expires) {
				v.Source = SourceExpired
				v.Reason = "授权已到期，已回落为档位默认"
				v.ExpiresAt = x.expires
			} else {
				v.Entitled = x.state == "on"
				v.Source = SourceGrant
				v.Reason = x.reason
				v.ExpiresAt = x.expires
			}
		}
		// 强制关：永远最后覆盖，且不需要"先降档"。
		if x.locked {
			v.Entitled = false
			v.Source = SourceLocked
			v.Reason = x.lockReason
		}
		out[x.code] = v
	}
	return out, nil
}

// Entitled 是单条判定。读失败返回 (false, err)——调用方必须显式处理错误，
// 不要写成 `ok, _ :=`：那等于把"读不到"当成"没有"却又继续走后面的写入。
func (s *Service) Entitled(ctx context.Context, tenantID, code string, ed edition.Edition) (bool, error) {
	all, err := s.Resolve(ctx, tenantID, ed)
	if err != nil {
		return false, err
	}
	v, ok := all[code]
	if !ok {
		return false, fmt.Errorf("%w: %s", ErrUnknownCode, code)
	}
	return v.Entitled, nil
}

func planFor(basic, pro, flagship bool, ed edition.Edition) bool {
	switch ed {
	case edition.Professional:
		return pro
	case edition.Business:
		return flagship
	default:
		return basic
	}
}

// 表示"跟随档位"的唯一取值。GET 与 PUT 都用它。
const StateInherit = "inherit"

// NormalizeState 归一化三态取值，并兼容历史别名。
//
// `default` 曾经是文档里用过的说法，有些对接方会照着传；
// 与其回 400 让它去猜，不如直接认下来——**同一个语义多认一个词，成本远低于一次联调**。
// 认不出来的值原样返回，由数据库函数报错（避免这里悄悄改成别的东西）。
func NormalizeState(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case StateInherit, "default":
		return StateInherit
	default:
		// 空串与未知值原样返回，由上层报 400。
		// **不能**把空串当 inherit：那会让"漏传 state 的请求"静默撤销已有授权。
		return strings.ToLower(strings.TrimSpace(s))
	}
}

// ---------------- 平台侧 ----------------

// Defs 返回全部能力定义（全局只读表）。
func (s *Service) Defs(ctx context.Context) ([]Def, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT code, name, description, basic_default, pro_default, flagship_default,
		       tenant_settable, platform_lockable, metered, requires, sort_order
		  FROM entitlement_def
		 ORDER BY sort_order, code`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Def
	for rows.Next() {
		var d Def
		if err := rows.Scan(&d.Code, &d.Name, &d.Description,
			&d.BasicDefault, &d.ProDefault, &d.FlagshipDefault,
			&d.TenantSettable, &d.PlatformLockable, &d.Metered,
			&d.Requires, &d.Sort); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// List 返回某租户的能力全貌（平台运营台用）。
//
// 走 SECURITY DEFINER 函数而不是直接查表：平台接口要读的是**别的租户**的行，
// 应用连接受 RLS 约束只能看自己，与 platform_tenant_edition 同一模式。
func (s *Service) List(ctx context.Context, slug string) ([]Item, error) {
	// state 用 "inherit" 表示"没有覆盖行、跟随档位"。
	// 早先返回空串，而 PUT 只认 "inherit"——对接方（含我们自己的验收脚本）
	// 必然要试错一次。同一个语义只留一个词，读写两侧一致。
	rows, err := s.pool.Query(ctx,
		`SELECT code, name, description, basic_default, pro_default, flagship_default,
		        tenant_settable, platform_lockable, metered, requires, sort_order,
		        COALESCE(NULLIF(state, ''), 'inherit'), COALESCE(reason, ''), expires_at,
		        COALESCE(updated_by, ''), locked, COALESCE(lock_reason, '')
		   FROM platform_tenant_entitlements($1)`,
		strings.ToLower(strings.TrimSpace(slug)))
	if err != nil {
		if isCode(err, "DV404") {
			return nil, ErrNotFound
		}
		return nil, err
	}
	defer rows.Close()

	var out []Item
	for rows.Next() {
		var it Item
		if err := rows.Scan(&it.Code, &it.Name, &it.Description,
			&it.BasicDefault, &it.ProDefault, &it.FlagshipDefault,
			&it.TenantSettable, &it.PlatformLockable, &it.Metered,
			&it.Requires, &it.Sort,
			&it.State, &it.Reason, &it.ExpiresAt, &it.UpdatedBy,
			&it.Locked, &it.LockReason); err != nil {
			return nil, err
		}
		if it.ExpiresAt != nil && !s.now().Before(*it.ExpiresAt) {
			it.Expired = true
		}
		out = append(out, it)
	}
	return out, rows.Err()
}

// Set 设置单租户单项授权。
//
// state=inherit 表示删行回到档位默认——这是三态里最容易被漏掉的一态，
// 没有它就"改过一次之后再也回不到默认"，客户升级也拿不到新能力。
func (s *Service) Set(ctx context.Context, slug, code, state, reason string, expires *time.Time, operator string) (Change, error) {
	var ch Change
	err := s.pool.QueryRow(ctx, `
		SELECT prev_state, prev_reason, prev_expires, cur_state, cur_reason, cur_expires
		  FROM platform_tenant_set_entitlement($1, $2, $3, $4, $5, $6)`,
		strings.ToLower(strings.TrimSpace(slug)), strings.TrimSpace(code),
		NormalizeState(state), strings.TrimSpace(reason), expires, operator).
		Scan(&ch.PrevState, &ch.PrevReason, &ch.PrevExpires,
			&ch.CurState, &ch.CurReason, &ch.CurExpires)
	if err != nil {
		switch {
		case isCode(err, "DV404"):
			return Change{}, ErrNotFound
		case isCode(err, "DV003"):
			return Change{}, ErrUnknownCode
		case isCode(err, "DV002"):
			return Change{}, ErrInvalidState
		default:
			return Change{}, err
		}
	}
	return ch, nil
}

// Lock 全局强制关/解（合规下线、故障止血）。
func (s *Service) Lock(ctx context.Context, code string, locked bool, reason string) (prev, cur bool, err error) {
	err = s.pool.QueryRow(ctx,
		`SELECT prev_locked, cur_locked FROM platform_entitlement_lock($1, $2, $3)`,
		strings.TrimSpace(code), locked, strings.TrimSpace(reason)).Scan(&prev, &cur)
	if err != nil {
		if isCode(err, "DV003") {
			return false, false, ErrUnknownCode
		}
		return false, false, err
	}
	return prev, cur, nil
}

// isCode 判断 PG 错误码（迁移里用 RAISE ... USING ERRCODE = 'DVxxx'）。
func isCode(err error, code string) bool {
	var pe *pgconn.PgError
	return errors.As(err, &pe) && pe.Code == code
}
