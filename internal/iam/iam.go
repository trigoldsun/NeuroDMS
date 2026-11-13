// Package iam 负责租户内的成员（账号）管理与角色授予。
//
// 为什么单独成包而不是直接写在 handler 里：
// 这一块的规则都是**拒绝类**规则——不能改自己的角色、不能把最后一个管理员停掉、
// 不能给别人超过自己的密级与封顶、不能把审计角色和管理角色叠在同一个人身上。
// 这类规则最容易在新增一个入口时被忘掉，所以必须集中一处、并被单独测试。
//
// 边界：
//   - 平台运营账号不在这里（见 platformauth）：它们不属于任何租户。
//   - 认证细节不在这里（见 auth）：本包只管"账号长什么样、谁能管它"。
//   - 会话吊销由 auth 负责，但**必须**在状态变更后调用，否则会出现
//     "已停用但人还在用"（见 SetStatus 的注释）。
package iam

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"docvault/internal/auth"
	"docvault/internal/db"
	"docvault/internal/rbac"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// 业务错误：HTTP 层据此映射状态码，不靠字符串匹配。
var (
	ErrNotFound     = errors.New("成员不存在")
	ErrForbidden    = errors.New("无权执行该操作")
	ErrInvalidInput = errors.New("参数不合法")
	ErrDuplicate    = errors.New("用户名或邮箱已被占用")
	ErrLastAdmin    = rbac.ErrLastAdmin
	ErrSeparation   = rbac.ErrRoleConflict
	ErrUnknownRole  = rbac.ErrUnknownRole
	ErrSelfTarget   = errors.New("不能对自己执行该操作")
	ErrEscalation   = errors.New("不能授予高于自己的密级或封顶")
)

// 账号主体类型。external 是外部协作账号（独立账号池，同一权限引擎）。
const (
	TypeInternal = "internal"
	TypeExternal = "external"
)

// 状态。与 app_user.status 的 CHECK 约束一致。
const (
	StatusInvited   = "invited"
	StatusActive    = "active"
	StatusSuspended = "suspended"
	StatusDeleted   = "deleted"
)

const (
	minPasswordLen = 12
	maxUsernameLen = 64
	maxDisplayLen  = 64
)

// Member 是成员的对外视图（不含任何口令材料）。
type Member struct {
	ID             string     `json:"id"`
	Username       string     `json:"username"`
	Email          string     `json:"email"`
	DisplayName    string     `json:"displayName"`
	PrincipalType  string     `json:"principalType"`
	Source         string     `json:"source"`
	Status         string     `json:"status"`
	DeptID         string     `json:"deptId"`
	DeptName       string     `json:"deptName"`
	Classification int        `json:"classification"`
	Ceiling        int        `json:"ceiling"`
	MFARequired    bool       `json:"mfaRequired"`
	ExpiresAt      *time.Time `json:"expiresAt"`
	LastLoginAt    *time.Time `json:"lastLoginAt"`
	CreatedAt      time.Time  `json:"createdAt"`
	Roles          []string   `json:"roles"`
	// CanLogin 由状态与到期时间推出，供界面直接判断，
	// 避免前端把"到期判定"再实现一遍（两处实现必然不一致）。
	CanLogin bool `json:"canLogin"`
}

// Actor 是执行操作的人。所有越权规则都基于它判定。
type Actor struct {
	ID             string
	Roles          []string
	Ceiling        int
	Classification int
}

// IsSysAdmin 判断是否系统管理员。
func (a Actor) IsSysAdmin() bool { return contains(a.Roles, rbac.SysAdmin) }

// ListFilter 是成员列表的筛选条件。
type ListFilter struct {
	Query  string
	Status string
	Role   string
	Type   string
	Limit  int
	Offset int
}

// Service 是成员管理入口。
type Service struct {
	pool *pgxpool.Pool
}

// New 构造服务。
func New(pool *pgxpool.Pool) *Service { return &Service{pool: pool} }

// List 返回成员列表与总数。
func (s *Service) List(ctx context.Context, tenantID string, f ListFilter) ([]Member, int, error) {
	if f.Limit <= 0 || f.Limit > 200 {
		f.Limit = 50
	}
	if f.Offset < 0 {
		f.Offset = 0
	}
	pattern := likePattern(f.Query)

	var (
		items []Member
		total int
	)
	err := db.WithTenant(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		const where = `
			u.deleted_at IS NULL AND u.status <> 'deleted'
			AND ($1 = '' OR u.username ILIKE $1 OR u.display_name ILIKE $1 OR COALESCE(u.email,'') ILIKE $1)
			AND ($2 = '' OR u.status = $2)
			AND ($3 = '' OR u.principal_type = $3)
			AND ($4 = '' OR EXISTS (
			      SELECT 1 FROM user_role ur JOIN role r ON r.id = ur.role_id
			       WHERE ur.user_id = u.id AND r.is_system AND r.deleted_at IS NULL AND r.code = $4))`

		if e := tx.QueryRow(ctx,
			`SELECT count(*) FROM app_user u WHERE `+where,
			pattern, f.Status, f.Type, f.Role).Scan(&total); e != nil {
			return e
		}

		rows, e := tx.Query(ctx, `
			SELECT u.id::text, u.username, COALESCE(u.email,''), u.display_name,
			       u.principal_type, u.source, u.status, u.classification, u.ceiling,
			       u.mfa_required, u.expires_at, u.last_login_at, u.created_at,
			       COALESCE(u.dept_id::text,''), COALESCE(d.name,''),
			       COALESCE((SELECT array_agg(r.code ORDER BY r.code)
			                   FROM user_role ur JOIN role r ON r.id = ur.role_id
			                  WHERE ur.user_id = u.id AND r.is_system AND r.deleted_at IS NULL), '{}')
			  FROM app_user u
			  LEFT JOIN dept d ON d.id = u.dept_id AND d.deleted_at IS NULL
			 WHERE `+where+`
			 ORDER BY u.status = 'active' DESC, lower(u.username)
			 LIMIT $5 OFFSET $6`,
			pattern, f.Status, f.Type, f.Role, f.Limit, f.Offset)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			m, e := scanMember(rows)
			if e != nil {
				return e
			}
			items = append(items, m)
		}
		return rows.Err()
	})
	if items == nil {
		items = []Member{}
	}
	return items, total, err
}

// Get 返回单个成员。
func (s *Service) Get(ctx context.Context, tenantID, userID string) (Member, error) {
	var m Member
	err := db.WithTenant(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		var e error
		m, e = getMember(ctx, tx, userID)
		return e
	})
	return m, err
}

// CreateInput 是创建成员的输入。
type CreateInput struct {
	Username       string     `json:"username"`
	DisplayName    string     `json:"displayName"`
	Email          string     `json:"email"`
	Password       string     `json:"password"`
	Role           string     `json:"role"`
	DeptID         string     `json:"deptId"`
	PrincipalType  string     `json:"principalType"`
	MFARequired    bool       `json:"mfaRequired"`
	Classification *int       `json:"classification"`
	Ceiling        *int       `json:"ceiling"`
	ExpiresAt      *time.Time `json:"expiresAt"`
}

// Create 创建成员。
//
// 三条不可省的校验：
//  1. 只能由系统管理员创建（handler 已拦，这里再断一次——服务可被 CLI/任务复用）；
//  2. 不能创建比自己密级/封顶更高的账号（否则等于给自己造一个更高级的替身）；
//  3. 授予的角色必须存在，且不得违反三权分立（由 rbac.Grant 判定）。
func (s *Service) Create(ctx context.Context, tenantID, actorID string, in CreateInput) (Member, error) {
	in.Username = strings.TrimSpace(in.Username)
	in.DisplayName = strings.TrimSpace(in.DisplayName)
	in.Email = strings.TrimSpace(in.Email)
	in.PrincipalType = strings.TrimSpace(in.PrincipalType)
	if in.PrincipalType == "" {
		in.PrincipalType = TypeInternal
	}

	if in.Username == "" || len(in.Username) > maxUsernameLen {
		return Member{}, fmt.Errorf("%w: 用户名需为 1-%d 字符", ErrInvalidInput, maxUsernameLen)
	}
	if strings.ContainsAny(in.Username, " \t\r\n/@") {
		return Member{}, fmt.Errorf("%w: 用户名不能包含空格或 /@", ErrInvalidInput)
	}
	if len([]rune(in.Password)) < minPasswordLen {
		return Member{}, fmt.Errorf("%w: 初始口令至少 %d 位", ErrInvalidInput, minPasswordLen)
	}
	if in.DisplayName == "" {
		in.DisplayName = in.Username
	}
	if len([]rune(in.DisplayName)) > maxDisplayLen {
		return Member{}, fmt.Errorf("%w: 显示名最多 %d 字", ErrInvalidInput, maxDisplayLen)
	}
	switch in.PrincipalType {
	case TypeInternal, TypeExternal:
	default:
		return Member{}, fmt.Errorf("%w: principalType 仅支持 internal/external", ErrInvalidInput)
	}
	if in.Role != "" && !rbac.Known(in.Role) {
		return Member{}, fmt.Errorf("%w: 未知角色 %s", ErrUnknownRole, in.Role)
	}

	hash, err := auth.HashPassword(in.Password)
	if err != nil {
		return Member{}, err
	}

	var out Member
	err = db.WithTenant(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		actor, e := actorOf(ctx, tx, actorID)
		if e != nil {
			return e
		}
		if !actor.IsSysAdmin() {
			return ErrForbidden
		}

		class := 0
		if in.Classification != nil {
			class = *in.Classification
		}
		// 与表默认（0008 起为 6）保持一致。
		//
		// 之前这里写 4、表默认 6，导致"接口创建的成员"与"目录同步进来的成员"
		// 拿到不同的封顶，同一职位的人能不能授出 owner 取决于入职方式——
		// 安全控制一旦不可预期，管理员就无法推理。
		// 真正的门是"必须先对对象有 manage_acl"（只有 owner 有），
		// ceiling 是第二道，需要收紧时由管理员显式设置。
		ceiling := 6
		if in.Ceiling != nil {
			ceiling = *in.Ceiling
		}
		if class < 0 || class > 6 || ceiling < 0 || ceiling > 6 {
			return fmt.Errorf("%w: 密级与封顶需在 0-6 之间", ErrInvalidInput)
		}
		if class > actor.Classification || ceiling > actor.Ceiling {
			return fmt.Errorf("%w（操作者 密级=%d 封顶=%d）", ErrEscalation, actor.Classification, actor.Ceiling)
		}

		// 部门必须属于本租户：跨租户部门 id 在 RLS 下查不到，这里显式确认而非静默置空
		if in.DeptID != "" {
			var n int
			if e := tx.QueryRow(ctx,
				`SELECT count(*) FROM dept WHERE id = $1 AND tenant_id = $2 AND deleted_at IS NULL`,
				in.DeptID, tenantID).Scan(&n); e != nil {
				return e
			}
			if n == 0 {
				return fmt.Errorf("%w: 部门不存在", ErrInvalidInput)
			}
		}

		var id string
		if e := tx.QueryRow(ctx, `
			INSERT INTO app_user (id, tenant_id, principal_type, source, username, email,
			                      display_name, password_hash, dept_id, classification, ceiling,
			                      mfa_required, status, expires_at)
			VALUES (gen_random_uuid(), $1, $2, 'local', $3, nullif($4,''), $5, $6,
			        nullif($7,'')::uuid, $8, $9, $10, 'active', $11)
			RETURNING id::text`,
			tenantID, in.PrincipalType, in.Username, in.Email, in.DisplayName, hash,
			in.DeptID, class, ceiling, in.MFARequired || in.PrincipalType == TypeExternal,
			in.ExpiresAt).Scan(&id); e != nil {
			if isDup(e) {
				return ErrDuplicate
			}
			return e
		}

		if in.Role != "" {
			if e := rbac.Grant(ctx, tx, tenantID, id, in.Role, actorID); e != nil {
				// 授予失败必须整体回滚：否则留下"建了人但没有角色"的半成品
				return e
			}
		}
		out, e = getMember(ctx, tx, id)
		return e
	})
	return out, err
}

// UpdateInput 是可改字段。用指针区分"没传"与"传了空值"。
type UpdateInput struct {
	DisplayName *string    `json:"displayName"`
	Email       *string    `json:"email"`
	DeptID      *string    `json:"deptId"`
	MFARequired *bool      `json:"mfaRequired"`
	ExpiresAt   *time.Time `json:"expiresAt"`
	// ClearExpiry 与 ExpiresAt 配合表达"永不过期"
	ClearExpiry    bool `json:"clearExpiry"`
	Classification *int `json:"classification"`
	Ceiling        *int `json:"ceiling"`
}

// Update 修改成员资料（不含角色与状态，那两件事各有专用入口）。
func (s *Service) Update(ctx context.Context, tenantID, actorID, userID string, in UpdateInput) (Member, error) {
	var out Member
	err := db.WithTenant(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		actor, e := actorOf(ctx, tx, actorID)
		if e != nil {
			return e
		}
		if !actor.IsSysAdmin() {
			return ErrForbidden
		}
		target, e := getMember(ctx, tx, userID)
		if e != nil {
			return e
		}

		// 提权护栏：不能把自己的密级/封顶改高，也不能把别人改成比自己高。
		// 只比"改完之后的结果"与操作者自身的上限——比"改之前"没有意义。
		newClass, newCeil := target.Classification, target.Ceiling
		if in.Classification != nil {
			newClass = *in.Classification
		}
		if in.Ceiling != nil {
			newCeil = *in.Ceiling
		}
		if newClass < 0 || newClass > 6 || newCeil < 0 || newCeil > 6 {
			return fmt.Errorf("%w: 密级与封顶需在 0-6 之间", ErrInvalidInput)
		}
		if newClass > actor.Classification || newCeil > actor.Ceiling {
			return fmt.Errorf("%w（操作者 密级=%d 封顶=%d）", ErrEscalation, actor.Classification, actor.Ceiling)
		}

		if in.DisplayName != nil {
			d := strings.TrimSpace(*in.DisplayName)
			if d == "" || len([]rune(d)) > maxDisplayLen {
				return fmt.Errorf("%w: 显示名需为 1-%d 字", ErrInvalidInput, maxDisplayLen)
			}
			if _, e := tx.Exec(ctx,
				`UPDATE app_user SET display_name = $2, updated_at = now() WHERE id = $1`, userID, d); e != nil {
				return e
			}
		}
		if in.Email != nil {
			mail := strings.TrimSpace(*in.Email)
			if _, e := tx.Exec(ctx,
				`UPDATE app_user SET email = nullif($2,''), updated_at = now() WHERE id = $1`, userID, mail); e != nil {
				if isDup(e) {
					return ErrDuplicate
				}
				return e
			}
		}
		if in.DeptID != nil {
			dept := strings.TrimSpace(*in.DeptID)
			if dept != "" {
				var n int
				if e := tx.QueryRow(ctx,
					`SELECT count(*) FROM dept WHERE id = $1 AND tenant_id = $2 AND deleted_at IS NULL`,
					dept, tenantID).Scan(&n); e != nil {
					return e
				}
				if n == 0 {
					return fmt.Errorf("%w: 部门不存在", ErrInvalidInput)
				}
			}
			if _, e := tx.Exec(ctx,
				`UPDATE app_user SET dept_id = nullif($2,'')::uuid, updated_at = now() WHERE id = $1`,
				userID, dept); e != nil {
				return e
			}
		}
		if in.MFARequired != nil {
			if _, e := tx.Exec(ctx,
				`UPDATE app_user SET mfa_required = $2, updated_at = now() WHERE id = $1`,
				userID, *in.MFARequired); e != nil {
				return e
			}
		}
		if in.ClearExpiry {
			if _, e := tx.Exec(ctx,
				`UPDATE app_user SET expires_at = NULL, updated_at = now() WHERE id = $1`, userID); e != nil {
				return e
			}
		} else if in.ExpiresAt != nil {
			if _, e := tx.Exec(ctx,
				`UPDATE app_user SET expires_at = $2, updated_at = now() WHERE id = $1`,
				userID, *in.ExpiresAt); e != nil {
				return e
			}
		}
		if in.Classification != nil {
			if _, e := tx.Exec(ctx,
				`UPDATE app_user SET classification = $2, updated_at = now() WHERE id = $1`,
				userID, *in.Classification); e != nil {
				return e
			}
		}
		if in.Ceiling != nil {
			if _, e := tx.Exec(ctx,
				`UPDATE app_user SET ceiling = $2, updated_at = now() WHERE id = $1`,
				userID, *in.Ceiling); e != nil {
				return e
			}
		}

		out, e = getMember(ctx, tx, userID)
		return e
	})
	return out, err
}

// SetStatus 启用/停用成员。
//
// 停用必须**同时**吊销会话：只改 status 而不动 session_epoch，
// 已签发的访问令牌还能用到过期（最长 15 分钟），表现就是"停用了但人还在用"。
// 这里与管理员保护在**同一事务**里完成，避免两个并发请求各自看到"还有两个管理员"。
func (s *Service) SetStatus(ctx context.Context, tenantID, actorID, userID, status string) (Member, error) {
	switch status {
	case StatusActive, StatusSuspended:
	default:
		return Member{}, fmt.Errorf("%w: 状态仅支持 active/suspended（删除请用删除接口）", ErrInvalidInput)
	}
	if actorID == userID {
		return Member{}, fmt.Errorf("%w: 不能停用/启用自己", ErrSelfTarget)
	}

	var out Member
	err := db.WithTenant(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		actor, e := actorOf(ctx, tx, actorID)
		if e != nil {
			return e
		}
		if !actor.IsSysAdmin() {
			return ErrForbidden
		}
		if _, e := getMember(ctx, tx, userID); e != nil {
			return e
		}
		if status != StatusActive {
			if e := ensureNotLastAdmin(ctx, tx, tenantID, userID); e != nil {
				return e
			}
			// 停用前必须交代名下空间：停用后他进不来，空间就没人管了。
			// 这里在 UPDATE 之前、且已对空间行加锁，避免"检查完又新建一个空间"。
			spaces, e := ownedSpacesTx(ctx, tx, tenantID, userID)
			if e != nil {
				return e
			}
			if len(spaces) > 0 {
				return &OwnsSpacesError{Spaces: spaces}
			}
		}
		if _, e := tx.Exec(ctx, `
			UPDATE app_user SET status = $2, session_epoch = session_epoch + 1, updated_at = now()
			 WHERE id = $1`, userID, status); e != nil {
			return e
		}
		if status != StatusActive {
			if _, e := tx.Exec(ctx,
				`UPDATE session SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL`,
				userID); e != nil {
				return e
			}
		}
		out, e = getMember(ctx, tx, userID)
		return e
	})
	return out, err
}

// ResetPassword 由管理员重置口令（用户忘记口令时的唯一自救路径之外的手段）。
//
// 重置会吊销该用户全部会话：否则"口令泄露后改了口令"依然拦不住已经在用的人。
func (s *Service) ResetPassword(ctx context.Context, tenantID, actorID, userID, newPassword string) error {
	if len([]rune(newPassword)) < minPasswordLen {
		return fmt.Errorf("%w: 新口令至少 %d 位", ErrInvalidInput, minPasswordLen)
	}
	hash, err := auth.HashPassword(newPassword)
	if err != nil {
		return err
	}
	return db.WithTenant(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		actor, e := actorOf(ctx, tx, actorID)
		if e != nil {
			return e
		}
		if !actor.IsSysAdmin() {
			return ErrForbidden
		}
		if _, e := getMember(ctx, tx, userID); e != nil {
			return e
		}
		if _, e := tx.Exec(ctx, `
			UPDATE app_user
			   SET password_hash = $2, session_epoch = session_epoch + 1, updated_at = now()
			 WHERE id = $1`, userID, hash); e != nil {
			return e
		}
		_, e = tx.Exec(ctx,
			`UPDATE session SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL`, userID)
		return e
	})
}

// Delete 逻辑删除成员（保留审计与追溯）。最后一个系统管理员不可删。
func (s *Service) Delete(ctx context.Context, tenantID, actorID, userID string) error {
	if actorID == userID {
		return fmt.Errorf("%w: 不能删除自己（请由另一名管理员操作）", ErrSelfTarget)
	}
	return db.WithTenant(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		actor, e := actorOf(ctx, tx, actorID)
		if e != nil {
			return e
		}
		if !actor.IsSysAdmin() {
			return ErrForbidden
		}
		if _, e := getMember(ctx, tx, userID); e != nil {
			return e
		}
		if e := ensureNotLastAdmin(ctx, tx, tenantID, userID); e != nil {
			return e
		}
		// 删除比停用更彻底：没有继任者参数，直接删会把空间变成孤儿。
		// 与停用共用同一套检查与同一把锁（space 行），两条路径语义一致。
		spaces, e := ownedSpacesTx(ctx, tx, tenantID, userID)
		if e != nil {
			return e
		}
		if len(spaces) > 0 {
			return &OwnsSpacesError{Spaces: spaces}
		}
		// 名下已无空间，但可能还挂着别人空间里的文件归属。
		// 把归属交给所在空间的所有者，避免列表里出现"已删除用户"。
		if _, e := tx.Exec(ctx, `
			UPDATE node n SET owner_id = s.owner_id
			  FROM space s
			 WHERE n.tenant_id = $1 AND n.space_id = s.id AND n.owner_id = $2`,
			tenantID, userID); e != nil {
			return e
		}
		if _, e := tx.Exec(ctx, `
			UPDATE app_user
			   SET status = 'deleted', deleted_at = now(),
			       session_epoch = session_epoch + 1, updated_at = now()
			 WHERE id = $1`, userID); e != nil {
			return e
		}
		_, e = tx.Exec(ctx,
			`UPDATE session SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL`, userID)
		return e
	})
}

// GrantRole 授予角色。三权分立冲突由 rbac 判定（返回 ErrSeparation）。
func (s *Service) GrantRole(ctx context.Context, tenantID, actorID, userID, code string) ([]string, error) {
	var roles []string
	err := db.WithTenant(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		actor, e := actorOf(ctx, tx, actorID)
		if e != nil {
			return e
		}
		if !actor.IsSysAdmin() {
			return ErrForbidden
		}
		if _, e := getMember(ctx, tx, userID); e != nil {
			return e
		}
		// 顺序是刻意的：先让 rbac 判"角色组合是否合法"，再判"是不是给自己授"。
		//
		// 如果先判自己，那么"系统管理员给自己加审计角色"会得到一个笼统的
		// SELF_OPERATION，掩盖真正的原因（三权分立冲突）——而后者才是合规上
		// 需要被记录与解释的那条。自授判定返回错误会让事务整体回滚，授权不会生效。
		if e := rbac.Grant(ctx, tx, tenantID, userID, code, actorID); e != nil {
			return e
		}
		if actorID == userID {
			return fmt.Errorf("%w: 不能给自己授予角色（避免自提权）", ErrSelfTarget)
		}
		roles, e = rbac.RolesOf(ctx, tx, tenantID, userID)
		return e
	})
	return roles, err
}

// RevokeRole 撤销角色。最后一个系统管理员不可撤（rbac 内部保证）。
//
// 允许撤销**自己**的角色：这是合法操作（例如把管理权交给别人后退出管理层），
// 而"会不会锁死"由 last-admin 判定兜住。
// 授予自己则不同——那是提权，必须禁止（见 GrantRole）。
func (s *Service) RevokeRole(ctx context.Context, tenantID, actorID, userID, code string) ([]string, error) {
	var roles []string
	err := db.WithTenant(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		actor, e := actorOf(ctx, tx, actorID)
		if e != nil {
			return e
		}
		if !actor.IsSysAdmin() {
			return ErrForbidden
		}
		if _, e := getMember(ctx, tx, userID); e != nil {
			return e
		}
		if e := rbac.Revoke(ctx, tx, tenantID, userID, code); e != nil {
			return e
		}
		roles, e = rbac.RolesOf(ctx, tx, tenantID, userID)
		return e
	})
	return roles, err
}

// ---------------- 内部 ----------------

// ensureNotLastAdmin 判断"停用/删除这个人之后，租户是否还有可用的系统管理员"。
//
// 与 rbac.Revoke 的检查口径一致但不完全相同：
//   - Revoke 看的是"还有没有 sysadmin 角色"；
//   - 这里看的是"还有没有**能登录的** sysadmin"——把最后一个管理员停用，
//     即使角色还在，也等于租户永久失去管理入口。
func ensureNotLastAdmin(ctx context.Context, tx pgx.Tx, tenantID, userID string) error {
	// 锁租户行：两个并发请求同时停用两个管理员时，必须串行判定
	if _, err := tx.Exec(ctx, `SELECT 1 FROM tenant WHERE id = $1 FOR UPDATE`, tenantID); err != nil {
		return err
	}
	var isAdmin bool
	if err := tx.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM user_role ur JOIN role r ON r.id = ur.role_id
			 WHERE ur.user_id = $1 AND r.tenant_id = $2
			   AND r.code = $3 AND r.deleted_at IS NULL)`,
		userID, tenantID, rbac.SysAdmin).Scan(&isAdmin); err != nil {
		return err
	}
	if !isAdmin {
		return nil
	}
	// 统计"除目标之外"还能登录的管理员。
	//
	// 必须排除目标本身：否则"停用一个已经停用的管理员"会被误判为锁死操作
	// （目标不在可用计数里，计数恰好为 1，误认为他是最后一个）。
	var others int
	if err := tx.QueryRow(ctx, `
		SELECT count(DISTINCT u.id)
		  FROM app_user u
		  JOIN user_role ur ON ur.user_id = u.id
		  JOIN role r ON r.id = ur.role_id
		 WHERE u.tenant_id = $1 AND u.deleted_at IS NULL AND u.status = 'active'
		   AND u.id <> $3
		   AND r.code = $2 AND r.deleted_at IS NULL
		   AND (u.expires_at IS NULL OR u.expires_at > now())`,
		tenantID, rbac.SysAdmin, userID).Scan(&others); err != nil {
		return err
	}
	if others == 0 {
		return fmt.Errorf("%w（停用/删除后租户将没有可登录的系统管理员）", ErrLastAdmin)
	}
	return nil
}

func actorOf(ctx context.Context, tx pgx.Tx, userID string) (Actor, error) {
	var a Actor
	if err := tx.QueryRow(ctx,
		`SELECT ceiling, classification FROM app_user
		  WHERE id = $1 AND deleted_at IS NULL AND status = 'active'`, userID).
		Scan(&a.Ceiling, &a.Classification); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Actor{}, ErrForbidden
		}
		return Actor{}, err
	}
	a.ID = userID
	// 直接查 user_role 而不复用 rbac.RolesOf：后者需要 tenantID 参数，
	// 而这里已经在租户事务里，RLS 保证只能看到本租户的行，少一个参数就少一处传错的可能。
	rows, err := tx.Query(ctx, `
		SELECT r.code FROM user_role ur JOIN role r ON r.id = ur.role_id
		 WHERE ur.user_id = $1 AND r.is_system AND r.deleted_at IS NULL ORDER BY r.code`, userID)
	if err != nil {
		return Actor{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			return Actor{}, err
		}
		a.Roles = append(a.Roles, c)
	}
	return a, rows.Err()
}

func getMember(ctx context.Context, tx pgx.Tx, userID string) (Member, error) {
	row := tx.QueryRow(ctx, `
		SELECT u.id::text, u.username, COALESCE(u.email,''), u.display_name,
		       u.principal_type, u.source, u.status, u.classification, u.ceiling,
		       u.mfa_required, u.expires_at, u.last_login_at, u.created_at,
		       COALESCE(u.dept_id::text,''), COALESCE(d.name,''),
		       COALESCE((SELECT array_agg(r.code ORDER BY r.code)
		                   FROM user_role ur JOIN role r ON r.id = ur.role_id
		                  WHERE ur.user_id = u.id AND r.is_system AND r.deleted_at IS NULL), '{}')
		  FROM app_user u
		  LEFT JOIN dept d ON d.id = u.dept_id AND d.deleted_at IS NULL
		 WHERE u.id = $1 AND u.deleted_at IS NULL AND u.status <> 'deleted'`, userID)
	m, err := scanMember(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Member{}, ErrNotFound
		}
		return Member{}, err
	}
	return m, nil
}

// scanner 兼容 pgx.Row 与 pgx.Rows。
type scanner interface{ Scan(dest ...any) error }

func scanMember(s scanner) (Member, error) {
	var m Member
	if err := s.Scan(&m.ID, &m.Username, &m.Email, &m.DisplayName,
		&m.PrincipalType, &m.Source, &m.Status, &m.Classification, &m.Ceiling,
		&m.MFARequired, &m.ExpiresAt, &m.LastLoginAt, &m.CreatedAt,
		&m.DeptID, &m.DeptName, &m.Roles); err != nil {
		return Member{}, err
	}
	if m.Roles == nil {
		m.Roles = []string{}
	}
	m.CanLogin = m.Status == StatusActive &&
		(m.ExpiresAt == nil || m.ExpiresAt.After(time.Now()))
	return m, nil
}

func likePattern(q string) string {
	q = strings.TrimSpace(q)
	if q == "" {
		return ""
	}
	// 转义 LIKE 通配符：否则用户搜 "%" 会匹配全部，看起来像"搜索坏了"
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return "%" + r.Replace(q) + "%"
}

func isDup(err error) bool {
	var pe *pgconn.PgError
	return errors.As(err, &pe) && pe.Code == "23505"
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}
