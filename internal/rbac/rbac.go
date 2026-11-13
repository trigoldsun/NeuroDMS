// Package rbac 实现管理面的角色模型与三权分立。
//
// 为什么单独成包而不塞进 httpapi：
// 三权分立是**合规要求**，不是界面功能。它的规则必须能被独立测试，
// 也必须被所有入口（HTTP、CLI、将来的定时任务）共用一份实现。
//
// 本包只管"谁有什么角色、能不能同时有"，不管"角色能做什么"——
// 后者由各 handler 显式声明所需角色（requireRole），不允许"登录即可"的隐式放行。
package rbac

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/jackc/pgx/v5"
)

// 内置角色编码。一旦发布不得改名（会出现在审计与配置里）。
const (
	// SysAdmin 系统管理员：用户、目录、空间、系统配置
	SysAdmin = "sysadmin"
	// SecAdmin 安全管理员：密级、授权策略、审批、水印策略
	SecAdmin = "secadmin"
	// Auditor 审计管理员：只读审计与证据包导出
	Auditor = "auditor"
)

// systemRoles 是内置角色的展示名与说明。
var systemRoles = []struct {
	Code string
	Name string
	Desc string
}{
	{SysAdmin, "系统管理员", "用户与目录、空间、系统配置"},
	{SecAdmin, "安全管理员", "密级与授权策略、外发审批、水印策略"},
	{Auditor, "审计管理员", "只读审计日志、导出证据包（不得修改任何业务配置）"},
}

// ErrRoleConflict 表示违反三权分立。
var ErrRoleConflict = errors.New("违反三权分立：审计角色不得与其他管理角色并存")

// ErrLastAdmin 表示这次变更会移除最后一个系统管理员。
var ErrLastAdmin = errors.New("不能移除最后一个系统管理员")

// ErrUnknownRole 表示角色编码不在内置列表里。
var ErrUnknownRole = errors.New("未知内置角色")

// All 返回全部内置角色编码。
func All() []string {
	out := make([]string, 0, len(systemRoles))
	for _, r := range systemRoles {
		out = append(out, r.Code)
	}
	return out
}

// Describe 返回内置角色的展示信息（code → name/desc）。
func Describe() []map[string]string {
	out := make([]map[string]string, 0, len(systemRoles))
	for _, r := range systemRoles {
		out = append(out, map[string]string{"code": r.Code, "name": r.Name, "description": r.Desc})
	}
	return out
}

// Known 判断是否为内置角色。
func Known(code string) bool {
	for _, r := range systemRoles {
		if r.Code == code {
			return true
		}
	}
	return false
}

// SeparationViolation 检查角色集合是否违反三权分立，返回人能读懂的原因。
//
// 规则：审计角色（auditor）不得与任何"能改东西"的管理角色并存。
// 理由：审计的价值来自独立性。一个人既能改配置又能审自己改的配置，
// 审计日志再完整也无法证明清白——这正是"三权分立"要防的事。
//
// 注意：这里刻意做成"任意顺序都返回同一结论"，避免调用方依赖遍历顺序。
func SeparationViolation(roles []string) string {
	hasAuditor := false
	var others []string
	for _, r := range roles {
		switch r {
		case Auditor:
			hasAuditor = true
		case SysAdmin, SecAdmin:
			others = append(others, r)
		}
	}
	if hasAuditor && len(others) > 0 {
		sort.Strings(others)
		return fmt.Sprintf("审计管理员不得同时拥有 %v", others)
	}
	return ""
}

// Contains 判断角色集合是否包含任一目标角色。
func Contains(roles []string, want ...string) bool {
	set := make(map[string]bool, len(roles))
	for _, r := range roles {
		set[r] = true
	}
	for _, w := range want {
		if set[w] {
			return true
		}
	}
	return false
}

// ensureRoles 幂等地创建内置角色，返回 code → id。
//
// 为什么按需创建而不是只在建租户时创建：
// 存量租户（含测试与迁移来的租户）不会有这些行，一旦缺失，
// 管理面就永远进不去。按需创建让"角色存在"成为不变量。
func ensureRoles(ctx context.Context, tx pgx.Tx, tenantID string) (map[string]string, error) {
	ids := make(map[string]string, len(systemRoles))
	for _, r := range systemRoles {
		var id string
		// ON CONFLICT 命中唯一索引 uq_role_tenant_code（部分索引需带谓词）
		err := tx.QueryRow(ctx, `
			INSERT INTO role (id, tenant_id, code, name, is_system, data_scope, perms)
			VALUES (gen_random_uuid(), $1, $2, $3, true, 'all', '{}')
			ON CONFLICT (tenant_id, code) WHERE deleted_at IS NULL
			DO UPDATE SET name = EXCLUDED.name, is_system = true
			RETURNING id::text`,
			tenantID, r.Code, r.Name).Scan(&id)
		if err != nil {
			return nil, err
		}
		ids[r.Code] = id
	}
	return ids, nil
}

// RolesOf 返回用户在租户内的内置角色编码（已排序，便于断言与展示）。
func RolesOf(ctx context.Context, tx pgx.Tx, tenantID, userID string) ([]string, error) {
	rows, err := tx.Query(ctx, `
		SELECT r.code FROM user_role ur JOIN role r ON r.id = ur.role_id
		 WHERE ur.user_id = $1 AND r.tenant_id = $2 AND r.is_system AND r.deleted_at IS NULL
		 ORDER BY r.code`, userID, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// Grant 给用户授予内置角色。
//
// 两道校验：角色必须已知；授予后不得违反三权分立。
// 冲突检查放在"授予后"而不是"授予前"，因为要判断的是结果状态。
func Grant(ctx context.Context, tx pgx.Tx, tenantID, userID, code, grantedBy string) error {
	if !Known(code) {
		return ErrUnknownRole
	}
	ids, err := ensureRoles(ctx, tx, tenantID)
	if err != nil {
		return err
	}

	current, err := RolesOf(ctx, tx, tenantID, userID)
	if err != nil {
		return err
	}
	if Contains(current, code) {
		return nil // 幂等
	}
	if v := SeparationViolation(append(current, code)); v != "" {
		return fmt.Errorf("%w: %s", ErrRoleConflict, v)
	}

	_, err = tx.Exec(ctx, `
		INSERT INTO user_role (tenant_id, user_id, role_id)
		VALUES ($1, $2, $3)
		ON CONFLICT (user_id, role_id) DO NOTHING`, tenantID, userID, ids[code])
	return err
}

// Revoke 移除用户的内置角色，并保护"最后一个系统管理员"。
//
// 这是 AC-76 的实现点：没有这道保护，一次误操作就能让租户永久失去
// 系统管理员入口（只能靠运维改库），属于典型的"操作一次、事故一生"。
func Revoke(ctx context.Context, tx pgx.Tx, tenantID, userID, code string) error {
	if !Known(code) {
		return ErrUnknownRole
	}
	ids, err := ensureRoles(ctx, tx, tenantID)
	if err != nil {
		return err
	}
	if code == SysAdmin {
		// 锁住租户行，避免两个并发撤销各自看到"还有 2 个"而同时成功
		if _, err := tx.Exec(ctx, `SELECT 1 FROM tenant WHERE id = $1 FOR UPDATE`, tenantID); err != nil {
			return err
		}
		var admins int
		if err := tx.QueryRow(ctx, `
			SELECT count(*) FROM user_role ur JOIN role r ON r.id = ur.role_id
			 WHERE r.tenant_id = $1 AND r.code = $2 AND r.deleted_at IS NULL`,
			tenantID, SysAdmin).Scan(&admins); err != nil {
			return err
		}
		var hasThis bool
		if err := tx.QueryRow(ctx, `
			SELECT EXISTS (SELECT 1 FROM user_role WHERE user_id = $1 AND role_id = $2)`,
			userID, ids[code]).Scan(&hasThis); err != nil {
			return err
		}
		if hasThis && admins <= 1 {
			return ErrLastAdmin
		}
	}

	_, err = tx.Exec(ctx, `DELETE FROM user_role WHERE user_id = $1 AND role_id = $2`, userID, ids[code])
	return err
}

// Bootstrap 保证租户至少有一个系统管理员。
//
// 只在启动装配时调用，**绝不能放在请求路径上**：
// 如果每次请求都判"没有管理员就把最早的用户提成管理员"，
// 那就等于给了一条"清空管理员 → 任意人自动变管理员"的提权链。
func Bootstrap(ctx context.Context, tx pgx.Tx, tenantID string) error {
	ids, err := ensureRoles(ctx, tx, tenantID)
	if err != nil {
		return err
	}
	var admins int
	if err := tx.QueryRow(ctx, `
		SELECT count(*) FROM user_role WHERE role_id = $1`, ids[SysAdmin]).Scan(&admins); err != nil {
		return err
	}
	if admins > 0 {
		return nil
	}
	// 取最早创建的本租户用户作为初始化管理员
	var userID string
	err = tx.QueryRow(ctx, `
		SELECT id::text FROM app_user
		 WHERE tenant_id = $1 AND deleted_at IS NULL
		 ORDER BY created_at, id LIMIT 1`, tenantID).Scan(&userID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil // 空租户：没有可授权的用户，不是错误
		}
		return err
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO user_role (tenant_id, user_id, role_id) VALUES ($1, $2, $3)
		ON CONFLICT (user_id, role_id) DO NOTHING`, tenantID, userID, ids[SysAdmin])
	return err
}
