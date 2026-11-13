// Package bootstrap 负责首次启动的初始化数据。
//
// 只做"空库时建一个可登录的演示账号"，不写入任何业务数据：
// 演示环境需要它，生产环境默认关闭（DOCVAULT_DEV_SEED 未设置即跳过）。
package bootstrap

import (
	"context"
	"errors"
	"fmt"

	"docvault/internal/auth"
	"docvault/internal/db"
	"docvault/internal/rbac"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// DemoResult 是初始化结果，供日志输出。
type DemoResult struct {
	Created    bool
	TenantSlug string
	AdminUser  string
}

// SeedDemo 在库为空时创建演示租户与管理员账号。
//
// 幂等：只要已存在任意租户就跳过，避免反复启动覆盖真实数据。
func SeedDemo(ctx context.Context, pool *pgxpool.Pool, tenantSlug, adminUser, adminPassword string) (DemoResult, error) {
	if tenantSlug == "" || adminUser == "" || adminPassword == "" {
		return DemoResult{}, errors.New("种子参数不完整")
	}
	if len(adminPassword) < 12 {
		return DemoResult{}, fmt.Errorf("演示管理员口令需 ≥12 位，当前 %d 位", len(adminPassword))
	}

	// 幂等判断按 slug：只要目标租户已存在就跳过。
	// 不用"库中是否有任何租户"，因为开发库里常有测试残留租户，
	// 那会导致演示账号永远建不出来。
	var existing int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM tenant WHERE slug = $1`, tenantSlug).Scan(&existing); err != nil {
		return DemoResult{}, err
	}
	if existing > 0 {
		return DemoResult{Created: false}, nil
	}

	hash, err := auth.HashPassword(adminPassword)
	if err != nil {
		return DemoResult{}, err
	}

	var tenantID string
	if err := pool.QueryRow(ctx, `
		INSERT INTO tenant (id, slug, name) VALUES (gen_random_uuid(), $1, $2)
		RETURNING id::text`, tenantSlug, "演示组织").Scan(&tenantID); err != nil {
		return DemoResult{}, fmt.Errorf("创建租户失败: %w", err)
	}

	// 建一个根部门，保证后续"按部门授权"有可用的载体
	var deptID string
	if err := pool.QueryRow(ctx, `
		INSERT INTO dept (id, tenant_id, path, name) VALUES (gen_random_uuid(), $1, $2::ltree, $3)
		RETURNING id::text`, tenantID, "root", "总部").Scan(&deptID); err != nil {
		return DemoResult{}, fmt.Errorf("创建部门失败: %w", err)
	}

	var adminID string
	err = db.WithTenant(ctx, pool, tenantID, func(tx pgx.Tx) error {
		if e := tx.QueryRow(ctx, `
			INSERT INTO app_user (id, tenant_id, username, display_name, password_hash,
			                      dept_id, status, classification)
			VALUES (gen_random_uuid(), $1, $2, $3, $4, $5, 'active', 1)
			RETURNING id::text`,
			tenantID, adminUser, "演示管理员", hash, deptID).Scan(&adminID); e != nil {
			return e
		}
		// 管理面必须有入口：种子阶段把首个用户初始化为系统管理员。
		// 注意只在种子/启动装配里做，绝不放进请求路径（否则等于留了一条自动提权链）。
		if e := rbac.Bootstrap(ctx, tx, tenantID); e != nil {
			return e
		}
		// 演示环境里同一个账号还负责密级与审批配置（安全管理员）。
		// 三权分立只禁止"审计 + 其他"，sysadmin 与 secadmin 并存是允许的。
		return rbac.Grant(ctx, tx, tenantID, adminID, rbac.SecAdmin, adminID)
	})
	if err != nil {
		return DemoResult{}, fmt.Errorf("创建管理员失败: %w", err)
	}

	return DemoResult{Created: true, TenantSlug: tenantSlug, AdminUser: adminUser}, nil
}
