// Package dbtest 给集成测试提供共享夹具。
//
// 存在的原因：各测试包都写了一遍"删掉本租户的数据"，但删除顺序经常漏掉子表，
// 触发外键错误后又被 `_, _ =` 忽略，结果库里堆了几百个残留租户。
// 把顺序写在一处，比在每个测试里重复一遍更可靠。
package dbtest

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// cleanupOrder 按"子表 → 父表"排列。顺序错了会静默失败（FK 约束），
// 所以这里显式列出，而不是依赖级联删除。
var cleanupOrder = []string{
	// M3：计量与租户配置。都引用 tenant，且要在 app_user / node 之前删
	// （usage 的触发器会在 node/app_user 行变动时更新 tenant_usage，
	//   先删账本再删业务行会让触发器把新行又插回来）。
	"usage_event",
	"usage_daily",
	"tenant_domain",
	"tenant_feature",
	"tenant_quota",
	"share_visit",
	"share_ticket",
	"share_verify", // 引用 share，必须先删
	"share",
	// 分片上传会话与分片（都在 node/space 之前）
	"upload_part",
	"upload_session",
	// 在线编辑会话：引用 node，必须在 node 之前删
	"doc_session",
	// 密级相关：classification_change 与 node_label 都引用 node，必须先删
	"classification_change",
	"node_label",
	"label_policy",
	"ace",
	"version",
	"blob",
	"node",
	// 空间移交请求引用 space，必须先删，否则 FK 会让整笔清理失败
	"space_transfer",
	"space",
	"classification_label",
	"session",
	"user_role",
	"role", // 必须在 user_role 之后：role 被 user_role 引用
	"group_member",
	"user_group",
	"otp_code",
	"notification",
	"directory_sync",
	"audit_anchor",
	"audit_event", // 有"只追加"规则，需临时禁用，见下
	"app_user",
	"dept",
	// tenant_usage / tenant_config 最后删：它们的触发器依赖上面两步已完成
	"tenant_usage",
	"tenant_config",
}

// CleanupTenant 删除某租户下的全部业务数据，最后删租户本身。
//
// 关于审计表：audit_event 的 DELETE 被规则挡住（只追加）。
// 早期做法是 `ALTER TABLE ... DISABLE RULE`，但那是表级 DDL，需要 ACCESS EXCLUSIVE 锁，
// 多个测试包并行跑时会互相等待、超时后静默留下残留租户（实测堆到 478 个）。
// 现在改为在**本事务内**设置会话级 GUC（见迁移 0014），不动表结构、不阻塞其它会话。
func CleanupTenant(t *testing.T, pool *pgxpool.Pool, tenantID string) {
	t.Helper()
	ctx := context.Background()

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Logf("清理租户失败（开启事务）: %v", err)
		return
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// 只在本事务内放开审计删除；提交后自动失效，不影响其它会话与生产行为
	if _, err := tx.Exec(ctx, `SET LOCAL lock_timeout = '20s'`); err != nil {
		t.Logf("设置锁超时失败: %v", err)
	}
	if _, err := tx.Exec(ctx, `SET LOCAL docvault.allow_audit_delete = 'on'`); err != nil {
		t.Logf("设置审计删除开关失败: %v", err)
		return
	}

	for _, table := range cleanupOrder {
		if _, err := tx.Exec(ctx, "DELETE FROM "+table+" WHERE tenant_id = $1", tenantID); err != nil {
			t.Logf("清理 %s 失败: %v", table, err)
		}
	}
	if _, err := tx.Exec(ctx, `DELETE FROM tenant WHERE id = $1`, tenantID); err != nil {
		t.Logf("删除租户失败: %v", err)
	}

	if err := tx.Commit(ctx); err != nil {
		t.Logf("提交清理事务失败: %v", err)
	}
}
