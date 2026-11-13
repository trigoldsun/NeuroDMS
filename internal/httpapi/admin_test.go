package httpapi

// M2-B 管理面与三权分立用例。
//
// 三条规则必须同时成立，缺一条就等于没有分权：
//   1. 没角色的人进不了管理面（AC-08），且被拒绝的尝试要留痕；
//   2. 审计员不能改配置（AC-74）——能改的人不能审自己；
//   3. 同一账号不能兼任审计员（AC-75），且不能把最后一个管理员撤掉（AC-76）。

import (
	"context"
	"net/http"
	"testing"

	"docvault/internal/rbac"

	"github.com/jackc/pgx/v5/pgxpool"
)

// seedRole 在租户内创建内置角色并授予用户（绕开管理面自身，用于构造前置状态）。
func seedRole(t *testing.T, pool *pgxpool.Pool, tenantID, userID, code string) {
	t.Helper()
	ctx := context.Background()
	var roleID string
	if err := pool.QueryRow(ctx, `
		INSERT INTO role (id, tenant_id, code, name, is_system, data_scope, perms)
		VALUES (gen_random_uuid(), $1, $2, $2, true, 'all', '{}')
		ON CONFLICT (tenant_id, code) WHERE deleted_at IS NULL
		DO UPDATE SET name = EXCLUDED.name
		RETURNING id::text`, tenantID, code).Scan(&roleID); err != nil {
		t.Fatalf("创建角色 %s 失败: %v", code, err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO user_role (tenant_id, user_id, role_id) VALUES ($1,$2,$3)
		ON CONFLICT (user_id, role_id) DO NOTHING`, tenantID, userID, roleID); err != nil {
		t.Fatalf("授予角色 %s 失败: %v", code, err)
	}
}

func countAudit(t *testing.T, pool *pgxpool.Pool, tenantID, action string) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(), `
		SELECT count(*) FROM audit_event WHERE tenant_id = $1 AND action = $2`,
		tenantID, action).Scan(&n); err != nil {
		t.Fatalf("统计审计事件失败: %v", err)
	}
	return n
}

// AC-08：普通用户调用管理面必须 403，且这次尝试要被审计。
//
// "被拒绝也要留痕"是这条用例的核心：只回 403 而不记录，
// 内部人员反复试探管理面时，事后完全查不出来。
func TestAC08AdminRequiresRole(t *testing.T) {
	srv, pool, slug := setup(t)
	tenantID := tenantOf(t, pool, slug)

	// 第一个用户（bob）就是 setup 建的账号，但它没有管理角色
	bobToken := login(t, srv.URL, slug)
	resp, body := getJSON(t, srv.URL+"/v1/admin/summary", bobToken)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("AC-08 普通用户调管理面应 403，实际 %d: %v", resp.StatusCode, body)
	}

	before := countAudit(t, pool, tenantID, "admin.denied")
	if before < 1 {
		t.Fatalf("AC-08 越权尝试必须写审计（admin.denied），实际 0 条")
	}
}

// AC-74：审计员不能改配置（系统管理员端点对它一律 403）。
func TestAC74AuditorCannotChangeConfig(t *testing.T) {
	srv, pool, slug := setup(t)
	tenantID := tenantOf(t, pool, slug)
	bobToken := login(t, srv.URL, slug)
	bobID := userIDByName(t, slug, "bob")

	// 先给 bob 系统管理员（保证租户不是"无管理员"状态），再造一个审计员账号
	seedRole(t, pool, tenantID, bobID, rbac.SysAdmin)
	auditorToken := seedUser(t, srv.URL, slug, "auditor74")
	auditorID := userIDByName(t, slug, "auditor74")
	seedRole(t, pool, tenantID, auditorID, rbac.Auditor)

	// 审计员访问系统管理端点（改配置的入口）→ 403
	if r, raw := getRaw(t, srv.URL+"/v1/admin/summary", auditorToken); r.StatusCode != http.StatusForbidden {
		t.Fatalf("AC-74 审计员不得访问系统管理端点，期望 403，实际 %d: %s", r.StatusCode, raw)
	}
	// 审计员访问审计查询 → 允许
	if r, raw := getRaw(t, srv.URL+"/v1/admin/audit/events?limit=5", auditorToken); r.StatusCode != 200 {
		t.Fatalf("AC-74 审计员应能查审计，实际 %d: %s", r.StatusCode, raw)
	}
	// 反向：系统管理员不能访问审计明细（独立性）
	if r, raw := getRaw(t, srv.URL+"/v1/admin/audit/events", bobToken); r.StatusCode != http.StatusForbidden {
		t.Fatalf("系统管理员不应能直接查审计明细，期望 403，实际 %d: %s", r.StatusCode, raw)
	}
}

// AC-75：同一账号不得同时拥有审计角色与其他管理角色。
func TestAC75SameAccountCannotBeAuditorAndAdmin(t *testing.T) {
	srv, pool, slug := setup(t)
	tenantID := tenantOf(t, pool, slug)
	bobToken := login(t, srv.URL, slug)
	bobID := userIDByName(t, slug, "bob")

	seedRole(t, pool, tenantID, bobID, rbac.SysAdmin)

	// 通过管理面把 auditor 授给已有 sysadmin 的账号 → 409
	resp, body := postJSON(t, srv.URL+"/v1/admin/users/"+bobID+"/roles", bobToken,
		map[string]any{"code": rbac.Auditor})
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("AC-75 兼任审计角色应 409，实际 %d: %v", resp.StatusCode, body)
	}
	if body["code"] != "SEPARATION_VIOLATION" {
		t.Fatalf("AC-75 应返回 SEPARATION_VIOLATION: %v", body)
	}

	// 反方向：先有 auditor 再授 sysadmin 也必须拒
	aud2 := seedUser(t, srv.URL, slug, "aud75")
	aud2ID := userIDByName(t, slug, "aud75")
	seedRole(t, pool, tenantID, aud2ID, rbac.Auditor)
	resp, body = postJSON(t, srv.URL+"/v1/admin/users/"+aud2ID+"/roles", bobToken,
		map[string]any{"code": rbac.SysAdmin})
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("AC-75 反方向兼任应 409，实际 %d: %v", resp.StatusCode, body)
	}

	// 历史脏状态（库里已同时存在审计与安全角色）：该账号的所有管理面访问必须被整体拒绝。
	// 这一条覆盖"规则上线前就有的脏数据"——只拦新授予是不够的。
	seedRole(t, pool, tenantID, aud2ID, rbac.SecAdmin) // 直接写库制造脏状态
	if r, raw := getRaw(t, srv.URL+"/v1/admin/audit/events", aud2); r.StatusCode != http.StatusForbidden {
		t.Fatalf("AC-75 违反分立的账号应被整体拒绝，实际 %d: %s", r.StatusCode, raw)
	}
	if _, b2 := getJSON(t, srv.URL+"/v1/admin/audit/events", aud2); b2["code"] != "SEPARATION_VIOLATION" {
		t.Fatalf("AC-75 应明确回报分立冲突: %v", b2)
	}
}

// AC-76：不能撤销最后一个系统管理员。
func TestAC76CannotRevokeLastAdmin(t *testing.T) {
	srv, pool, slug := setup(t)
	tenantID := tenantOf(t, pool, slug)
	bobToken := login(t, srv.URL, slug)
	bobID := userIDByName(t, slug, "bob")

	seedRole(t, pool, tenantID, bobID, rbac.SysAdmin)

	resp, body := delJSON(t, srv.URL+"/v1/admin/users/"+bobID+"/roles/"+rbac.SysAdmin, bobToken)
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("AC-76 撤销最后一个管理员应 409，实际 %d: %v", resp.StatusCode, body)
	}

	// 有两个管理员时可以撤掉一个
	second := seedUser(t, srv.URL, slug, "admin76b")
	secondID := userIDByName(t, slug, "admin76b")
	seedRole(t, pool, tenantID, secondID, rbac.SysAdmin)
	resp, body = delJSON(t, srv.URL+"/v1/admin/users/"+secondID+"/roles/"+rbac.SysAdmin, bobToken)
	if resp.StatusCode != 200 {
		t.Fatalf("AC-76 存在两个管理员时撤一个应成功，实际 %d: %v", resp.StatusCode, body)
	}
	_ = second
}

// 管理面授予角色要留痕，且返回最新角色集合。
func TestAdminGrantRoleIsAudited(t *testing.T) {
	srv, pool, slug := setup(t)
	tenantID := tenantOf(t, pool, slug)
	bobToken := login(t, srv.URL, slug)
	bobID := userIDByName(t, slug, "bob")
	seedRole(t, pool, tenantID, bobID, rbac.SysAdmin)

	target := seedUser(t, srv.URL, slug, "sec1")
	targetID := userIDByName(t, slug, "sec1")

	resp, body := postJSON(t, srv.URL+"/v1/admin/users/"+targetID+"/roles", bobToken,
		map[string]any{"code": rbac.SecAdmin})
	if resp.StatusCode != 200 {
		t.Fatalf("授予 secadmin 失败 %d: %v", resp.StatusCode, body)
	}
	roles, _ := dataMap(t, body)["roles"].([]any)
	if len(roles) != 1 || roles[0] != rbac.SecAdmin {
		t.Fatalf("返回角色集合不符: %v", roles)
	}
	if countAudit(t, pool, tenantID, "admin.role.grant") < 1 {
		t.Fatal("授予角色必须写审计")
	}
	_ = target
}
