package httpapi

import (
	"context"
	"fmt"
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// 账号管理（成员）测试。
//
// 这一组测试守的都是"拒绝类"规则：不能越权建号、不能给自己加角色、
// 不能给别人超过自己的密级、不能把最后一个管理员停掉。
// 这类规则一旦漏了，界面上不会有任何异常，只有出事时才会被发现。

var memberSeq int64

func uniq(prefix string) string {
	return fmt.Sprintf("%s%d", prefix, atomic.AddInt64(&memberSeq, 1))
}

// adminToken 把 bob 设为系统管理员并返回其令牌（大多数用例的前置条件）。
func adminToken(t *testing.T, base string, pool *pgxpool.Pool, slug string) string {
	t.Helper()
	tok := login(t, base, slug)
	bobID := userIDByName(t, slug, "bob")
	seedRole(t, pool, tenantOf(t, pool, slug), bobID, "sysadmin")
	return tok
}

// ---------------- 创建 ----------------

func TestMemberCreateWithRoleAndLogin(t *testing.T) {
	srv, pool, slug := setup(t)
	tenantID := tenantOf(t, pool, slug)
	bobToken := login(t, srv.URL, slug)
	bobID := userIDByName(t, slug, "bob")
	seedRole(t, pool, tenantID, bobID, "sysadmin")
	// 操作者密级为 0 时不能建密级 2 的账号（另有用例覆盖），
	// 这里先把操作者抬到 3，验证"允许"的那条路径。
	if _, err := pool.Exec(context.Background(),
		`UPDATE app_user SET classification = 3 WHERE id = $1`, bobID); err != nil {
		t.Fatal(err)
	}

	name := uniq("alice")
	resp, body := postJSON(t, srv.URL+"/v1/admin/members", bobToken, map[string]any{
		"username": name, "displayName": "爱丽丝", "password": "member-pass-1234",
		"role": "secadmin", "ceiling": 4, "classification": 2,
	})
	if resp.StatusCode != 200 {
		t.Fatalf("创建成员失败 %d: %v", resp.StatusCode, body)
	}
	m := dataMap(t, body)
	if m["username"] != name {
		t.Fatalf("返回的用户名不符: %v", m)
	}
	if roles, _ := m["roles"].([]any); len(roles) != 1 || roles[0] != "secadmin" {
		t.Fatalf("应带上已授予的角色: %v", m)
	}

	// 新账号必须能直接登录（否则"建号成功但进不来"是常被投诉的问题）
	tok := loginWith(t, srv.URL, slug, name, "member-pass-1234")
	if r, _ := getJSON(t, srv.URL+"/v1/me", tok); r.StatusCode != 200 {
		t.Fatalf("新成员应可登录，实际 %d", r.StatusCode)
	}

	// 列表里能看到
	_, list := getJSON(t, srv.URL+"/v1/admin/members?q="+name, bobToken)
	items, _ := dataMap(t, list)["items"].([]any)
	if len(items) != 1 {
		t.Fatalf("列表应能按关键字命中，实际 %v", list)
	}
}

// 只有系统管理员能建号：安全管理员与审计管理员都不行。
// 这是三权分立的落地断言——否则"安全管理员"可以给自己建一个管理员账号。
func TestMemberCreateRequiresSysadmin(t *testing.T) {
	srv, pool, slug := setup(t)
	tenantID := tenantOf(t, pool, slug)

	cases := []struct {
		name string
		role string
	}{
		{"no-role", ""},
		{"sec", "secadmin"},
		{"aud", "auditor"},
	}
	for _, c := range cases {
		user := uniq("u")
		seedUser(t, srv.URL, slug, user)
		uid := userIDByName(t, slug, user)
		if c.role != "" {
			seedRole(t, pool, tenantID, uid, c.role)
		}
		tok := loginWith(t, srv.URL, slug, user, pwd)

		resp, body := postJSON(t, srv.URL+"/v1/admin/members", tok, map[string]any{
			"username": uniq("x"), "password": "member-pass-1234",
		})
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("%s 建号应 403，实际 %d: %v", c.name, resp.StatusCode, body)
		}
	}
}

// 不能创建比自己密级/封顶更高的账号——那等于给自己造一个更高级的替身。
func TestMemberCreateBlocksEscalation(t *testing.T) {
	srv, pool, slug := setup(t)
	tenantID := tenantOf(t, pool, slug)
	bobToken := login(t, srv.URL, slug)
	bobID := userIDByName(t, slug, "bob")
	seedRole(t, pool, tenantID, bobID, "sysadmin")
	// bob 的封顶调到 3
	if _, err := pool.Exec(context.Background(),
		`UPDATE app_user SET ceiling = 3, classification = 2 WHERE id = $1`, bobID); err != nil {
		t.Fatal(err)
	}

	resp, body := postJSON(t, srv.URL+"/v1/admin/members", bobToken, map[string]any{
		"username": uniq("esc"), "password": "member-pass-1234", "ceiling": 5,
	})
	if resp.StatusCode != http.StatusForbidden || body["code"] != "CEILING_EXCEEDED" {
		t.Fatalf("超过自身封顶应 403 CEILING_EXCEEDED，实际 %d: %v", resp.StatusCode, body)
	}

	// 密级同理
	resp, body = postJSON(t, srv.URL+"/v1/admin/members", bobToken, map[string]any{
		"username": uniq("esc2"), "password": "member-pass-1234", "classification": 4,
	})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("超过自身密级应 403，实际 %d: %v", resp.StatusCode, body)
	}
}

func TestMemberCreateRejectsDuplicateAndBadInput(t *testing.T) {
	srv, pool, slug := setup(t)
	tenantID := tenantOf(t, pool, slug)
	bobToken := login(t, srv.URL, slug)
	bobID := userIDByName(t, slug, "bob")
	seedRole(t, pool, tenantID, bobID, "sysadmin")

	name := uniq("dup")
	if r, b := postJSON(t, srv.URL+"/v1/admin/members", bobToken, map[string]any{
		"username": name, "password": "member-pass-1234",
	}); r.StatusCode != 200 {
		t.Fatalf("首次创建应成功 %d: %v", r.StatusCode, b)
	}
	resp, body := postJSON(t, srv.URL+"/v1/admin/members", bobToken, map[string]any{
		"username": name, "password": "member-pass-1234",
	})
	if resp.StatusCode != http.StatusConflict || body["code"] != "USER_EXISTS" {
		t.Fatalf("重名应 409 USER_EXISTS，实际 %d: %v", resp.StatusCode, body)
	}

	// 弱口令
	resp, _ = postJSON(t, srv.URL+"/v1/admin/members", bobToken, map[string]any{
		"username": uniq("weak"), "password": "short",
	})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("弱口令应 400，实际 %d", resp.StatusCode)
	}

	// 未知角色
	resp, _ = postJSON(t, srv.URL+"/v1/admin/members", bobToken, map[string]any{
		"username": uniq("badrole"), "password": "member-pass-1234", "role": "god",
	})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("未知角色应 400，实际 %d", resp.StatusCode)
	}
}

// 部门必须属于本租户：拿别的租户的 dept id 建号必须被拒。
func TestMemberCreateRejectsCrossTenantDept(t *testing.T) {
	srv, pool, slug := setup(t)
	tenantID := tenantOf(t, pool, slug)
	bobToken := login(t, srv.URL, slug)
	bobID := userIDByName(t, slug, "bob")
	seedRole(t, pool, tenantID, bobID, "sysadmin")

	// 造另一个租户的部门
	otherTenant, otherDept := uuid(t), uuid(t)
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO tenant (id, slug, name) VALUES ($1,$2,$3)`,
		otherTenant, "other-"+otherTenant[:8], "别的租户"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { dbtestCleanup(t, pool, otherTenant) })
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO dept (id, tenant_id, path, name) VALUES ($1,$2,'root'::ltree,$3)`,
		otherDept, otherTenant, "外部部门"); err != nil {
		t.Fatal(err)
	}

	resp, body := postJSON(t, srv.URL+"/v1/admin/members", bobToken, map[string]any{
		"username": uniq("xdept"), "password": "member-pass-1234", "deptId": otherDept,
	})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("跨租户部门应 400，实际 %d: %v", resp.StatusCode, body)
	}
}

// ---------------- 越权与自保护 ----------------

// 不能给自己加角色（提权），也不能停用/删除自己（自锁死）。
func TestMemberSelfOperationsBlocked(t *testing.T) {
	srv, pool, slug := setup(t)
	tenantID := tenantOf(t, pool, slug)
	bobToken := login(t, srv.URL, slug)
	bobID := userIDByName(t, slug, "bob")
	seedRole(t, pool, tenantID, bobID, "sysadmin")

	resp, body := postJSON(t, srv.URL+"/v1/admin/members/"+bobID+"/roles", bobToken,
		map[string]any{"code": "secadmin"})
	if resp.StatusCode != http.StatusBadRequest || body["code"] != "SELF_OPERATION" {
		t.Fatalf("给自己加角色应 400 SELF_OPERATION，实际 %d: %v", resp.StatusCode, body)
	}
	// 旧路径也必须拦住，否则等于留了后门
	resp, body = postJSON(t, srv.URL+"/v1/admin/users/"+bobID+"/roles", bobToken,
		map[string]any{"code": "secadmin"})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("旧路径自授角色也应 400，实际 %d: %v", resp.StatusCode, body)
	}

	resp, _ = postJSON(t, srv.URL+"/v1/admin/members/"+bobID+"/status", bobToken,
		map[string]any{"status": "suspended"})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("停用自己应 400，实际 %d", resp.StatusCode)
	}
	resp, _ = sendJSONMap(t, http.MethodDelete, srv.URL+"/v1/admin/members/"+bobID, bobToken, nil)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("删除自己应 400，实际 %d", resp.StatusCode)
	}
}

// 跨租户的成员 id 在本租户里必须"不存在"（不是 403，而是 404——不泄漏存在性）。
func TestMemberCrossTenantInvisible(t *testing.T) {
	srv, pool, slug := setup(t)
	tenantID := tenantOf(t, pool, slug)
	bobToken := login(t, srv.URL, slug)
	bobID := userIDByName(t, slug, "bob")
	seedRole(t, pool, tenantID, bobID, "sysadmin")

	// 另一个租户的用户
	otherTenant, otherUser := uuid(t), uuid(t)
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO tenant (id, slug, name) VALUES ($1,$2,$3)`,
		otherTenant, "other-"+otherTenant[:8], "别的租户"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { dbtestCleanup(t, pool, otherTenant) })
	if _, err := pool.Exec(context.Background(), `
		INSERT INTO app_user (id, tenant_id, username, display_name, password_hash, status)
		VALUES ($1,$2,'outsider','局外人','x','active')`, otherUser, otherTenant); err != nil {
		t.Fatal(err)
	}

	if r, b := getJSON(t, srv.URL+"/v1/admin/members/"+otherUser, bobToken); r.StatusCode != http.StatusNotFound {
		t.Fatalf("跨租户成员应 404，实际 %d: %v", r.StatusCode, b)
	}
	if r, _ := postJSON(t, srv.URL+"/v1/admin/members/"+otherUser+"/status", bobToken,
		map[string]any{"status": "suspended"}); r.StatusCode != http.StatusNotFound {
		t.Fatalf("跨租户停用应 404，实际 %d", r.StatusCode)
	}
}

// ---------------- 状态与口令 ----------------

// 停用成员后，其已签发的令牌必须立即失效。
func TestMemberSuspendRevokesSession(t *testing.T) {
	srv, pool, slug := setup(t)
	tenantID := tenantOf(t, pool, slug)
	bobToken := login(t, srv.URL, slug)
	bobID := userIDByName(t, slug, "bob")
	seedRole(t, pool, tenantID, bobID, "sysadmin")

	name := uniq("victim")
	if r, b := postJSON(t, srv.URL+"/v1/admin/members", bobToken, map[string]any{
		"username": name, "password": "member-pass-1234",
	}); r.StatusCode != 200 {
		t.Fatalf("建号失败 %d: %v", r.StatusCode, b)
	}
	uid := userIDByName(t, slug, name)
	victimTok := loginWith(t, srv.URL, slug, name, "member-pass-1234")
	if r, _ := getJSON(t, srv.URL+"/v1/me", victimTok); r.StatusCode != 200 {
		t.Fatal("停用前应可用")
	}

	if r, b := postJSON(t, srv.URL+"/v1/admin/members/"+uid+"/status", bobToken,
		map[string]any{"status": "suspended"}); r.StatusCode != 200 {
		t.Fatalf("停用失败 %d: %v", r.StatusCode, b)
	}
	if r, b := getJSON(t, srv.URL+"/v1/me", victimTok); r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("停用后旧令牌应 401，实际 %d: %v", r.StatusCode, b)
	}
	// 也不能再登录
	if r, _ := postJSON(t, srv.URL+"/v1/auth/login", "", map[string]any{
		"tenantSlug": slug, "username": name, "password": "member-pass-1234",
	}); r.StatusCode == 200 {
		t.Fatal("停用后不应能登录")
	}
	// 恢复后可登录
	if r, _ := postJSON(t, srv.URL+"/v1/admin/members/"+uid+"/status", bobToken,
		map[string]any{"status": "active"}); r.StatusCode != 200 {
		t.Fatal("恢复失败")
	}
	_ = loginWith(t, srv.URL, slug, name, "member-pass-1234")
}

// 管理员重置口令：旧令牌失效，旧口令不再可用，新口令可登录。
func TestMemberResetPassword(t *testing.T) {
	srv, pool, slug := setup(t)
	tenantID := tenantOf(t, pool, slug)
	bobToken := login(t, srv.URL, slug)
	bobID := userIDByName(t, slug, "bob")
	seedRole(t, pool, tenantID, bobID, "sysadmin")

	name := uniq("rst")
	if r, b := postJSON(t, srv.URL+"/v1/admin/members", bobToken, map[string]any{
		"username": name, "password": "member-pass-1234",
	}); r.StatusCode != 200 {
		t.Fatalf("建号失败 %d: %v", r.StatusCode, b)
	}
	uid := userIDByName(t, slug, name)
	oldTok := loginWith(t, srv.URL, slug, name, "member-pass-1234")

	if r, b := postJSON(t, srv.URL+"/v1/admin/members/"+uid+"/password", bobToken,
		map[string]any{"password": "brand-new-pass-9876"}); r.StatusCode != 200 {
		t.Fatalf("重置失败 %d: %v", r.StatusCode, b)
	}
	if r, _ := getJSON(t, srv.URL+"/v1/me", oldTok); r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("重置后旧令牌应 401，实际 %d", r.StatusCode)
	}
	if r, _ := postJSON(t, srv.URL+"/v1/auth/login", "", map[string]any{
		"tenantSlug": slug, "username": name, "password": "member-pass-1234",
	}); r.StatusCode == 200 {
		t.Fatal("旧口令不应还能登录")
	}
	_ = loginWith(t, srv.URL, slug, name, "brand-new-pass-9876")
}

// 最后一个可登录管理员不能被停用。
//
// 判定口径是"除目标之外还有没有能登录的管理员"，所以一个**已过期**的管理员不算数：
// 否则停用另一个就把租户彻底锁死了（角色还在，但没人能登录）。
func TestMemberCannotSuspendLastUsableAdmin(t *testing.T) {
	srv, pool, slug := setup(t)
	tenantID := tenantOf(t, pool, slug)

	// 先用 bob（临时管理员）建出 A、B 两个管理员
	bobTok := adminToken(t, srv.URL, pool, slug)
	aName := uniq("admA")
	if r, b := postJSON(t, srv.URL+"/v1/admin/members", bobTok, map[string]any{
		"username": aName, "password": "member-pass-1234", "role": "sysadmin",
	}); r.StatusCode != 200 {
		t.Fatalf("建 A 失败 %d: %v", r.StatusCode, b)
	}
	aID := userIDByName(t, slug, aName)
	bName := uniq("admB")
	if r, b := postJSON(t, srv.URL+"/v1/admin/members", bobTok, map[string]any{
		"username": bName, "password": "member-pass-1234", "role": "sysadmin",
	}); r.StatusCode != 200 {
		t.Fatalf("建 B 失败 %d: %v", r.StatusCode, b)
	}
	bID := userIDByName(t, slug, bName)

	// A 先登录（拿到令牌），再把 A 置为已过期，并撤掉 bob 的管理员角色。
	// 这样"能登录的管理员"只剩 B —— 正是要测的场景。
	aTok := loginWith(t, srv.URL, slug, aName, "member-pass-1234")
	if _, err := pool.Exec(context.Background(),
		`UPDATE app_user SET expires_at = now() - interval '1 day' WHERE id = $1`, aID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(context.Background(),
		`DELETE FROM user_role WHERE tenant_id = $1 AND user_id = $2`, tenantID,
		userIDByName(t, slug, "bob")); err != nil {
		t.Fatal(err)
	}

	resp, body := postJSON(t, srv.URL+"/v1/admin/members/"+bID+"/status", aTok,
		map[string]any{"status": "suspended"})
	if resp.StatusCode != http.StatusConflict || body["code"] != "LAST_ADMIN" {
		t.Fatalf("停用最后一个可用管理员应 409 LAST_ADMIN，实际 %d: %v", resp.StatusCode, body)
	}
}

// ---------------- 平台账号 ----------------

func TestPlatformUserLifecycle(t *testing.T) {
	srv, pool, _ := setup(t)
	email := uniq("ops") + "@example.com"

	resp, body := platJSON(t, http.MethodPost, srv.URL+"/v1/platform/users", map[string]any{
		"email": email, "displayName": "只读运营", "role": "readonly", "password": "platform-pass-1",
	})
	if resp.StatusCode != 200 {
		t.Fatalf("创建平台账号失败 %d: %v", resp.StatusCode, body)
	}
	uid := dataMap(t, body)["id"].(string)
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM platform_user WHERE id = $1`, uid)
	})

	// 只读角色不能建账号
	loginResp, loginBody := postJSON(t, srv.URL+"/v1/platform/auth/login", "", map[string]any{
		"email": email, "password": "platform-pass-1",
	})
	if loginResp.StatusCode != 200 {
		t.Fatalf("平台登录失败 %d: %v", loginResp.StatusCode, loginBody)
	}
	roTok := dataMap(t, loginBody)["accessToken"].(string)

	resp, body = sendJSONMap(t, http.MethodPost, srv.URL+"/v1/platform/users", roTok, map[string]any{
		"email": uniq("no") + "@example.com", "role": "ops", "password": "platform-pass-1",
	})
	if resp.StatusCode != http.StatusForbidden || body["code"] != "READONLY_ROLE" {
		t.Fatalf("只读平台账号建号应 403，实际 %d: %v", resp.StatusCode, body)
	}

	// 静态令牌可停用该账号；停用后其令牌立即失效
	if r, b := platJSON(t, http.MethodPost, srv.URL+"/v1/platform/users/"+uid+"/status",
		map[string]any{"status": "suspended"}); r.StatusCode != 200 {
		t.Fatalf("停用平台账号失败 %d: %v", r.StatusCode, b)
	}
	if r, _ := getJSON(t, srv.URL+"/v1/platform/me", roTok); r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("停用后平台令牌应 401，实际 %d", r.StatusCode)
	}
}

func TestPlatformUserGuards(t *testing.T) {
	srv, pool, _ := setup(t)
	email := uniq("ops") + "@example.com"
	resp, body := platJSON(t, http.MethodPost, srv.URL+"/v1/platform/users", map[string]any{
		"email": email, "role": "ops", "password": "platform-pass-1",
	})
	if resp.StatusCode != 200 {
		t.Fatalf("创建失败 %d: %v", resp.StatusCode, body)
	}
	uid := dataMap(t, body)["id"].(string)
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM platform_user WHERE id = $1`, uid)
	})

	// 用该账号登录，然后尝试停用自己
	_, lb := postJSON(t, srv.URL+"/v1/platform/auth/login", "", map[string]any{
		"email": email, "password": "platform-pass-1",
	})
	tok := dataMap(t, lb)["accessToken"].(string)
	resp, body = sendJSONMap(t, http.MethodPost, srv.URL+"/v1/platform/users/"+uid+"/status", tok,
		map[string]any{"status": "suspended"})
	if resp.StatusCode != http.StatusBadRequest || body["code"] != "SELF_OPERATION" {
		t.Fatalf("停用自己应 400 SELF_OPERATION，实际 %d: %v", resp.StatusCode, body)
	}

	// 弱口令重置
	resp, _ = sendJSONMap(t, http.MethodPost, srv.URL+"/v1/platform/users/"+uid+"/password", tok,
		map[string]any{"password": "short"})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("弱口令应 400，实际 %d", resp.StatusCode)
	}

	// 未知角色
	resp, _ = platJSON(t, http.MethodPost, srv.URL+"/v1/platform/users", map[string]any{
		"email": uniq("x") + "@example.com", "role": "root", "password": "platform-pass-1",
	})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("未知角色应 400，实际 %d", resp.StatusCode)
	}
}
