package httpapi

// 外部用户生命周期（AC-59 / AC-60 / AC-64）。

import (
	"context"
	"net/http"
	"testing"

	"docvault/internal/authz"
	"docvault/internal/rbac"
)

// AC-59：外部用户是独立主体类型——给内部用户授的权限不会自动落到外部用户身上。
func TestAC59ExternalIsDistinctSubject(t *testing.T) {
	srv, pool, slug := setup(t)
	owner := login(t, srv.URL, slug)
	spaceID, nodeID := prepareFile(t, srv.URL, owner)
	tenantID := tenantOf(t, pool, slug)

	ext := seedUser(t, srv.URL, slug, "ext59")
	extID := userIDByName(t, slug, "ext59")
	// 关键：ACE 里记的是 user:<id>。把账号类型改成 external 后，
	// 主体键变成 external:<id>，原来那条授权不应再命中。
	grantBits(t, pool, tenantID, "node", nodeID, extID, int64(authz.PresetEditor.Bits()))

	// 先确认类型为 internal 时可用
	if r, raw := getJSON(t, srv.URL+"/v1/nodes/"+nodeID, ext); r.StatusCode != 200 {
		t.Fatalf("内部类型应可见，实际 %d: %s", r.StatusCode, raw)
	}

	// 改成外部用户：原来的 user: 授权不再命中 → 看不到
	if _, err := pool.Exec(context.Background(),
		`UPDATE app_user SET principal_type = 'external' WHERE id = $1`, extID); err != nil {
		t.Fatal(err)
	}
	if r, raw := getRaw(t, srv.URL+"/v1/nodes/"+nodeID+"/content", ext); r.StatusCode == 200 {
		t.Fatalf("AC-59 外部类型不应继承内部类型的授权: %s", raw)
	}

	// 显式给 external 主体授权后应可用
	if _, err := pool.Exec(context.Background(), `
		INSERT INTO ace (id, tenant_id, object_type, object_id, subject_type, subject_id, allow_bits, granted_by)
		VALUES (gen_random_uuid(), $1, 'node', $2, 'external', $3, $4, $3)`,
		tenantID, nodeID, extID, int64(authz.PresetEditor.Bits())); err != nil {
		t.Fatal(err)
	}
	if r, raw := getJSON(t, srv.URL+"/v1/nodes/"+nodeID, ext); r.StatusCode != 200 {
		t.Fatalf("AC-59 显式 external 授权后应可见，实际 %d: %s", r.StatusCode, raw)
	}
	_ = spaceID
}

// AC-60：外部账号过期后不能再登录。
func TestAC60ExpiredExternalCannotLogin(t *testing.T) {
	srv, pool, slug := setup(t)
	tenantID := tenantOf(t, pool, slug)
	bobID := userIDByName(t, slug, "bob")
	seedRole(t, pool, tenantID, bobID, rbac.SysAdmin)
	bobToken := login(t, srv.URL, slug)

	seedUser(t, srv.URL, slug, "ext60")
	extID := userIDByName(t, slug, "ext60")
	if _, err := pool.Exec(context.Background(),
		`UPDATE app_user SET principal_type='external' WHERE id=$1`, extID); err != nil {
		t.Fatal(err)
	}
	// 先确认能登录
	if resp, _ := postJSON(t, srv.URL+"/v1/auth/login", "", map[string]any{
		"tenantSlug": slug, "username": "ext60", "password": pwd,
	}); resp.StatusCode != 200 {
		t.Fatalf("过期前应能登录，实际 %d", resp.StatusCode)
	}

	// 管理员设置为已过期
	resp, out := sendJSONMap(t, http.MethodPost, srv.URL+"/v1/admin/users/"+extID+"/expiry", bobToken,
		map[string]any{"expiresAt": "2020-01-01T00:00:00Z"})
	if resp.StatusCode != 200 {
		t.Fatalf("设置有效期失败 %d: %v", resp.StatusCode, out)
	}

	resp, out = postJSON(t, srv.URL+"/v1/auth/login", "", map[string]any{
		"tenantSlug": slug, "username": "ext60", "password": pwd,
	})
	if resp.StatusCode == 200 {
		t.Fatalf("AC-60 过期账号不应能登录: %v", out)
	}
	if resp.StatusCode != http.StatusForbidden && resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("AC-60 期望 401/403，实际 %d: %v", resp.StatusCode, out)
	}
}

// AC-64：账号删除后，已签发的令牌必须立刻失效（不能靠"等它过期"）。
func TestAC64DeletedUserTokenInvalidated(t *testing.T) {
	srv, pool, slug := setup(t)
	tenantID := tenantOf(t, pool, slug)
	bobID := userIDByName(t, slug, "bob")
	seedRole(t, pool, tenantID, bobID, rbac.SysAdmin)
	bobToken := login(t, srv.URL, slug)

	victim := seedUser(t, srv.URL, slug, "ext64")
	victimID := userIDByName(t, slug, "ext64")
	// 删除前确认令牌可用
	if r, raw := getJSON(t, srv.URL+"/v1/me", victim); r.StatusCode != 200 {
		t.Fatalf("删除前应可用，实际 %d: %s", r.StatusCode, raw)
	}

	resp, out := delJSON(t, srv.URL+"/v1/admin/users/"+victimID, bobToken)
	if resp.StatusCode != 200 {
		t.Fatalf("删除账号失败 %d: %v", resp.StatusCode, out)
	}

	// 旧令牌立即失效
	if r, raw := getJSON(t, srv.URL+"/v1/me", victim); r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("AC-64 删除后旧令牌应 401，实际 %d: %s", r.StatusCode, raw)
	}

	// 也不能再登录
	if r, _ := postJSON(t, srv.URL+"/v1/auth/login", "", map[string]any{
		"tenantSlug": slug, "username": "ext64", "password": pwd,
	}); r.StatusCode == 200 {
		t.Fatal("AC-64 删除后不应能登录")
	}
}
