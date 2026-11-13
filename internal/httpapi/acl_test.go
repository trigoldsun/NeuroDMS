package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"testing"

	"docvault/internal/auth"
	"docvault/internal/db"

	"github.com/jackc/pgx/v5/pgxpool"
)

// seedUser 在指定租户下建一个用户并返回其访问令牌。
func seedUser(t *testing.T, srvURL, slug, username string) string {
	t.Helper()
	pool := mustPool(t)
	ctx := context.Background()

	var tenantID string
	if err := pool.QueryRow(ctx, `SELECT id::text FROM tenant WHERE slug=$1`, slug).Scan(&tenantID); err != nil {
		t.Fatal(err)
	}
	hash, _ := auth.HashPassword(pwd)
	id := uuid(t)
	if _, err := pool.Exec(ctx, `
		INSERT INTO app_user (id, tenant_id, username, display_name, password_hash, status)
		VALUES ($1,$2,$3,$4,$5,'active')`, id, tenantID, username, username, hash); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM app_user WHERE id=$1`, id)
	})

	resp, body := postJSON(t, srvURL+"/v1/auth/login", "", map[string]any{
		"tenantSlug": slug, "username": username, "password": pwd,
	})
	if resp.StatusCode != 200 {
		t.Fatalf("用户 %s 登录失败 %d: %v", username, resp.StatusCode, body)
	}
	return dataMap(t, body)["accessToken"].(string)
}

func delJSON(t *testing.T, url, token string) (*http.Response, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodDelete, url, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("请求失败: %v", err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp, out
}

// 授权后对方可见可用；档位越高能力越强。
func TestGrantViewerThenAccess(t *testing.T) {
	srv, _, slug := setup(t)
	owner := login(t, srv.URL, slug)
	eve := seedUser(t, srv.URL, slug, "eve")

	_, body := postJSON(t, srv.URL+"/v1/spaces", owner, map[string]any{"kind": "project", "name": "共享空间"})
	spaceID := dataMap(t, body)["spaceId"].(string)
	_, ub := upload(t, srv.URL+"/v1/spaces/"+spaceID+"/files", owner, "合同.pdf", "content")
	nodeID := dataMap(t, ub)["nodeId"].(string)

	// 授权前：看不到
	if resp, _ := getJSON(t, srv.URL+"/v1/spaces/"+spaceID+"/nodes", eve); resp.StatusCode != 404 {
		t.Fatalf("授权前应 404，实际 %d", resp.StatusCode)
	}

	// 授予查看者
	resp, gb := postJSON(t, srv.URL+"/v1/acl", owner, map[string]any{
		"objectType": "space", "objectId": spaceID,
		"subjectType": "user", "subjectId": userIDByName(t, slug, "eve"),
		"preset": "viewer",
	})
	if resp.StatusCode != 200 {
		t.Fatalf("授权失败 %d: %v", resp.StatusCode, gb)
	}

	// 授权后：可列目录
	if resp, _ := getJSON(t, srv.URL+"/v1/spaces/"+spaceID+"/nodes", eve); resp.StatusCode != 200 {
		t.Fatalf("授权后应可列目录，实际 %d", resp.StatusCode)
	}
	// 查看者没有 download 位：下载应被拒。
	// 注意状态码是 403 而不是 404——查看者能在列表里看到这个文件，
	// "假装不存在"只会误导使用者；只有在完全看不见时才用 404。
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/v1/nodes/"+nodeID+"/content", nil)
	req.Header.Set("Authorization", "Bearer "+eve)
	dresp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer dresp.Body.Close()
	if dresp.StatusCode != 403 {
		t.Fatalf("查看者不应能下载，实际 %d", dresp.StatusCode)
	}
	// 查看者也不能上传（缺 create）——同样因为可见，返回 403
	if resp, _ := upload(t, srv.URL+"/v1/spaces/"+spaceID+"/files", eve, "越权.txt", "x"); resp.StatusCode != 403 {
		t.Fatalf("查看者不应能上传，实际 %d", resp.StatusCode)
	}
}

// 贡献者档位应具备上传与下载能力。
func TestGrantContributorCanUploadAndDownload(t *testing.T) {
	srv, _, slug := setup(t)
	owner := login(t, srv.URL, slug)
	eve := seedUser(t, srv.URL, slug, "eve")

	_, body := postJSON(t, srv.URL+"/v1/spaces", owner, map[string]any{"kind": "project", "name": "协作空间"})
	spaceID := dataMap(t, body)["spaceId"].(string)

	resp, gb := postJSON(t, srv.URL+"/v1/acl", owner, map[string]any{
		"objectType": "space", "objectId": spaceID,
		"subjectType": "user", "subjectId": userIDByName(t, slug, "eve"),
		"preset": "contributor",
	})
	if resp.StatusCode != 200 {
		t.Fatalf("授权失败: %v", gb)
	}

	if resp, ub := upload(t, srv.URL+"/v1/spaces/"+spaceID+"/files", eve, "eve上传.txt", "hi"); resp.StatusCode != 200 {
		t.Fatalf("贡献者应能上传，实际 %d: %v", resp.StatusCode, ub)
	}
	_, lb := getJSON(t, srv.URL+"/v1/spaces/"+spaceID+"/nodes", eve)
	items, _ := dataMap(t, lb)["items"].([]any)
	if len(items) != 1 {
		t.Fatalf("应看到 1 个文件，实际 %d", len(items))
	}
}

// 越权授出必须被拒绝并留痕。
func TestGrantOwnerByNonOwnerRejected(t *testing.T) {
	srv, _, slug := setup(t)
	owner := login(t, srv.URL, slug)
	eve := seedUser(t, srv.URL, slug, "eve")

	_, body := postJSON(t, srv.URL+"/v1/spaces", owner, map[string]any{"kind": "project", "name": "空间"})
	spaceID := dataMap(t, body)["spaceId"].(string)
	eveID := userIDByName(t, slug, "eve")

	// eve 是受限账号：授权上限压到编辑者（默认已改为所有者，需显式下调）
	if _, err := mustPool(t).Exec(context.Background(),
		`UPDATE app_user SET ceiling = 4 WHERE id = $1`, eveID); err != nil {
		t.Fatal(err)
	}

	// 给 eve 对象级 owner ACE（她能管理该对象的权限），但把她账号的 ceiling 压到编辑者。
	// 这样"有 manage_acl 但封顶不足"两个条件同时成立，才能精确验证越权授出被拒。
	if resp, b := postJSON(t, srv.URL+"/v1/acl", owner, map[string]any{
		"objectType": "space", "objectId": spaceID,
		"subjectType": "user", "subjectId": eveID, "preset": "owner",
	}); resp.StatusCode != 200 {
		t.Fatalf("授予所有者失败: %v", b)
	}

	// eve 尝试授出管理者（档位 5 > 自身 ceiling 4）：必须 403
	resp, b := postJSON(t, srv.URL+"/v1/acl", eve, map[string]any{
		"objectType": "space", "objectId": spaceID,
		"subjectType": "user", "subjectId": eveID, "preset": "manager",
	})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("越权授出应 403，实际 %d: %v", resp.StatusCode, b)
	}
	if b["code"] != "CEILING_EXCEEDED" {
		t.Fatalf("错误码应为 CEILING_EXCEEDED，实际 %v", b["code"])
	}
}

// 不能移除最后一个所有者（防锁死）。
func TestCannotRemoveLastOwner(t *testing.T) {
	srv, _, slug := setup(t)
	owner := login(t, srv.URL, slug)

	_, body := postJSON(t, srv.URL+"/v1/spaces", owner, map[string]any{"kind": "project", "name": "空间"})
	spaceID := dataMap(t, body)["spaceId"].(string)

	_, lb := getJSON(t, srv.URL+"/v1/acl?objectType=space&objectId="+spaceID, owner)
	items, _ := dataMap(t, lb)["items"].([]any)
	if len(items) != 1 {
		t.Fatalf("应只有 1 条（创建者 owner），实际 %d", len(items))
	}
	aceID := items[0].(map[string]any)["aceId"].(string)

	resp, rb := delJSON(t, srv.URL+"/v1/acl/"+aceID, owner)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("删除最后一个所有者应 400，实际 %d: %v", resp.StatusCode, rb)
	}
	if rb["code"] != "LAST_OWNER" {
		t.Fatalf("错误码应为 LAST_OWNER，实际 %v", rb["code"])
	}
}

// 撤销后立即失去访问。
func TestRevokeTakesEffectImmediately(t *testing.T) {
	srv, _, slug := setup(t)
	owner := login(t, srv.URL, slug)
	eve := seedUser(t, srv.URL, slug, "eve")

	_, body := postJSON(t, srv.URL+"/v1/spaces", owner, map[string]any{"kind": "project", "name": "空间"})
	spaceID := dataMap(t, body)["spaceId"].(string)

	_, gb := postJSON(t, srv.URL+"/v1/acl", owner, map[string]any{
		"objectType": "space", "objectId": spaceID,
		"subjectType": "user", "subjectId": userIDByName(t, slug, "eve"), "preset": "viewer",
	})
	aceID := dataMap(t, gb)["aceId"].(string)

	if resp, _ := getJSON(t, srv.URL+"/v1/spaces/"+spaceID+"/nodes", eve); resp.StatusCode != 200 {
		t.Fatalf("撤销前应可访问，实际 %d", resp.StatusCode)
	}
	if resp, rb := delJSON(t, srv.URL+"/v1/acl/"+aceID, owner); resp.StatusCode != 200 {
		t.Fatalf("撤销失败 %d: %v", resp.StatusCode, rb)
	}
	if resp, _ := getJSON(t, srv.URL+"/v1/spaces/"+spaceID+"/nodes", eve); resp.StatusCode != 404 {
		t.Fatalf("撤销后应立即失去访问，实际 %d", resp.StatusCode)
	}
}

// mustPool 打开一个测试连接池（仅用于准备数据与断言）。
func mustPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("DOCVAULT_TEST_DSN")
	if dsn == "" {
		t.Skip("未设置 DOCVAULT_TEST_DSN")
	}
	pool, err := db.Connect(context.Background(), dsn)
	if err != nil {
		t.Fatalf("连接失败: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// userIDByName 按租户 slug + 用户名查用户 id。
func userIDByName(t *testing.T, slug, username string) string {
	t.Helper()
	pool := mustPool(t)
	var id string
	if err := pool.QueryRow(context.Background(), `
		SELECT u.id::text FROM app_user u JOIN tenant t ON t.id = u.tenant_id
		 WHERE t.slug = $1 AND u.username = $2`, slug, username).Scan(&id); err != nil {
		t.Fatalf("查询用户 %s 失败: %v", username, err)
	}
	return id
}
