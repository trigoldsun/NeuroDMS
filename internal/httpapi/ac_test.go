package httpapi

// 本文件把《越权与安全用例集 v1.0》里可在 M1 验证的用例落成可执行测试。
//
// 约定：测试名带 AC 编号，便于 scripts/ac-gate.sh 做"用例 → 测试"的追溯。
// 一条 AC 若需要多个场景，用子测试区分，但主测试名必须含编号。

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"docvault/internal/auth"
	"docvault/internal/authz"
	"docvault/internal/dbtest"

	"github.com/jackc/pgx/v5/pgxpool"
)

// grantBits 直接写一条 ACE。
//
// 为什么绕过 API：部分用例需要构造"只有 display 没有 preview"这类
// 界面上不存在的组合（界面只暴露 6 个档位）。这是刻意的：
// 权限引擎必须对任意位组合正确，而不只是对档位正确。
func grantBits(t *testing.T, pool *pgxpool.Pool, tenantID, objectType, objectID, userID string, bits int64) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), `
		INSERT INTO ace (id, tenant_id, object_type, object_id, subject_type, subject_id, allow_bits, granted_by)
		VALUES (gen_random_uuid(), $1, $2, $3, 'user', $4, $5, $4)
		ON CONFLICT (tenant_id, object_type, object_id, subject_type,
		             COALESCE(subject_id, '00000000-0000-0000-0000-000000000000'::uuid))
		DO UPDATE SET allow_bits = EXCLUDED.allow_bits`,
		tenantID, objectType, objectID, userID, bits); err != nil {
		t.Fatalf("写入 ACE 失败: %v", err)
	}
}

// prepareFile 建空间并上传一个文件，返回 nodeID 与空间 ID。
func prepareFile(t *testing.T, srvURL, token string) (spaceID, nodeID string) {
	t.Helper()
	_, body := postJSON(t, srvURL+"/v1/spaces", token, map[string]any{"kind": "project", "name": "AC 用例空间"})
	spaceID = dataMap(t, body)["spaceId"].(string)
	_, up := upload(t, srvURL+"/v1/spaces/"+spaceID+"/files", token, "report.txt", "敏感内容-不得泄漏")
	nodeID = dataMap(t, up)["nodeId"].(string)
	return spaceID, nodeID
}

// assertNoLeak 断言响应体不含对象名——只测状态码是"假测试"。
func assertNoLeak(t *testing.T, raw []byte, secret string) {
	t.Helper()
	if strings.Contains(string(raw), secret) {
		t.Fatalf("响应体泄漏了对象信息: %s", string(raw))
	}
}

// AC-16：只有 display 时不能预览。
func TestAC16PreviewDeniedWithoutPreviewBit(t *testing.T) {
	srv, pool, slug := setup(t)
	owner := login(t, srv.URL, slug)
	spaceID, nodeID := prepareFile(t, srv.URL, owner)

	eve := seedUser(t, srv.URL, slug, "eve16")
	tenantID := tenantOf(t, pool, slug)
	grantBits(t, pool, tenantID, "node", nodeID, userIDByName(t, slug, "eve16"), int64(authz.Display))

	resp, raw := getRaw(t, srv.URL+"/v1/nodes/"+nodeID+"/preview", eve)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("AC-16 只读不可预览，期望 403，实际 %d: %s", resp.StatusCode, raw)
	}
	assertNoLeak(t, raw, "敏感内容")
	assertNoLeak(t, raw, "report.txt")
	_ = spaceID
}

// AC-17：只有 display+preview 时不能下载原文件。
func TestAC17DownloadDeniedWithoutDownloadBit(t *testing.T) {
	srv, pool, slug := setup(t)
	owner := login(t, srv.URL, slug)
	_, nodeID := prepareFile(t, srv.URL, owner)

	eve := seedUser(t, srv.URL, slug, "eve17")
	tenantID := tenantOf(t, pool, slug)
	grantBits(t, pool, tenantID, "node", nodeID, userIDByName(t, slug, "eve17"),
		int64(authz.Display|authz.Preview))

	resp, raw := getRaw(t, srv.URL+"/v1/nodes/"+nodeID+"/content", eve)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("AC-17 可预览不可下载，期望 403，实际 %d: %s", resp.StatusCode, raw)
	}
	assertNoLeak(t, raw, "敏感内容")
}

// AC-18：只有 preview 时不能改名（缺 edit）。
func TestAC18RenameDeniedWithoutEditBit(t *testing.T) {
	srv, pool, slug := setup(t)
	owner := login(t, srv.URL, slug)
	_, nodeID := prepareFile(t, srv.URL, owner)

	eve := seedUser(t, srv.URL, slug, "eve18")
	tenantID := tenantOf(t, pool, slug)
	grantBits(t, pool, tenantID, "node", nodeID, userIDByName(t, slug, "eve18"),
		int64(authz.Display|authz.Preview))

	resp, raw := sendJSON(t, http.MethodPatch, srv.URL+"/v1/nodes/"+nodeID, eve,
		map[string]any{"name": "改名.txt"})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("AC-18 缺 edit 应 403，实际 %d: %s", resp.StatusCode, raw)
	}
	// 反向确认：名字真的没变
	meta, body := getJSON(t, srv.URL+"/v1/nodes/"+nodeID, owner)
	if meta.StatusCode != 200 || dataMap(t, body)["name"].(string) != "report.txt" {
		t.Fatalf("AC-18 拒绝后名字被改了: %v", body)
	}
}

// AC-19：只有 edit 时不能删除（缺 delete）。
func TestAC19DeleteDeniedWithoutDeleteBit(t *testing.T) {
	srv, pool, slug := setup(t)
	owner := login(t, srv.URL, slug)
	_, nodeID := prepareFile(t, srv.URL, owner)

	eve := seedUser(t, srv.URL, slug, "eve19")
	tenantID := tenantOf(t, pool, slug)
	grantBits(t, pool, tenantID, "node", nodeID, userIDByName(t, slug, "eve19"),
		int64(authz.Display|authz.Edit))

	resp, raw := sendJSON(t, http.MethodDelete, srv.URL+"/v1/nodes/"+nodeID, eve, nil)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("AC-19 缺 delete 应 403，实际 %d: %s", resp.StatusCode, raw)
	}
	// 对象必须仍然可访问
	if r, _ := getJSON(t, srv.URL+"/v1/nodes/"+nodeID, owner); r.StatusCode != 200 {
		t.Fatal("AC-19 拒绝后对象却消失了")
	}
}

// AC-20：有 move 但目标目录没有 create → 403。
func TestAC20MoveDeniedWhenTargetHasNoCreate(t *testing.T) {
	srv, pool, slug := setup(t)
	owner := login(t, srv.URL, slug)
	spaceID, nodeID := prepareFile(t, srv.URL, owner)

	// owner 建一个目标目录
	_, fb := postJSON(t, srv.URL+"/v1/spaces/"+spaceID+"/folders", owner,
		map[string]any{"name": "目标目录"})
	folderID := dataMap(t, fb)["folderId"].(string)

	eve := seedUser(t, srv.URL, slug, "eve20")
	tenantID := tenantOf(t, pool, slug)
	// 只给 Move|Display：能移动源对象，但目标目录上没有 create
	grantBits(t, pool, tenantID, "node", nodeID, userIDByName(t, slug, "eve20"),
		int64(authz.Display|authz.Move))

	resp, raw := sendJSON(t, http.MethodPost, srv.URL+"/v1/nodes/"+nodeID+"/move", eve,
		map[string]any{"parentId": folderID})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("AC-20 目标无 create 应 403，实际 %d: %s", resp.StatusCode, raw)
	}
}

// AC-21：只有 create 时不能移动别人的文件（缺源侧 move）。
//
// 注意与用例集原文的差异：原文期望 403，这里断言 404。
// 原因是此时用户对源对象连 display 都没有，"承认它存在"本身就是信息泄漏；
// 另一个子用例（有 display 但无 move）覆盖了 403 的路径。
func TestAC21MoveDeniedWithoutMoveOnSource(t *testing.T) {
	srv, pool, slug := setup(t)
	owner := login(t, srv.URL, slug)
	spaceID, nodeID := prepareFile(t, srv.URL, owner)

	// 子场景 1：只有 create（看不到源对象）→ 404
	eve := seedUser(t, srv.URL, slug, "eve21a")
	tenantID := tenantOf(t, pool, slug)
	grantBits(t, pool, tenantID, "space", spaceID, userIDByName(t, slug, "eve21a"), int64(authz.Create))

	resp, raw := sendJSON(t, http.MethodPost, srv.URL+"/v1/nodes/"+nodeID+"/move", eve,
		map[string]any{"parentId": spaceID})
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("AC-21 无任何可见性时应 404（不泄漏存在性），实际 %d: %s", resp.StatusCode, raw)
	}

	// 子场景 2：有 display|create 但无 move → 403
	frank := seedUser(t, srv.URL, slug, "eve21b")
	grantBits(t, pool, tenantID, "space", spaceID, userIDByName(t, slug, "eve21b"),
		int64(authz.Display|authz.Create))
	resp2, raw2 := sendJSON(t, http.MethodPost, srv.URL+"/v1/nodes/"+nodeID+"/move", frank,
		map[string]any{"parentId": spaceID})
	if resp2.StatusCode != http.StatusForbidden {
		t.Fatalf("AC-21 有可见性但缺 move 应 403，实际 %d: %s", resp2.StatusCode, raw2)
	}
}

// AC-25：无任何权限时读元数据返回 404，不泄漏存在性。
func TestAC25MetaReturns404WithoutAnyACE(t *testing.T) {
	srv, _, slug := setup(t)
	owner := login(t, srv.URL, slug)
	_, nodeID := prepareFile(t, srv.URL, owner)

	eve := seedUser(t, srv.URL, slug, "eve25")
	resp, raw := getRaw(t, srv.URL+"/v1/nodes/"+nodeID, eve)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("AC-25 无权限应 404，实际 %d: %s", resp.StatusCode, raw)
	}
	assertNoLeak(t, raw, "report.txt")
}

// AC-36：不允许手工给匿名主体授权。
func TestAC36AnonymousGrantRejected(t *testing.T) {
	srv, _, slug := setup(t)
	owner := login(t, srv.URL, slug)
	spaceID, _ := prepareFile(t, srv.URL, owner)

	resp, raw := postJSON(t, srv.URL+"/v1/acl", owner, map[string]any{
		"objectType": "space", "objectId": spaceID,
		"subjectType": "anonymous", "preset": "viewer",
	})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("AC-36 匿名授权应 400，实际 %d: %s", resp.StatusCode, raw)
	}
}

// AC-49：口令连续错误 6 次后链接锁定；锁定期间正确口令也不放行。
func TestAC49SharePasswordLocksAfterSixAttempts(t *testing.T) {
	srv, _, slug := setup(t)
	owner := login(t, srv.URL, slug)
	_, nodeID := prepareFile(t, srv.URL, owner)

	_, sb := postJSON(t, srv.URL+"/v1/shares", owner, map[string]any{
		"objectType": "node", "objectId": nodeID,
		"expiresInHours": 1, "allowDownload": true, "password": "join-2026",
	})
	token := dataMap(t, sb)["token"].(string)

	wrong := func() int {
		req, _ := http.NewRequest(http.MethodGet, srv.URL+"/v1/public/shares/"+token, nil)
		req.Header.Set("X-Share-Password", "not-the-password")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		return resp.StatusCode
	}

	for i := 1; i <= 5; i++ {
		if code := wrong(); code != http.StatusForbidden {
			t.Fatalf("AC-49 第 %d 次错误口令应 403，实际 %d", i, code)
		}
	}
	if code := wrong(); code != http.StatusTooManyRequests {
		t.Fatalf("AC-49 第 6 次应触发锁定（429），实际 %d", code)
	}

	// 锁定后用正确口令也必须被拒
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/v1/public/shares/"+token, nil)
	req.Header.Set("X-Share-Password", "join-2026")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("AC-49 锁定期间正确口令也应被拒，实际 %d", resp.StatusCode)
	}
}

// AC-58：robots.txt 禁止抓取。
func TestAC58RobotsDisallowAll(t *testing.T) {
	srv, _, _ := setup(t)
	resp, err := http.Get(srv.URL + "/robots.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(resp.Body)
	body := buf.String()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("robots.txt 应 200，实际 %d", resp.StatusCode)
	}
	if !strings.Contains(body, "Disallow: /") {
		t.Fatalf("robots.txt 应禁止全站抓取，实际: %s", body)
	}
}

// AC-65：双扩展名（shell.php.jpg）拒绝。
func TestAC65DoubleExtensionRejected(t *testing.T) {
	srv, _, slug := setup(t)
	owner := login(t, srv.URL, slug)
	spaceID := ensureSpace(t, srv.URL, owner)

	for _, name := range []string{"shell.php.jpg", "x.jsp.png", "a.exe.txt", "b.ps1.log"} {
		resp, body := upload(t, srv.URL+"/v1/spaces/"+spaceID+"/files", owner, name, "harmless")
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("AC-65 %s 应被拒（400），实际 %d: %v", name, resp.StatusCode, body)
		}
	}

	// 正常名字必须仍然可传（避免"一刀切把功能拦死"）
	if resp, body := upload(t, srv.URL+"/v1/spaces/"+spaceID+"/files", owner, "report.v2.final.pdf", "ok"); resp.StatusCode != 200 {
		t.Fatalf("正常多扩展名文件应允许，实际 %d: %v", resp.StatusCode, body)
	}
}

// AC-66：超限返回 413，且不产生半个 blob。
func TestAC66OversizeRejectedWithoutBlob(t *testing.T) {
	srv, pool, slug := setup(t)
	owner := login(t, srv.URL, slug)
	spaceID := ensureSpace(t, srv.URL, owner)
	tenantID := tenantOf(t, pool, slug)

	old := maxUploadBytes
	maxUploadBytes = 64
	t.Cleanup(func() { maxUploadBytes = old })

	resp, body := upload(t, srv.URL+"/v1/spaces/"+spaceID+"/files", owner, "big.bin",
		strings.Repeat("A", 1024))
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("AC-66 超限应 413，实际 %d: %v", resp.StatusCode, body)
	}

	var blobs int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM blob WHERE tenant_id = $1`, tenantID).Scan(&blobs); err != nil {
		t.Fatal(err)
	}
	if blobs != 0 {
		t.Fatalf("AC-66 超限不应留下 blob，实际 %d 条", blobs)
	}
}

// AC-68：伪造 MIME 的可执行文件按魔数拒绝。
func TestAC68ExecutableContentRejected(t *testing.T) {
	srv, _, slug := setup(t)
	owner := login(t, srv.URL, slug)
	spaceID := ensureSpace(t, srv.URL, owner)

	// 声明成文本，但内容以 MZ（PE）与 ELF 开头
	cases := []struct{ name, content string }{
		{"totally-safe.txt", "MZ\x90\x00\x03\x00\x00\x00"},
		{"report.pdf", "\x7fELF\x02\x01\x01\x00"},
	}
	for _, c := range cases {
		resp, body := upload(t, srv.URL+"/v1/spaces/"+spaceID+"/files", owner, c.name, c.content)
		if resp.StatusCode != http.StatusUnsupportedMediaType {
			t.Fatalf("AC-68 %s 应 415，实际 %d: %v", c.name, resp.StatusCode, body)
		}
	}
}

// AC-73：/metrics 需要独立令牌，用户会话令牌无效。
func TestAC73MetricsRequiresOwnToken(t *testing.T) {
	const token = "metrics-scrape-token-32bytes-long"
	srv, _, slug := setupWith(t, func(a *API) { a.MetricsToken = token })
	user := login(t, srv.URL, slug)

	// 无令牌
	if resp, _ := getRaw(t, srv.URL+"/metrics", ""); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("AC-73 无令牌应 401，实际 %d", resp.StatusCode)
	}
	// 用普通用户令牌
	if resp, _ := getRaw(t, srv.URL+"/metrics", user); resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("AC-73 用户令牌不该能读指标，实际 %d", resp.StatusCode)
	}
	// 正确令牌
	resp, raw := getRaw(t, srv.URL+"/metrics", token)
	if resp.StatusCode != http.StatusOK || !strings.Contains(string(raw), "docvault_up 1") {
		t.Fatalf("AC-73 正确令牌应 200 且含指标，实际 %d: %s", resp.StatusCode, raw)
	}
}

// ---------------------------------------------------------------- 辅助

// getRaw 发起带令牌的 GET，返回响应与原始响应体（用于断言"不泄漏"）。
func getRaw(t *testing.T, url, token string) (*http.Response, []byte) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("请求失败: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(resp.Body)
	return resp, buf.Bytes()
}

// sendJSON 发起任意方法的 JSON 请求。
func sendJSON(t *testing.T, method, url, token string, body any) (*http.Response, []byte) {
	t.Helper()
	var rd *bytes.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		rd = bytes.NewReader(raw)
	} else {
		rd = bytes.NewReader(nil)
	}
	req, err := http.NewRequest(method, url, rd)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("请求失败: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	var buf bytes.Buffer
	_, _ = buf.ReadFrom(resp.Body)
	return resp, buf.Bytes()
}

// AC-09 / AC-10 / AC-12：跨租户访问一律不可见，且 tenant 参数不能覆盖上下文。
func TestAC09CrossTenantInvisible(t *testing.T) {
	srv, pool, slugA := setup(t)
	ownerA := login(t, srv.URL, slugA)
	spaceA, nodeA := prepareFile(t, srv.URL, ownerA)

	// 造一个独立租户 B 与其用户
	ctx := context.Background()
	tenantB, userB := uuid(t), uuid(t)
	slugB := "httpb-" + tenantB[:8]
	if _, err := pool.Exec(ctx, `INSERT INTO tenant (id, slug, name) VALUES ($1,$2,$3)`,
		tenantB, slugB, "B 租户"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { dbtestCleanup(t, pool, tenantB) })
	hash, _ := hashPassword()
	if _, err := pool.Exec(ctx, `
		INSERT INTO app_user (id, tenant_id, username, display_name, password_hash, status)
		VALUES ($1,$2,'bob','Bob',$3,'active')`, userB, tenantB, hash); err != nil {
		t.Fatal(err)
	}
	tokenB := login(t, srv.URL, slugB)

	// AC-09：直接请求 A 的 nodeId
	if resp, raw := getRaw(t, srv.URL+"/v1/nodes/"+nodeA, tokenB); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("AC-09 跨租户读节点应 404，实际 %d: %s", resp.StatusCode, raw)
	}
	if resp, raw := getRaw(t, srv.URL+"/v1/nodes/"+nodeA+"/content", tokenB); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("AC-09 跨租户下载应 404，实际 %d: %s", resp.StatusCode, raw)
	}

	// AC-10：列表传 A 的 spaceId
	if resp, raw := getRaw(t, srv.URL+"/v1/spaces/"+spaceA+"/nodes", tokenB); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("AC-10 跨租户列目录应 404，实际 %d: %s", resp.StatusCode, raw)
	}

	// AC-12：用查询参数试图覆盖租户上下文
	if resp, raw := getRaw(t, srv.URL+"/v1/nodes/"+nodeA+"?tenant_id="+tenantB+"&tenantId="+tenantB, tokenB); resp.StatusCode != http.StatusNotFound {
		t.Fatalf("AC-12 查询参数不得覆盖租户上下文，实际 %d: %s", resp.StatusCode, raw)
	}
}

// AC-23：没有 share_external 位不能创建外链。
//
// 这条此前是真实漏洞：分享创建完全不校验权限位，
// 任何"能看见文件"的人都能生成公开链接，把 download 放大成全网可访问。
func TestAC23ShareRequiresExternalBit(t *testing.T) {
	srv, pool, slug := setup(t)
	owner := login(t, srv.URL, slug)
	_, nodeID := prepareFile(t, srv.URL, owner)

	reader := seedUser(t, srv.URL, slug, "eve23")
	tenantID := tenantOf(t, pool, slug)
	// 能看、能下载，但没有 share_external
	grantBits(t, pool, tenantID, "node", nodeID, userIDByName(t, slug, "eve23"),
		int64(authz.Display|authz.Preview|authz.Download))

	resp, raw := postJSON(t, srv.URL+"/v1/shares", reader, map[string]any{
		"objectType": "node", "objectId": nodeID, "allowDownload": true,
	})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("AC-23 缺 share_external 应 403，实际 %d: %s", resp.StatusCode, raw)
	}

	// 反向确认：有 share_external 的用户可以创建
	grantBits(t, pool, tenantID, "node", nodeID, userIDByName(t, slug, "eve23"),
		int64(authz.Display|authz.Preview|authz.Download|authz.ShareExternal))
	resp2, raw2 := postJSON(t, srv.URL+"/v1/shares", reader, map[string]any{
		"objectType": "node", "objectId": nodeID, "allowDownload": true,
	})
	if resp2.StatusCode != 200 {
		t.Fatalf("有 share_external 应允许创建，实际 %d: %s", resp2.StatusCode, raw2)
	}
}

// dbtestCleanup 包一层，避免本文件直接依赖 dbtest 的 testing 接口差异。
func dbtestCleanup(t *testing.T, pool *pgxpool.Pool, tenantID string) {
	t.Helper()
	dbtest.CleanupTenant(t, pool, tenantID)
}

func hashPassword() (string, error) {
	return auth.HashPassword(pwd)
}

// AC-54：仅预览分享不能取回原始字节。
func TestAC54PreviewOnlyShareCannotDownload(t *testing.T) {
	srv, _, slug := setup(t)
	owner := login(t, srv.URL, slug)
	_, nodeID := prepareFile(t, srv.URL, owner)

	_, sb := postJSON(t, srv.URL+"/v1/shares", owner, map[string]any{
		"objectType": "node", "objectId": nodeID,
		"expiresInHours": 1, "allowDownload": false,
	})
	token := dataMap(t, sb)["token"].(string)

	_, rb := getJSON(t, srv.URL+"/v1/public/shares/"+token, "")
	ticket := dataMap(t, rb)["ticket"].(string)

	// 行内预览（图片/文本）允许，但"下载原始字节"必须被拒
	resp, raw := getRaw(t, srv.URL+"/v1/public/tickets/"+ticket+"/content?download=1", "")
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("AC-54 allowDownload=false 时下载应 403，实际 %d: %s", resp.StatusCode, raw)
	}
	assertNoLeak(t, raw, "敏感内容")
}
