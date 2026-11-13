package httpapi

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"docvault/internal/auth"
	"docvault/internal/metering"

	"github.com/jackc/pgx/v5/pgxpool"
)

// 平台静态令牌（setupWith 里注入）。
const platTok = "test-platform-token"

var tenantSeq int64

func platJSON(t *testing.T, method, url string, body any) (*http.Response, map[string]any) {
	t.Helper()
	return sendJSONMap(t, method, url, platTok, body)
}

// createdTenant 记录测试创建的租户，便于统一清理。
type createdTenant struct {
	slug     string
	token    string
	tenantID string
}

// createTenant 通过平台接口开通租户（含首个管理员），并返回可用令牌。
func createTenant(t *testing.T, pool *pgxpool.Pool, base, tag string) createdTenant {
	t.Helper()
	// 每次跑用唯一 slug：上一次失败留下的逻辑删除行仍占着 slug 唯一索引，
	// 固定 slug 会让"重跑即失败"，把真正的错误盖掉。
	slug := fmt.Sprintf("m3-%s-%d", tag, atomic.AddInt64(&tenantSeq, 1))
	resp, body := platJSON(t, http.MethodPost, base+"/v1/platform/tenants", map[string]any{
		"slug": slug, "name": "M3 测试租户",
		"adminUsername": "admin", "adminPassword": "m3-test-password-1",
	})
	if resp.StatusCode != 200 {
		t.Fatalf("开通租户失败 %d: %v", resp.StatusCode, body)
	}
	ct := createdTenant{
		slug:     slug,
		tenantID: dataMap(t, body)["tenantId"].(string),
	}
	t.Cleanup(func() { dbtestCleanup(t, pool, ct.tenantID) })
	ct.token = loginWith(t, base, slug, "admin", "m3-test-password-1")
	return ct
}

func loginWith(t *testing.T, base, slug, user, pass string) string {
	t.Helper()
	resp, body := postJSON(t, base+"/v1/auth/login", "", map[string]any{
		"tenantSlug": slug, "username": user, "password": pass,
	})
	if resp.StatusCode != 200 {
		t.Fatalf("登录失败 %d: %v", resp.StatusCode, body)
	}
	return dataMap(t, body)["accessToken"].(string)
}

// ---------------- 生命周期 ----------------

// 停用必须让**已签发**的令牌立刻失效，而不是等它自然过期。
// 这是 M3 最容易漏的地方：状态改了、登录拦了，但在线的人还能用到 15 分钟。
func TestM3SuspendTenantKillsLiveSessions(t *testing.T) {
	srv, pool, _ := setup(t)
	ct := createTenant(t, pool, srv.URL, "susp")

	if r, b := getJSON(t, srv.URL+"/v1/me", ct.token); r.StatusCode != 200 {
		t.Fatalf("停用前应可用 %d: %v", r.StatusCode, b)
	}

	resp, body := platJSON(t, http.MethodPatch, srv.URL+"/v1/platform/tenants/"+ct.slug,
		map[string]any{"status": "suspended"})
	if resp.StatusCode != 200 {
		t.Fatalf("停用失败 %d: %v", resp.StatusCode, body)
	}
	if d := dataMap(t, body); d["curStatus"] != "suspended" {
		t.Fatalf("状态未变更: %v", d)
	}

	// 已签发令牌必须立刻不可用
	if r, b := getJSON(t, srv.URL+"/v1/me", ct.token); r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("停用后旧令牌应 401，实际 %d: %v", r.StatusCode, b)
	}
	// 重新登录也必须拒绝（租户状态非 active）
	if r, b := postJSON(t, srv.URL+"/v1/auth/login", "", map[string]any{
		"tenantSlug": ct.slug, "username": "admin", "password": "m3-test-password-1",
	}); r.StatusCode == 200 {
		t.Fatalf("停用后不应能登录: %v", b)
	}

	// 恢复后应能登录（证明吊销不是不可逆的）
	if r, b := platJSON(t, http.MethodPatch, srv.URL+"/v1/platform/tenants/"+ct.slug,
		map[string]any{"status": "active"}); r.StatusCode != 200 {
		t.Fatalf("恢复失败 %d: %v", r.StatusCode, b)
	}
	_ = loginWith(t, srv.URL, ct.slug, "admin", "m3-test-password-1")
}

// 只读租户：读放行、写拒绝。这是试用到期与超限降级共用的形态。
func TestM3ReadonlyTenantBlocksWrites(t *testing.T) {
	srv, pool, _ := setup(t)
	ct := createTenant(t, pool, srv.URL, "ro")

	if r, b := platJSON(t, http.MethodPatch, srv.URL+"/v1/platform/tenants/"+ct.slug,
		map[string]any{"status": "readonly"}); r.StatusCode != 200 {
		t.Fatalf("设为只读失败 %d: %v", r.StatusCode, b)
	}

	if r, b := getJSON(t, srv.URL+"/v1/spaces", ct.token); r.StatusCode != 200 {
		t.Fatalf("只读租户应可读，实际 %d: %v", r.StatusCode, b)
	}
	resp, body := postJSON(t, srv.URL+"/v1/spaces", ct.token, map[string]any{
		"kind": "project", "name": "只读期新建",
	})
	if resp.StatusCode != http.StatusForbidden || body["code"] != "TENANT_READONLY" {
		t.Fatalf("只读租户写操作应 403 TENANT_READONLY，实际 %d: %v", resp.StatusCode, body)
	}

	// 账号安全类写操作必须仍然可用（否则用户改不了密码、退不出去）
	if r, _ := postJSON(t, srv.URL+"/v1/auth/logout", ct.token, map[string]any{}); r.StatusCode >= 500 {
		t.Fatalf("只读状态下登出不应报错，实际 %d", r.StatusCode)
	}
}

// 逻辑删除：不出现在列表，单查 404，但数据仍保留并记录保留期。
func TestM3DeleteTenantIsLogical(t *testing.T) {
	srv, pool, _ := setup(t)
	ct := createTenant(t, pool, srv.URL, "del")

	if r, b := platJSON(t, http.MethodDelete, srv.URL+"/v1/platform/tenants/"+ct.slug, nil); r.StatusCode != 200 {
		t.Fatalf("删除失败 %d: %v", r.StatusCode, b)
	}
	if r, _ := platJSON(t, http.MethodGet, srv.URL+"/v1/platform/tenants/"+ct.slug, nil); r.StatusCode != 404 {
		t.Fatalf("删除后单查应 404，实际 %d", r.StatusCode)
	}
	_, list := platJSON(t, http.MethodGet, srv.URL+"/v1/platform/tenants", nil)
	for _, it := range dataMap(t, list)["items"].([]any) {
		if m := it.(map[string]any); m["slug"] == ct.slug {
			t.Fatal("已删除租户不应出现在列表")
		}
	}
	var status string
	var retention *string
	if err := pool.QueryRow(context.Background(),
		`SELECT status, retention_until::text FROM tenant WHERE slug = $1`, ct.slug).
		Scan(&status, &retention); err != nil {
		t.Fatalf("查库失败: %v", err)
	}
	if status != "deleted" || retention == nil {
		t.Fatalf("应保留并记录保留期，实际 status=%s retention=%v", status, retention)
	}
}

// ---------------- 令牌种类不可互换（隔离的核心） ----------------

func TestM3TokenKindsAreNotInterchangeable(t *testing.T) {
	srv, _, slug := setup(t)
	tenantTok := login(t, srv.URL, slug)

	if r, b := getJSON(t, srv.URL+"/v1/platform/tenants", tenantTok); r.StatusCode != 401 {
		t.Fatalf("租户令牌访问平台面应 401，实际 %d: %v", r.StatusCode, b)
	}
	if r, b := getJSON(t, srv.URL+"/v1/spaces", platTok); r.StatusCode != 401 {
		t.Fatalf("平台令牌访问租户面应 401，实际 %d: %v", r.StatusCode, b)
	}
	if r, _ := getJSON(t, srv.URL+"/v1/platform/tenants", ""); r.StatusCode != 401 {
		t.Fatalf("匿名访问平台面应 401，实际 %d", r.StatusCode)
	}
	if r, _ := getJSON(t, srv.URL+"/v1/platform/tenants", "plat_deadbeef"); r.StatusCode != 401 {
		t.Fatalf("伪造令牌应 401，实际 %d", r.StatusCode)
	}
}

// 平台只读角色：能看不能改。
func TestM3PlatformReadonlyRoleCannotWrite(t *testing.T) {
	srv, pool, _ := setup(t)

	hash, herr := auth.HashPassword("readonly-pass-123456")
	if herr != nil {
		t.Fatal(herr)
	}
	email := fmt.Sprintf("ro-%d@example.com", atomic.AddInt64(&tenantSeq, 1))
	if _, err := pool.Exec(context.Background(), `
		INSERT INTO platform_user (id, email, display_name, password_hash, role)
		VALUES (gen_random_uuid(), $1, '只读运营', $2, 'readonly')`, email, hash); err != nil {
		t.Fatalf("建平台账号失败: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM platform_user WHERE email = $1`, email)
	})

	resp, body := postJSON(t, srv.URL+"/v1/platform/auth/login", "", map[string]any{
		"email": email, "password": "readonly-pass-123456",
	})
	if resp.StatusCode != 200 {
		t.Fatalf("平台登录失败 %d: %v", resp.StatusCode, body)
	}
	tok := dataMap(t, body)["accessToken"].(string)

	if r, b := getJSON(t, srv.URL+"/v1/platform/tenants", tok); r.StatusCode != 200 {
		t.Fatalf("只读角色应能查看 %d: %v", r.StatusCode, b)
	}
	resp, body = sendJSONMap(t, http.MethodPost, srv.URL+"/v1/platform/tenants", tok, map[string]any{
		"slug": "m3-ro-denied", "name": "x", "adminUsername": "a", "adminPassword": "123456789012",
	})
	if resp.StatusCode != http.StatusForbidden || body["code"] != "READONLY_ROLE" {
		t.Fatalf("只读角色写操作应 403 READONLY_ROLE，实际 %d: %v", resp.StatusCode, body)
	}
}

// ---------------- 计量准确性 ----------------

// 存储用量必须与真实文件聚合完全一致，且在并发下不丢更新。
func TestM3StorageMeteringIsExactUnderConcurrency(t *testing.T) {
	srv, pool, slug := setup(t)
	tenantID := tenantOf(t, pool, slug)
	tok := login(t, srv.URL, slug)
	spaceID := createSpace(t, srv.URL, tok, "计量空间")

	const n = 12
	const size = 4096

	var wg sync.WaitGroup
	errs := make(chan string, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			// 每个文件的**内容必须不同**：内容相同会命中秒传/去重，
			// 12 个并发写入就都指向同一个 blob 目标路径，在 Windows 上
			// 并发 rename 会报 "Access is denied"，用例随机失败——
			// 而这个用例要证明的是"12 个文件各自计量"，不是去重。
			payload := strings.Repeat(string(rune('a'+i)), size)
			resp, body := upload(t, srv.URL+"/v1/spaces/"+spaceID+"/files", tok,
				fmt.Sprintf("m3-%02d.txt", i), payload)
			if resp.StatusCode != 200 {
				errs <- fmt.Sprintf("上传失败 %d: %v", resp.StatusCode, body)
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for e := range errs {
		t.Fatal(e)
	}

	want := int64(n * size)
	if got := storageOf(t, pool, tenantID); got != want {
		t.Fatalf("并发计量不准确：账本 %d，期望 %d（差 %d）", got, want, got-want)
	}
	if got := realStorageOf(t, pool, tenantID); got != want {
		t.Fatalf("真实存储 %d 与期望 %d 不符（测试自身有问题）", got, want)
	}

	drifts, err := metering.New(pool).Reconcile(context.Background(), false)
	if err != nil {
		t.Fatalf("对账失败: %v", err)
	}
	for _, d := range drifts {
		if d.Slug == slug && (d.StorageDrift != 0 || d.UsersDrift != 0) {
			t.Fatalf("对账有偏差: %+v", d)
		}
	}
}

// 软删除后用量要减回去，否则客户"删了还是超限"，无法自助恢复。
func TestM3SoftDeleteReleasesStorage(t *testing.T) {
	srv, pool, slug := setup(t)
	tenantID := tenantOf(t, pool, slug)
	tok := login(t, srv.URL, slug)
	spaceID := createSpace(t, srv.URL, tok, "删除空间")

	_, up := upload(t, srv.URL+"/v1/spaces/"+spaceID+"/files", tok, "gone.txt", strings.Repeat("y", 2048))
	nodeID := dataMap(t, up)["nodeId"].(string)

	if got := storageOf(t, pool, tenantID); got != 2048 {
		t.Fatalf("上传后应为 2048，实际 %d", got)
	}
	if r, b := sendJSONMap(t, http.MethodDelete, srv.URL+"/v1/nodes/"+nodeID, tok, nil); r.StatusCode != 200 {
		t.Fatalf("删除失败 %d: %v", r.StatusCode, b)
	}
	if got := storageOf(t, pool, tenantID); got != 0 {
		t.Fatalf("软删后应回到 0，实际 %d", got)
	}
}

// 存储配额在数据库层硬拦：即使绕过应用层检查也超不过去。
func TestM3StorageQuotaEnforcedByDatabase(t *testing.T) {
	srv, pool, slug := setup(t)
	tenantID := tenantOf(t, pool, slug)
	tok := login(t, srv.URL, slug)
	spaceID := createSpace(t, srv.URL, tok, "配额空间")

	if r, b := platJSON(t, http.MethodPut, srv.URL+"/v1/platform/tenants/"+slug+"/quota",
		map[string]any{"maxStorageBytes": 1000, "onExceed": "reject"}); r.StatusCode != 200 {
		t.Fatalf("设置配额失败 %d: %v", r.StatusCode, b)
	}

	resp, body := upload(t, srv.URL+"/v1/spaces/"+spaceID+"/files", tok, "big.txt",
		strings.Repeat("z", 2000))
	if resp.StatusCode != http.StatusForbidden || body["code"] != "QUOTA_EXCEEDED" {
		t.Fatalf("超配额应 403 QUOTA_EXCEEDED，实际 %d: %v", resp.StatusCode, body)
	}

	// 绕过应用层：直接写 node 行，数据库必须拦住（SQLSTATE DV403）
	var ownerID string
	if err := pool.QueryRow(context.Background(),
		`SELECT id::text FROM app_user WHERE tenant_id = $1 LIMIT 1`, tenantID).Scan(&ownerID); err != nil {
		t.Fatal(err)
	}
	_, err := pool.Exec(context.Background(), `
		INSERT INTO node (id, tenant_id, space_id, parent_id, kind, name, size_bytes, owner_id)
		VALUES (gen_random_uuid(), $1, $2, $2, 'file', 'sneaky.txt', 5000, $3)`,
		tenantID, spaceID, ownerID)
	if err == nil {
		t.Fatal("数据库应拒绝超过配额的写入（否则配额只是界面装饰）")
	}
	if !strings.Contains(err.Error(), "quota:storage") {
		t.Fatalf("应命中配额约束，实际错误: %v", err)
	}
}

// 用户数配额同理：在数据库层硬拦。
func TestM3UserQuotaEnforced(t *testing.T) {
	srv, pool, slug := setup(t)
	tenantID := tenantOf(t, pool, slug)

	if r, b := platJSON(t, http.MethodPut, srv.URL+"/v1/platform/tenants/"+slug+"/quota",
		map[string]any{"maxUsers": 1, "onExceed": "reject"}); r.StatusCode != 200 {
		t.Fatalf("设置用户配额失败 %d: %v", r.StatusCode, b)
	}
	_, err := pool.Exec(context.Background(), `
		INSERT INTO app_user (id, tenant_id, username, display_name, password_hash, status)
		VALUES (gen_random_uuid(), $1, 'extra', 'Extra', 'x', 'active')`, tenantID)
	if err == nil || !strings.Contains(err.Error(), "quota:users") {
		t.Fatalf("应命中用户配额，实际 %v", err)
	}
}

// usage_record 幂等：同一 dedupe_key 提交两次只计一次。
func TestM3UsageRecordIsIdempotent(t *testing.T) {
	_, pool, slug := setup(t)
	tenantID := tenantOf(t, pool, slug)

	var first, second bool
	if err := pool.QueryRow(context.Background(),
		`SELECT usage_record($1,'transcode_seconds',30,'job:abc', '{}'::jsonb)`, tenantID).Scan(&first); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(context.Background(),
		`SELECT usage_record($1,'transcode_seconds',30,'job:abc', '{}'::jsonb)`, tenantID).Scan(&second); err != nil {
		t.Fatal(err)
	}
	if !first || second {
		t.Fatalf("首次应为 true、重复应为 false，实际 %v/%v", first, second)
	}

	var total int64
	if err := pool.QueryRow(context.Background(),
		`SELECT COALESCE(sum(quantity),0) FROM usage_event WHERE tenant_id=$1 AND metric='transcode_seconds'`,
		tenantID).Scan(&total); err != nil {
		t.Fatal(err)
	}
	if total != 30 {
		t.Fatalf("重复提交被计了两次：%d", total)
	}
	var daily int64
	if err := pool.QueryRow(context.Background(),
		`SELECT quantity FROM usage_daily WHERE tenant_id=$1 AND metric='transcode_seconds' AND day=current_date`,
		tenantID).Scan(&daily); err != nil {
		t.Fatal(err)
	}
	if daily != 30 {
		t.Fatalf("日聚合错误：%d", daily)
	}
}

// ---------------- 灰度开关 ----------------

// 关闭外链分享后，服务端必须拒绝创建（不能只靠前端隐藏按钮）。
func TestM3FeatureFlagGatesExternalShareServerSide(t *testing.T) {
	srv, _, slug := setup(t)
	tok := login(t, srv.URL, slug)
	_, nodeID := prepareFile(t, srv.URL, tok)

	if r, b := platJSON(t, http.MethodPut, srv.URL+"/v1/platform/tenants/"+slug+"/flags/share.external",
		map[string]any{"enabled": false}); r.StatusCode != 200 {
		t.Fatalf("关闭开关失败 %d: %v", r.StatusCode, b)
	}
	t.Cleanup(func() {
		_, _ = platJSON(t, http.MethodDelete,
			srv.URL+"/v1/platform/tenants/"+slug+"/flags/share.external", nil)
	})

	resp, body := postJSON(t, srv.URL+"/v1/shares", tok, map[string]any{
		"objectType": "node", "objectId": nodeID,
	})
	if resp.StatusCode != http.StatusForbidden || body["code"] != "FEATURE_DISABLED" {
		t.Fatalf("关闭后应 403 FEATURE_DISABLED，实际 %d: %v", resp.StatusCode, body)
	}

	if r, b := platJSON(t, http.MethodPut, srv.URL+"/v1/platform/tenants/"+slug+"/flags/share.external",
		map[string]any{"enabled": true}); r.StatusCode != 200 {
		t.Fatalf("打开开关失败 %d: %v", r.StatusCode, b)
	}
	if r, b := postJSON(t, srv.URL+"/v1/shares", tok, map[string]any{
		"objectType": "node", "objectId": nodeID,
	}); r.StatusCode != 200 {
		t.Fatalf("打开后应可创建，实际 %d: %v", r.StatusCode, b)
	}
}

// 全局关掉 + 租户覆盖开启：覆盖必须优先（运营对个别租户的例外）。
func TestM3TenantOverrideBeatsGlobalKill(t *testing.T) {
	srv, _, slug := setup(t)
	tok := login(t, srv.URL, slug)
	_, nodeID := prepareFile(t, srv.URL, tok)

	if r, b := platJSON(t, http.MethodPut, srv.URL+"/v1/platform/flags/share.external",
		map[string]any{"defaultEnabled": false, "rolloutPercent": 0}); r.StatusCode != 200 {
		t.Fatalf("全局关闭失败 %d: %v", r.StatusCode, b)
	}
	t.Cleanup(func() {
		_, _ = platJSON(t, http.MethodPut, srv.URL+"/v1/platform/flags/share.external",
			map[string]any{"defaultEnabled": true, "rolloutPercent": 100})
	})

	if r, _ := postJSON(t, srv.URL+"/v1/shares", tok, map[string]any{
		"objectType": "node", "objectId": nodeID,
	}); r.StatusCode != http.StatusForbidden {
		t.Fatalf("全局关闭后应拒绝，实际 %d", r.StatusCode)
	}

	if r, b := platJSON(t, http.MethodPut,
		srv.URL+"/v1/platform/tenants/"+slug+"/flags/share.external",
		map[string]any{"enabled": true}); r.StatusCode != 200 {
		t.Fatalf("设置租户覆盖失败 %d: %v", r.StatusCode, b)
	}
	t.Cleanup(func() {
		_, _ = platJSON(t, http.MethodDelete,
			srv.URL+"/v1/platform/tenants/"+slug+"/flags/share.external", nil)
	})
	if r, b := postJSON(t, srv.URL+"/v1/shares", tok, map[string]any{
		"objectType": "node", "objectId": nodeID,
	}); r.StatusCode != 200 {
		t.Fatalf("租户覆盖应优先，实际 %d: %v", r.StatusCode, b)
	}
}

// ---------------- 白标 ----------------

func TestM3BrandingUpdateAndPublicRead(t *testing.T) {
	srv, pool, _ := setup(t)
	ct := createTenant(t, pool, srv.URL, "brand")

	// 非法颜色必须在写库前被拒
	if r, b := sendJSONMap(t, http.MethodPut, srv.URL+"/v1/admin/branding", ct.token, map[string]any{
		"productName": "X", "primaryColor": "red", "accentColor": "#0b5fa5",
	}); r.StatusCode != http.StatusBadRequest {
		t.Fatalf("非法颜色应 400，实际 %d: %v", r.StatusCode, b)
	}

	if r, b := sendJSONMap(t, http.MethodPut, srv.URL+"/v1/admin/branding", ct.token, map[string]any{
		"productName": "某某文档中心", "primaryColor": "#123456", "accentColor": "#654321",
		"footerText": "内部使用",
	}); r.StatusCode != 200 {
		t.Fatalf("更新品牌失败 %d: %v", r.StatusCode, b)
	}

	resp, body := getJSON(t, srv.URL+"/v1/tenant/branding?slug="+ct.slug, "")
	if resp.StatusCode != 200 {
		t.Fatalf("公开品牌读取失败 %d: %v", resp.StatusCode, body)
	}
	d := dataMap(t, body)
	if d["productName"] != "某某文档中心" || d["primaryColor"] != "#123456" {
		t.Fatalf("品牌未生效: %v", d)
	}

	// 停用后公开品牌应 404（避免"看起来还在服务"）
	if r, _ := platJSON(t, http.MethodPatch, srv.URL+"/v1/platform/tenants/"+ct.slug,
		map[string]any{"status": "suspended"}); r.StatusCode != 200 {
		t.Fatalf("停用失败 %d", r.StatusCode)
	}
	if r, _ := getJSON(t, srv.URL+"/v1/tenant/branding?slug="+ct.slug, ""); r.StatusCode != 404 {
		t.Fatalf("停用后品牌应 404，实际 %d", r.StatusCode)
	}
}

// 自有域名：未验证不可用；验证后可解析；跨租户不可抢占。
func TestM3DomainVerifyAndIsolation(t *testing.T) {
	// DNS 结果由测试控制：把"当前应匹配的 token"放在一个变量里，
	// 因为 token 是绑定时才生成的，不能在装配时写死。
	var want atomic.Value
	srv, pool, _ := setupWith(t, func(a *API) {
		a.LookupTXT = func(ctx context.Context, name string) ([]string, error) {
			if name != "_docvault-challenge.example-doc.test" {
				return nil, nil
			}
			if v, ok := want.Load().(string); ok && v != "" {
				return []string{"noise", v}, nil
			}
			return []string{"noise"}, nil
		}
	})
	ct := createTenant(t, pool, srv.URL, "dom")

	resp, body := platJSON(t, http.MethodPost, srv.URL+"/v1/platform/tenants/"+ct.slug+"/domains",
		map[string]any{"host": "example-doc.test", "primary": true})
	if resp.StatusCode != 200 {
		t.Fatalf("绑定域名失败 %d: %v", resp.StatusCode, body)
	}
	dnsValue := dataMap(t, body)["dns"].(map[string]any)["value"].(string)
	if dnsValue == "" {
		t.Fatal("绑定应返回 DNS 验证值")
	}

	// 未验证：按 Host 解析不到
	if r, _ := getJSON(t, srv.URL+"/v1/tenant/branding", ""); r.StatusCode != 404 {
		t.Fatalf("未验证域名不应可用，实际 %d", r.StatusCode)
	}
	// DNS 还没配好时验证必须失败（证明验证真的在查 DNS，而不是走过场）
	want.Store("not-the-token")
	if r, b := platJSON(t, http.MethodPost,
		srv.URL+"/v1/platform/tenants/"+ct.slug+"/domains/example-doc.test/verify", nil); r.StatusCode != 412 {
		t.Fatalf("TXT 不匹配应 412，实际 %d: %v", r.StatusCode, b)
	}
	// 配上正确值后通过
	want.Store(dnsValue)
	if r, b := platJSON(t, http.MethodPost,
		srv.URL+"/v1/platform/tenants/"+ct.slug+"/domains/example-doc.test/verify", nil); r.StatusCode != 200 {
		t.Fatalf("验证失败 %d: %v", r.StatusCode, b)
	}

	// 验证后：按 Host 可解析
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/v1/tenant/branding", nil)
	req.Host = "example-doc.test"
	r2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer r2.Body.Close()
	if r2.StatusCode != 200 {
		raw, _ := io.ReadAll(r2.Body)
		t.Fatalf("验证后应按 Host 解析成功，实际 %d: %s", r2.StatusCode, raw)
	}

	// 另一个租户抢同一域名必须失败
	ct2 := createTenant(t, pool, srv.URL, "dom2")
	if r, b := platJSON(t, http.MethodPost, srv.URL+"/v1/platform/tenants/"+ct2.slug+"/domains",
		map[string]any{"host": "example-doc.test"}); r.StatusCode == 200 {
		t.Fatalf("同域名不应能绑到第二个租户: %v", b)
	}
}

// 未配置加密密钥时，上传证书必须拒绝（而不是明文落库）。
func TestM3CertificateRequiresSecretKey(t *testing.T) {
	srv, pool, _ := setup(t)
	ct := createTenant(t, pool, srv.URL, "cert")

	if r, b := platJSON(t, http.MethodPost, srv.URL+"/v1/platform/tenants/"+ct.slug+"/domains",
		map[string]any{"host": "cert-test.test"}); r.StatusCode != 200 {
		t.Fatalf("绑定域名失败 %d: %v", r.StatusCode, b)
	}
	resp, body := platJSON(t, http.MethodPut,
		srv.URL+"/v1/platform/tenants/"+ct.slug+"/domains/cert-test.test/certificate",
		map[string]any{"certPem": "x", "keyPem": "y"})
	if resp.StatusCode != http.StatusServiceUnavailable || body["code"] != "SECRET_KEY_MISSING" {
		t.Fatalf("无密钥时应 503 SECRET_KEY_MISSING，实际 %d: %v", resp.StatusCode, body)
	}
}

// ---------------- 账单与审计 ----------------

func TestM3InvoiceCSVExported(t *testing.T) {
	srv, pool, slug := setup(t)
	tenantID := tenantOf(t, pool, slug)
	if _, err := pool.Exec(context.Background(),
		`SELECT usage_record($1,'transcode_seconds',42,'inv:1','{}'::jsonb)`, tenantID); err != nil {
		t.Fatal(err)
	}

	req, _ := http.NewRequest(http.MethodGet,
		srv.URL+"/v1/platform/tenants/"+slug+"/invoice.csv", nil)
	req.Header.Set("Authorization", "Bearer "+platTok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != 200 {
		t.Fatalf("导出失败 %d: %s", resp.StatusCode, raw)
	}
	if !bytes.HasPrefix(raw, []byte{0xEF, 0xBB, 0xBF}) {
		t.Fatal("CSV 应带 BOM，否则 Excel 打开中文列名乱码")
	}
	if !bytes.Contains(raw, []byte("transcode_seconds")) || !bytes.Contains(raw, []byte("42")) {
		t.Fatalf("账单内容缺少用量: %s", raw)
	}
}

func TestM3PlatformAuditTrailWritten(t *testing.T) {
	srv, pool, _ := setup(t)
	ct := createTenant(t, pool, srv.URL, "aud")

	_, body := platJSON(t, http.MethodGet, srv.URL+"/v1/platform/audit?action=platform.tenant.create", nil)
	items, _ := dataMap(t, body)["items"].([]any)
	var found bool
	for _, it := range items {
		if m := it.(map[string]any); m["target"] == ct.slug {
			found = true
		}
	}
	if !found {
		t.Fatalf("平台审计应记录租户开通，实际 %v", body)
	}
}

// ---------------- 辅助 ----------------

func createSpace(t *testing.T, base, tok, name string) string {
	t.Helper()
	resp, body := postJSON(t, base+"/v1/spaces", tok, map[string]any{"kind": "project", "name": name})
	if resp.StatusCode != 200 {
		t.Fatalf("建空间失败 %d: %v", resp.StatusCode, body)
	}
	return dataMap(t, body)["spaceId"].(string)
}

func storageOf(t *testing.T, pool *pgxpool.Pool, tenantID string) int64 {
	t.Helper()
	var v int64
	if err := pool.QueryRow(context.Background(),
		`SELECT storage_bytes FROM tenant_usage WHERE tenant_id = $1`, tenantID).Scan(&v); err != nil {
		t.Fatalf("读用量失败: %v", err)
	}
	return v
}

func realStorageOf(t *testing.T, pool *pgxpool.Pool, tenantID string) int64 {
	t.Helper()
	var v int64
	if err := pool.QueryRow(context.Background(), `
		SELECT COALESCE(sum(size_bytes),0) FROM node
		 WHERE tenant_id=$1 AND kind='file' AND deleted_at IS NULL`, tenantID).Scan(&v); err != nil {
		t.Fatalf("读真实存储失败: %v", err)
	}
	return v
}

// 关闭"分享邮箱验证"后，**新建**链接不再要求验证；存量链接不受影响。
//
// 这条守的是一个容易做错的方向：如果连存量也拦，客户会突然打不开已经发出去的链接，
// 那种事故比"功能少一块"严重得多。因此只在创建路径上生效。
func TestM3FeatureFlagDisablesNewVerifyRequirement(t *testing.T) {
	srv, pool, slug := setup(t)
	tenantID := tenantOf(t, pool, slug)
	tok := login(t, srv.URL, slug)
	_, nodeID := prepareFile(t, srv.URL, tok)

	if r, b := platJSON(t, http.MethodPut,
		srv.URL+"/v1/platform/tenants/"+slug+"/flags/share.email_verify",
		map[string]any{"enabled": false}); r.StatusCode != 200 {
		t.Fatalf("关闭开关失败 %d: %v", r.StatusCode, b)
	}
	t.Cleanup(func() {
		_, _ = platJSON(t, http.MethodDelete,
			srv.URL+"/v1/platform/tenants/"+slug+"/flags/share.email_verify", nil)
	})

	resp, body := postJSON(t, srv.URL+"/v1/shares", tok, map[string]any{
		"objectType": "node", "objectId": nodeID, "requireVerify": true,
	})
	if resp.StatusCode != 200 {
		t.Fatalf("创建分享失败 %d: %v", resp.StatusCode, body)
	}
	shareID := dataMap(t, body)["shareId"].(string)

	var requireVerify bool
	if err := pool.QueryRow(context.Background(),
		`SELECT require_verify FROM share WHERE id = $1 AND tenant_id = $2`, shareID, tenantID).
		Scan(&requireVerify); err != nil {
		t.Fatal(err)
	}
	if requireVerify {
		t.Fatal("开关关闭时新建链接不应要求邮箱验证")
	}
}

// 路由清单守卫：M3 新增的受保护端点，匿名访问必须 401。
//
// 这条测试的存在动机很具体：`GET /v1/features` 一开始漏了 requireAuth，
// 表现是"200 + 永远空列表"——不报错、不报警，只有在界面上发现"开关不显示"才会被注意。
// 把端点列成清单逐个断言，是防止下一次漏包鉴权的最省事办法。
func TestM3ProtectedRoutesRejectAnonymous(t *testing.T) {
	srv, _, _ := setup(t)

	protected := []struct{ method, path string }{
		{http.MethodGet, "/v1/features"},
		{http.MethodGet, "/v1/admin/branding"},
		{http.MethodPut, "/v1/admin/branding"},
		{http.MethodGet, "/v1/admin/policy"},
		{http.MethodPut, "/v1/admin/policy"},
		{http.MethodGet, "/v1/admin/usage"},
		{http.MethodGet, "/v1/platform/me"},
		{http.MethodGet, "/v1/platform/tenants"},
		{http.MethodGet, "/v1/platform/audit"},
		{http.MethodGet, "/v1/platform/flags"},
		{http.MethodGet, "/v1/platform/usage/reconcile"},
	}
	for _, rt := range protected {
		req, _ := http.NewRequest(rt.method, srv.URL+rt.path, nil)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("%s %s 请求失败: %v", rt.method, rt.path, err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("%s %s 匿名访问应 401，实际 %d", rt.method, rt.path, resp.StatusCode)
		}
	}
}

// 已登录用户读开关必须拿到真实列表（防止"200 但空"这类静默失败）。
func TestM3FeaturesVisibleToTenantUser(t *testing.T) {
	srv, _, slug := setup(t)
	tok := login(t, srv.URL, slug)

	_, body := getJSON(t, srv.URL+"/v1/features", tok)
	items, _ := dataMap(t, body)["items"].([]any)
	if len(items) == 0 {
		t.Fatalf("已登录用户应拿到开关列表，实际 %v", body)
	}
	var found bool
	for _, it := range items {
		m := it.(map[string]any)
		if m["code"] == "share.external" {
			found = true
			if _, ok := m["source"]; !ok {
				t.Fatalf("开关应带 source 字段: %v", m)
			}
		}
	}
	if !found {
		t.Fatalf("缺少 share.external 开关: %v", items)
	}
}
