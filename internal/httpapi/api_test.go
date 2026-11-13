package httpapi

import (
	"bytes"
	"context"
	"crypto/rand"
	"docvault/internal/dbtest"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"docvault/internal/audit"
	"docvault/internal/auth"
	"docvault/internal/content"
	"docvault/internal/db"
	"docvault/internal/feature"
	"docvault/internal/iam"
	"docvault/internal/metering"
	"docvault/internal/platform/httpmw"
	"docvault/internal/platformauth"
	"docvault/internal/tenant"
	"docvault/migrations"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const pwd = "correct-horse-battery-2026"

func uuid(t *testing.T) string {
	t.Helper()
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	d := make([]byte, 36)
	hex.Encode(d[0:8], b[0:4])
	d[8] = '-'
	hex.Encode(d[9:13], b[4:6])
	d[13] = '-'
	hex.Encode(d[14:18], b[6:8])
	d[18] = '-'
	hex.Encode(d[19:23], b[8:10])
	d[23] = '-'
	hex.Encode(d[24:36], b[10:16])
	return string(d)
}

// setup 返回一个已注册路由的测试服务器与租户 slug。
func setup(t *testing.T) (*httptest.Server, *pgxpool.Pool, string) {
	t.Helper()
	return setupWith(t, nil)
}

// setupWith 允许在启动前装饰 API（注入预览/编辑器等可选依赖）。
func setupWith(t *testing.T, decorate func(*API)) (*httptest.Server, *pgxpool.Pool, string) {
	t.Helper()
	dsn := os.Getenv("DOCVAULT_TEST_DSN")
	if dsn == "" {
		t.Skip("未设置 DOCVAULT_TEST_DSN，跳过 HTTP 集成测试")
	}
	pool, err := db.Connect(context.Background(), dsn)
	if err != nil {
		t.Fatalf("连接失败: %v", err)
	}
	t.Cleanup(pool.Close)
	if _, err := db.Migrate(context.Background(), pool, migrations.Files); err != nil {
		t.Fatalf("迁移失败: %v", err)
	}

	ctx := context.Background()
	tenantID, userID := uuid(t), uuid(t)
	slug := "http-" + tenantID[:8]
	// 测试租户显式建成商业版：这些用例验证的是功能行为，不是档位限制。
	// 档位差异（基础版无密级、专业版只允许 0/3/4 等）由 edition_test.go 单独覆盖，
	// 否则每加一档限制都要改动几十个无关用例。
	if _, err := pool.Exec(ctx,
		`INSERT INTO tenant (id, slug, name, edition) VALUES ($1,$2,$3,'business')`,
		tenantID, slug, "HTTP 测试租户"); err != nil {
		t.Fatal(err)
	}
	hash, _ := auth.HashPassword(pwd)
	if _, err := pool.Exec(ctx, `
		INSERT INTO app_user (id, tenant_id, username, display_name, password_hash, status)
		VALUES ($1,$2,'bob','Bob',$3,'active')`, userID, tenantID, hash); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { dbtest.CleanupTenant(t, pool, tenantID) })

	store, err := content.New(pool, t.TempDir())
	if err != nil {
		t.Fatalf("初始化存储失败: %v", err)
	}
	api := &API{
		Pool:    pool,
		Auth:    auth.New(pool, []byte("0123456789abcdef0123456789abcdef"), auth.DefaultConfig()),
		Content: store,
		// M3 依赖：平台侧与计量/开关。测试里同样装配，否则平台端点会因
		// "服务未初始化"返回 401，看起来像权限问题。
		Tenants:       tenant.New(pool),
		IAM:           iam.New(pool),
		Metering:      metering.New(pool),
		Features:      feature.New(pool),
		PlatformAuth:  platformauth.New(pool),
		PlatformToken: "test-platform-token",
	}
	api.OnAudit = func(ctx context.Context, tenantID string, ev AuditEntry) error {
		return db.WithTenant(ctx, pool, tenantID, func(tx pgx.Tx) error {
			return audit.Append(ctx, tx, tenantID, audit.Event{
				ActorID: ev.ActorID, ActorType: ev.ActorType, Action: ev.Action,
				ObjectID: ev.ObjectID, Result: ev.Result, Detail: ev.Detail,
				IP: ev.IP, RequestID: ev.RequestID,
			})
		})
	}

	if decorate != nil {
		decorate(api)
	}

	mux := http.NewServeMux()
	api.Register(mux)
	srv := httptest.NewServer(httpmw.RequestID(mux))
	t.Cleanup(srv.Close)
	return srv, pool, slug
}

func postJSON(t *testing.T, url, token string, body any) (*http.Response, map[string]any) {
	t.Helper()
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPost, url, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("请求失败: %v", err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp, out
}

func getJSON(t *testing.T, url, token string) (*http.Response, map[string]any) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("请求失败: %v", err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp, out
}

func dataMap(t *testing.T, body map[string]any) map[string]any {
	t.Helper()
	d, ok := body["data"].(map[string]any)
	if !ok {
		t.Fatalf("响应缺少 data: %v", body)
	}
	return d
}

func TestAuthAndShareFlowOverHTTP(t *testing.T) {
	srv, pool, slug := setup(t)

	// 1. 登录
	resp, body := postJSON(t, srv.URL+"/v1/auth/login", "", map[string]any{
		"tenantSlug": slug, "username": "bob", "password": pwd,
	})
	if resp.StatusCode != 200 {
		t.Fatalf("登录应成功，实际 %d: %v", resp.StatusCode, body)
	}
	access := dataMap(t, body)["accessToken"].(string)
	if access == "" {
		t.Fatal("应返回 accessToken")
	}

	// 2. 带令牌访问 /v1/me
	resp, body = getJSON(t, srv.URL+"/v1/me", access)
	if resp.StatusCode != 200 {
		t.Fatalf("/v1/me 应成功，实际 %d", resp.StatusCode)
	}

	// 3. 无令牌访问受保护端点
	resp, _ = getJSON(t, srv.URL+"/v1/me", "")
	if resp.StatusCode != 401 {
		t.Fatalf("无令牌应 401，实际 %d", resp.StatusCode)
	}

	// 4. 创建一次性分享
	//
	// 必须先有真实对象：分享一个不存在的 nodeId 现在会被拒（404）。
	// 这是有意的改动——过去允许"分享悬空对象"，会生成一条永远打不开的链接，
	// 且留下无法追溯的 share 行。
	one := 1
	_, sb := postJSON(t, srv.URL+"/v1/spaces", access, map[string]any{"kind": "project", "name": "分享空间"})
	shareSpace := dataMap(t, sb)["spaceId"].(string)
	_, fb := upload(t, srv.URL+"/v1/spaces/"+shareSpace+"/files", access, "对外通告.pdf", "hello")
	shareNode := dataMap(t, fb)["nodeId"].(string)

	resp, body = postJSON(t, srv.URL+"/v1/shares", access, map[string]any{
		"objectType": "node", "objectId": shareNode,
		"maxUses": one, "watermark": true, "allowDownload": false,
	})
	if resp.StatusCode != 200 {
		t.Fatalf("创建分享应成功，实际 %d: %v", resp.StatusCode, body)
	}
	token := dataMap(t, body)["token"].(string)

	// 5. 免登录访问：第一次成功
	resp, body = getJSON(t, srv.URL+"/v1/public/shares/"+token, "")
	if resp.StatusCode != 200 {
		t.Fatalf("首次访问应成功，实际 %d: %v", resp.StatusCode, body)
	}
	if dataMap(t, body)["oneTime"] != true {
		t.Fatal("应标记为一次性")
	}

	// 6. 第二次访问：410 且与"不存在"同一表现
	resp, body2 := getJSON(t, srv.URL+"/v1/public/shares/"+token, "")
	if resp.StatusCode != http.StatusGone {
		t.Fatalf("二次访问应 410，实际 %d", resp.StatusCode)
	}
	resp, body3 := getJSON(t, srv.URL+"/v1/public/shares/not-a-real-token", "")
	if resp.StatusCode != http.StatusGone {
		t.Fatalf("不存在的链接也应 410，实际 %d", resp.StatusCode)
	}
	if body2["code"] != body3["code"] {
		t.Fatalf("两种失效必须返回同一错误码: %v vs %v", body2["code"], body3["code"])
	}

	// 7. 审计应记录登录、创建分享与兑换
	var n int
	ctx := context.Background()
	// 按 slug 精确定位租户：用 username 反查可能命中其他测试残留的同名账号
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM audit_event WHERE tenant_id=(SELECT id FROM tenant WHERE slug=$1)`, slug).
		Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n < 3 {
		t.Fatalf("应至少写入 3 条审计（登录/创建/兑换），实际 %d", n)
	}
}

func TestLoginWrongPasswordOverHTTP(t *testing.T) {
	srv, _, slug := setup(t)
	resp, body := postJSON(t, srv.URL+"/v1/auth/login", "", map[string]any{
		"tenantSlug": slug, "username": "bob", "password": "nope",
	})
	if resp.StatusCode != 401 {
		t.Fatalf("错误口令应 401，实际 %d: %v", resp.StatusCode, body)
	}
	if body["code"] != "INVALID_CREDENTIALS" {
		t.Fatalf("错误码不符: %v", body["code"])
	}
}
