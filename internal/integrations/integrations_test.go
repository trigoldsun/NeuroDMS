package integrations

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"docvault/internal/db"
	"docvault/internal/dbtest"
	"docvault/internal/secretbox"
	"docvault/migrations"

	"github.com/jackc/pgx/v5/pgxpool"
)

// 用一个假通道测"存储层"的通用行为：必填校验、密钥分流、只写不读、切换。
// 具体厂商的请求形状由各自包测。
func fakeRegistry() *Registry {
	reg := NewRegistry()
	reg.Register(Descriptor{
		Kind: "sms", Code: "fake", Name: "假通道", Mode: "local",
		Fields: []Field{
			{Key: "appId", Label: "AppId", Required: true},
			{Key: "sign", Label: "签名"},
			{Key: "appSecret", Label: "AppSecret", Required: true, Secret: true},
		},
	}, func(cfg, sec map[string]string) (Runner, error) { return fakeRunner{cfg, sec}, nil })
	return reg
}

type fakeRunner struct{ cfg, sec map[string]string }

func (f fakeRunner) Test(context.Context) error { return nil }

func setup(t *testing.T) (*pgxpool.Pool, *Store, string) {
	t.Helper()
	dsn := os.Getenv("DOCVAULT_TEST_DSN")
	if dsn == "" {
		t.Skip("未设置 DOCVAULT_TEST_DSN，跳过凭证中心集成测试")
	}
	ctx := context.Background()
	pool, err := db.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("连接失败: %v", err)
	}
	t.Cleanup(pool.Close)
	if _, err := db.Migrate(ctx, pool, migrations.Files); err != nil {
		t.Fatalf("迁移失败: %v", err)
	}
	var id string
	slug := "integ-" + time.Now().Format("150405-000000")
	if err := pool.QueryRow(ctx,
		`INSERT INTO tenant (id, slug, name, edition) VALUES (gen_random_uuid(), $1, $2, 'business')
		 RETURNING id::text`, slug, "凭证测试租户").Scan(&id); err != nil {
		t.Fatalf("建租户失败: %v", err)
	}
	t.Cleanup(func() { dbtest.CleanupTenant(t, pool, id) })

	box, _ := secretbox.New(base64.StdEncoding.EncodeToString(make([]byte, 32)))
	return pool, NewStore(pool, box, fakeRegistry()), id
}

func TestSaveRequiresSecretsAndKeepsThemOut(t *testing.T) {
	_, st, tenantID := setup(t)
	ctx := context.Background()

	// 必填密钥缺失 → 拒绝
	_, err := st.Save(ctx, tenantID, "u1", Settings{
		Kind: "sms", Provider: "fake", Config: map[string]string{"appId": "a1"},
	})
	if err == nil || !strings.Contains(err.Error(), "AppSecret") {
		t.Fatalf("缺少必填密钥应被拒，实际 %v", err)
	}

	// 把密钥塞进 config → 拒绝（否则会明文落库并在 GET 里回显）
	_, err = st.Save(ctx, tenantID, "u1", Settings{
		Kind: "sms", Provider: "fake",
		Config:  map[string]string{"appId": "a1", "appSecret": "leak"},
		Secrets: map[string]string{"appSecret": "s3cret"},
	})
	if err == nil || !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("密钥走 config 通道应被拒，实际 %v", err)
	}

	// 正常保存
	saved, err := st.Save(ctx, tenantID, "u1", Settings{
		Kind: "sms", Provider: "fake",
		Config:  map[string]string{"appId": "a1", "sign": "签名A"},
		Secrets: map[string]string{"appSecret": "s3cret"},
	})
	if err != nil {
		t.Fatalf("保存失败: %v", err)
	}
	if !saved.Active {
		t.Fatal("第一条配置应自动生效")
	}
	if !saved.HasSecret["appSecret"] {
		t.Fatal("应标记 appSecret 已保存")
	}

	// JSON 里不能出现密钥值（Secrets 是 json:"-"），也不能被回显成字段
	raw, _ := json.Marshal(saved)
	if strings.Contains(string(raw), "s3cret") {
		t.Fatalf("响应里泄漏了密钥: %s", raw)
	}

	// 留空保存 = 沿用旧密钥；改非密字段不丢密钥
	saved2, err := st.Save(ctx, tenantID, "u1", Settings{
		Kind: "sms", Provider: "fake",
		Config: map[string]string{"appId": "a2", "sign": "签名B"},
	})
	if err != nil {
		t.Fatalf("二次保存失败: %v", err)
	}
	if !saved2.HasSecret["appSecret"] {
		t.Fatal("留空保存后密钥丢失")
	}
}

func TestActiveSwitchAndDelete(t *testing.T) {
	_, st, tenantID := setup(t)
	ctx := context.Background()

	// 第一个通道带必填密钥
	if _, err := st.Save(ctx, tenantID, "u1", Settings{
		Kind: "sms", Provider: "fake",
		Config:  map[string]string{"appId": "x"},
		Secrets: map[string]string{"appSecret": "s"},
	}); err != nil {
		t.Fatalf("保存 fake 失败: %v", err)
	}
	// 第二个通道模拟"换厂商"（无密钥字段）
	st.reg.Register(Descriptor{Kind: "sms", Code: "fake2", Name: "假通道2",
		Fields: []Field{{Key: "appId", Label: "AppId", Required: true}}}, nil)
	if _, err := st.Save(ctx, tenantID, "u1", Settings{
		Kind: "sms", Provider: "fake2", Config: map[string]string{"appId": "x"},
	}); err != nil {
		t.Fatalf("保存 fake2 失败: %v", err)
	}

	cur, ok, err := st.Active(ctx, tenantID, "sms")
	if err != nil || !ok {
		t.Fatalf("应有生效配置: ok=%v err=%v", ok, err)
	}
	// **新增备用配置不能抢走生效位**：这是评审发现的真实缺陷，
	// 早期"新增即生效"会让加一条备用通道 = 线上静默切流。
	if cur.Provider != "fake" {
		t.Fatalf("新增配置不应自动生效，实际生效 %s", cur.Provider)
	}

	// 编辑生效中的配置且不传 active：必须保持生效，
	// 否则改一个模板 ID 就把通道关掉，静默回落平台通道。
	if _, err := st.Save(ctx, tenantID, "u1", Settings{
		Kind: "sms", Provider: "fake",
		Config: map[string]string{"appId": "changed"},
	}); err != nil {
		t.Fatalf("编辑生效配置失败: %v", err)
	}
	if cur, _, _ := st.Active(ctx, tenantID, "sms"); cur.Provider != "fake" {
		t.Fatal("编辑后不应失去生效位")
	}

	if err := st.Activate(ctx, tenantID, "sms", "fake"); err != nil {
		t.Fatalf("切换失败: %v", err)
	}
	cur, _, _ = st.Active(ctx, tenantID, "sms")
	if cur.Provider != "fake" {
		t.Fatalf("切换后应生效 fake，实际 %s", cur.Provider)
	}

	list, err := st.List(ctx, tenantID, "sms")
	if err != nil || len(list) != 2 {
		t.Fatalf("应列出 2 条，实际 %d（err=%v）", len(list), err)
	}
	// 列表必须带回非密字段，否则页面打开是空白，管理员会重填覆盖正确配置
	for _, item := range list {
		if item.Provider == "fake" && item.Config["appId"] != "changed" {
			t.Fatalf("列表应回显 appId，实际 %v", item.Config)
		}
	}

	if err := st.Delete(ctx, tenantID, "sms", "fake2"); err != nil {
		t.Fatalf("删除失败: %v", err)
	}
	if _, err := st.Get(ctx, tenantID, "sms", "fake2"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("删除后应 404，实际 %v", err)
	}
}

// 未注册的 provider 不能保存（防拼写错误悄悄存成一条没人认识的配置）。
func TestUnknownProviderRejected(t *testing.T) {
	_, st, tenantID := setup(t)
	_, err := st.Save(context.Background(), tenantID, "u1", Settings{
		Kind: "sms", Provider: "typo", Config: map[string]string{},
	})
	if !errors.Is(err, ErrUnknownProvider) {
		t.Fatalf("应拒绝未注册 provider，实际 %v", err)
	}
}
