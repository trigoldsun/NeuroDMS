package sms

import (
	"context"
	"os"
	"testing"
	"time"

	"docvault/internal/db"
	"docvault/internal/dbtest"
	"docvault/migrations"
)

// 本地核验的四条硬规则（docs/47 §4.5.2）：
//  1. 正确的码只能成功一次（消费后失效）；
//  2. 错码累计 5 次后，即使后来输对也不认（必须重发）；
//  3. 5 分钟后失效；
//  4. 同一个号新码覆盖旧码（连点两次不该有两个有效码）。
func setupCodeStore(t *testing.T) (*Service, string) {
	t.Helper()
	dsn := os.Getenv("DOCVAULT_TEST_DSN")
	if dsn == "" {
		t.Skip("未设置 DOCVAULT_TEST_DSN，跳过本地验证码测试")
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
	slug := "smscode-" + time.Now().Format("150405-000000")
	if err := pool.QueryRow(ctx,
		`INSERT INTO tenant (id, slug, name, edition) VALUES (gen_random_uuid(), $1, $2, 'business')
		 RETURNING id::text`, slug, "验证码测试租户").Scan(&id); err != nil {
		t.Fatalf("建租户失败: %v", err)
	}
	t.Cleanup(func() { dbtest.CleanupTenant(t, pool, id) })
	return NewService(pool, nil, []byte("0123456789abcdef0123456789abcdef"), nil), id
}

func TestLocalCodeSingleUse(t *testing.T) {
	svc, tenantID := setupCodeStore(t)
	ctx := context.Background()
	phone := "+8613800138000"

	if err := svc.issue(ctx, tenantID, phone, "fake", "123456"); err != nil {
		t.Fatalf("写入验证码失败: %v", err)
	}
	ok, err := svc.verifyLocal(ctx, tenantID, phone, "123456")
	if err != nil || !ok {
		t.Fatalf("正确验证码应通过: ok=%v err=%v", ok, err)
	}
	ok, _ = svc.verifyLocal(ctx, tenantID, phone, "123456")
	if ok {
		t.Fatal("同一个验证码不能被使用两次")
	}
}

func TestLocalCodeAttemptLimit(t *testing.T) {
	svc, tenantID := setupCodeStore(t)
	ctx := context.Background()
	phone := "+8613800138001"

	if err := svc.issue(ctx, tenantID, phone, "fake", "654321"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		if ok, _ := svc.verifyLocal(ctx, tenantID, phone, "000000"); ok {
			t.Fatal("错码不应通过")
		}
	}
	if ok, _ := svc.verifyLocal(ctx, tenantID, phone, "654321"); ok {
		t.Fatal("错 5 次后正确码也应拒绝（必须重发）")
	}
}

func TestLocalCodeExpiry(t *testing.T) {
	svc, tenantID := setupCodeStore(t)
	ctx := context.Background()
	phone := "+8613800138002"

	if err := svc.issue(ctx, tenantID, phone, "fake", "111222"); err != nil {
		t.Fatal(err)
	}
	// 把"现在"推到 6 分钟后：码已过期
	svc.SetNow(func() time.Time { return time.Now().Add(6 * time.Minute) })
	if ok, _ := svc.verifyLocal(ctx, tenantID, phone, "111222"); ok {
		t.Fatal("过期验证码不应通过")
	}
}

func TestLocalCodeOverwrite(t *testing.T) {
	svc, tenantID := setupCodeStore(t)
	ctx := context.Background()
	phone := "+8613800138003"

	if err := svc.issue(ctx, tenantID, phone, "fake", "111111"); err != nil {
		t.Fatal(err)
	}
	if err := svc.issue(ctx, tenantID, phone, "fake", "222222"); err != nil {
		t.Fatal(err)
	}
	if ok, _ := svc.verifyLocal(ctx, tenantID, phone, "111111"); ok {
		t.Fatal("旧码应被新码覆盖")
	}
	if ok, _ := svc.verifyLocal(ctx, tenantID, phone, "222222"); !ok {
		t.Fatal("新码应通过")
	}
}
