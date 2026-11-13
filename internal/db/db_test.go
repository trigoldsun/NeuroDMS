package db

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"testing"

	"docvault/migrations"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// 集成测试需要真实数据库；未设置 DSN 时跳过，避免污染普通单元测试。
//
// 运行方式：
//
//	DOCVAULT_TEST_DSN="postgres://docvault:PW@127.0.0.1:55433/docvault?sslmode=disable" \
//	  go test ./internal/db/ -v
func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("DOCVAULT_TEST_DSN")
	if dsn == "" {
		t.Skip("未设置 DOCVAULT_TEST_DSN，跳过数据库集成测试")
	}
	pool, err := Connect(context.Background(), dsn)
	if err != nil {
		t.Fatalf("连接数据库失败: %v", err)
	}
	t.Cleanup(pool.Close)
	if _, err := Migrate(context.Background(), pool, migrations.Files); err != nil {
		t.Fatalf("迁移失败: %v", err)
	}
	return pool
}

func newUUID(t *testing.T) string {
	t.Helper()
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	dst := make([]byte, 36)
	hex.Encode(dst[0:8], b[0:4])
	dst[8] = '-'
	hex.Encode(dst[9:13], b[4:6])
	dst[13] = '-'
	hex.Encode(dst[14:18], b[6:8])
	dst[18] = '-'
	hex.Encode(dst[19:23], b[8:10])
	dst[23] = '-'
	hex.Encode(dst[24:36], b[10:16])
	return string(dst)
}

// 建租户与部门必须以平台身份（超级用户）执行，否则会被 RLS 拦在上下文之外。
func seedTenant(t *testing.T, pool *pgxpool.Pool, slug string) (tenantID, deptID string) {
	t.Helper()
	ctx := context.Background()
	tenantID = newUUID(t)
	deptID = newUUID(t)

	if _, err := pool.Exec(ctx,
		`INSERT INTO tenant (id, slug, name) VALUES ($1, $2, $3)`, tenantID, slug, "测试租户"); err != nil {
		t.Fatalf("插入租户失败: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO dept (id, tenant_id, path, name) VALUES ($1, $2, $3::ltree, $4)`,
		deptID, tenantID, "root."+slug, "测试部门"); err != nil {
		t.Fatalf("插入部门失败: %v", err)
	}
	t.Cleanup(func() {
		bg := context.Background()
		_, _ = pool.Exec(bg, `DELETE FROM dept WHERE tenant_id = $1`, tenantID)
		_, _ = pool.Exec(bg, `DELETE FROM app_user WHERE tenant_id = $1`, tenantID)
		_, _ = pool.Exec(bg, `DELETE FROM role WHERE tenant_id = $1`, tenantID)
		_, _ = pool.Exec(bg, `DELETE FROM tenant WHERE id = $1`, tenantID)
	})
	return tenantID, deptID
}

func TestMigrateIdempotent(t *testing.T) {
	pool := testPool(t)
	applied, err := Migrate(context.Background(), pool, migrations.Files)
	if err != nil {
		t.Fatalf("重复迁移应成功: %v", err)
	}
	if len(applied) != 0 {
		t.Fatalf("已应用的迁移不应重复执行，实际执行了 %v", applied)
	}
}

func TestTenantIsolation(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()

	tidA, _ := seedTenant(t, pool, "iso-a-"+newUUID(t)[:8])
	tidB, _ := seedTenant(t, pool, "iso-b-"+newUUID(t)[:8])

	var seenA int
	if err := WithTenant(ctx, pool, tidA, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM dept`).Scan(&seenA)
	}); err != nil {
		t.Fatalf("查询失败: %v", err)
	}
	if seenA != 1 {
		t.Fatalf("租户 A 应只看到自己的 1 条部门，实际 %d", seenA)
	}

	var seenB int
	if err := WithTenant(ctx, pool, tidB, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM dept`).Scan(&seenB)
	}); err != nil {
		t.Fatalf("查询失败: %v", err)
	}
	if seenB != 1 {
		t.Fatalf("租户 B 应只看到自己的 1 条部门，实际 %d", seenB)
	}

	// 反向确认：平台视角能看到两条，证明隔离不是"因为表里只有一条"
	var total int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM dept WHERE tenant_id IN ($1,$2)`, tidA, tidB).Scan(&total); err != nil {
		t.Fatal(err)
	}
	if total != 2 {
		t.Fatalf("平台视角应看到 2 条，实际 %d", total)
	}
}

func TestMissingTenantContextYieldsNoRows(t *testing.T) {
	pool := testPool(t)
	seedTenant(t, pool, "noctx-"+newUUID(t)[:8])
	ctx := context.Background()

	if err := WithTenant(ctx, pool, "", func(tx pgx.Tx) error { return nil }); err == nil {
		t.Fatal("空租户上下文应直接拒绝执行")
	}

	// 切到应用角色但不设置 tenant_id：RLS 应过滤掉全部行
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, "SET LOCAL ROLE "+AppRole); err != nil {
		t.Fatal(err)
	}
	var seen int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM dept`).Scan(&seen); err != nil {
		t.Fatalf("查询失败: %v", err)
	}
	if seen != 0 {
		t.Fatalf("未设置租户上下文时必须看不到任何行（fail-closed），实际看到 %d", seen)
	}
}

func TestCrossTenantInsertRejected(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	tidA, _ := seedTenant(t, pool, "wx-a-"+newUUID(t)[:8])
	tidB, _ := seedTenant(t, pool, "wx-b-"+newUUID(t)[:8])

	err := WithTenant(ctx, pool, tidA, func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx,
			`INSERT INTO dept (id, tenant_id, path, name) VALUES ($1, $2, $3::ltree, $4)`,
			newUUID(t), tidB, "root.hack", "越权部门")
		return e
	})
	if err == nil {
		t.Fatal("跨租户写入必须被 RLS 拒绝")
	}
}

func TestRLSCoveragePassesAndDetectsGap(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()

	missing, err := AssertRLSCoverage(ctx, pool)
	if err != nil {
		t.Fatalf("自检失败: %v", err)
	}
	if len(missing) != 0 {
		t.Fatalf("当前结构应全部具备 RLS，缺失: %+v", missing)
	}

	if _, err := pool.Exec(ctx, `CREATE TABLE tmp_rls_gap (id int, tenant_id uuid)`); err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = pool.Exec(context.Background(), `DROP TABLE IF EXISTS tmp_rls_gap`) }()

	missing, err = AssertRLSCoverage(ctx, pool)
	if err != nil {
		t.Fatal(err)
	}
	if len(missing) != 1 || missing[0].Table != "tmp_rls_gap" {
		t.Fatalf("应检出 tmp_rls_gap，实际 %+v", missing)
	}
}
