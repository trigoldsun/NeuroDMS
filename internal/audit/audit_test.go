package audit

import (
	"context"
	"crypto/rand"
	"docvault/internal/dbtest"
	"encoding/hex"
	"os"
	"testing"

	"docvault/internal/db"
	"docvault/migrations"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("DOCVAULT_TEST_DSN")
	if dsn == "" {
		t.Skip("未设置 DOCVAULT_TEST_DSN，跳过审计集成测试")
	}
	pool, err := db.Connect(context.Background(), dsn)
	if err != nil {
		t.Fatalf("连接失败: %v", err)
	}
	t.Cleanup(pool.Close)
	if _, err := db.Migrate(context.Background(), pool, migrations.Files); err != nil {
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

func seedTenant(t *testing.T, pool *pgxpool.Pool) string {
	t.Helper()
	id := newUUID(t)
	ctx := context.Background()
	if _, err := pool.Exec(ctx, `INSERT INTO tenant (id, slug, name) VALUES ($1,$2,$3)`,
		id, "audit-"+id[:8], "审计测试租户"); err != nil {
		t.Fatalf("建租户失败: %v", err)
	}
	t.Cleanup(func() { dbtest.CleanupTenant(t, pool, id) })
	return id
}

func TestAppendAndVerifyChain(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	tid := seedTenant(t, pool)

	for i := 0; i < 5; i++ {
		err := db.WithTenant(ctx, pool, tid, func(tx pgx.Tx) error {
			return Append(ctx, tx, tid, Event{
				ActorID: "", ActorType: "system", Action: "test.append",
				Result: ResultOK, Detail: map[string]any{"i": i, "note": `含引号的"文件名".pdf`},
			})
		})
		if err != nil {
			t.Fatalf("第 %d 条写入失败: %v", i, err)
		}
	}

	n, err := Verify(ctx, pool, tid)
	if err != nil {
		t.Fatalf("链校验失败: %v", err)
	}
	if n != 5 {
		t.Fatalf("应校验 5 条，实际 %d", n)
	}
}

// 篡改检测：直接插入一条哈希错误的记录（模拟绕过应用写入），校验必须报错。
func TestVerifyDetectsForgedRecord(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	tid := seedTenant(t, pool)

	if err := db.WithTenant(ctx, pool, tid, func(tx pgx.Tx) error {
		return Append(ctx, tx, tid, Event{Action: "a", Result: ResultOK})
	}); err != nil {
		t.Fatal(err)
	}

	// 以平台身份（超级用户）伪造第 2 条，hash 故意填错
	if _, err := pool.Exec(ctx, `
		INSERT INTO audit_event (id, tenant_id, seq, actor_type, action, result, prev_hash, hash)
		VALUES (gen_random_uuid(), $1, 2, 'system', 'forged', 'ok', NULL, '\xdeadbeef')`, tid); err != nil {
		t.Fatalf("伪造记录失败: %v", err)
	}

	if _, err := Verify(ctx, pool, tid); err == nil {
		t.Fatal("伪造记录必须被检出")
	}
}

// 只追加：应用角色不能 UPDATE/DELETE（规则 + 权限双保险）。
func TestAuditIsAppendOnly(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	tid := seedTenant(t, pool)

	if err := db.WithTenant(ctx, pool, tid, func(tx pgx.Tx) error {
		return Append(ctx, tx, tid, Event{Action: "immutable", Result: ResultOK})
	}); err != nil {
		t.Fatal(err)
	}

	// 应用角色连权限都没有（GRANT 只给 SELECT/INSERT）——这是第一道防线，
	// 所以这里期望的是"被拒绝"，比"静默删 0 行"更强。
	err := db.WithTenant(ctx, pool, tid, func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `DELETE FROM audit_event WHERE tenant_id = $1`, tid)
		return e
	})
	if err == nil {
		t.Fatal("应用角色不应有权删除审计事件")
	}

	// 第二道防线：即使以表属主身份删除，规则也会把语句改写为"什么都不做"。
	// 迁移 0014 起规则改为读会话开关，未开启时依然完全禁止。
	if _, derr := pool.Exec(ctx, `DELETE FROM audit_event WHERE tenant_id = $1`, tid); derr != nil {
		t.Fatalf("属主删除不应报错（规则会静默拦截）: %v", derr)
	}

	var count int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM audit_event WHERE tenant_id=$1`, tid).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("审计记录应不可删除，实际剩余 %d", count)
	}
}

func TestAppendRejectsEmptyTenant(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	// 空租户上下文必须在进入事务前就被拒
	err := db.WithTenant(ctx, pool, "", func(tx pgx.Tx) error {
		return Append(ctx, tx, "", Event{Action: "x", Result: ResultOK})
	})
	if err == nil {
		t.Fatal("空租户应被拒绝")
	}
}

// PostgreSQL 的 inet 文本会补上主机掩码，写入时哈希的是不带掩码的地址。
// 曾经因此让**每一条带 IP 的记录**都校验失败——链本身没坏，是两种文本表示不一致。
// 这个用例把"读回来必须还原"钉住，避免以后有人把这段当成无用代码删掉。
func TestNormalizeIPText(t *testing.T) {
	cases := []struct{ in, want string }{
		{"172.25.0.1/32", "172.25.0.1"},
		{"2001:db8::1/128", "2001:db8::1"},
		{"172.25.0.1", "172.25.0.1"},
		{"", ""},
		{"10.0.0.0/8", "10.0.0.0/8"}, // 真正的网段不动
	}
	for _, c := range cases {
		if got := normalizeIPText(c.in); got != c.want {
			t.Errorf("normalizeIPText(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
