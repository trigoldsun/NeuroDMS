package share

import (
	"context"
	"crypto/rand"
	"docvault/internal/dbtest"
	"encoding/hex"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"docvault/internal/auth"
	"docvault/internal/db"
	"docvault/migrations"

	"github.com/jackc/pgx/v5/pgxpool"
)

func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("DOCVAULT_TEST_DSN")
	if dsn == "" {
		t.Skip("未设置 DOCVAULT_TEST_DSN，跳过分享集成测试")
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

func seedTenantAndUser(t *testing.T, pool *pgxpool.Pool) (tenantID, userID string) {
	t.Helper()
	ctx := context.Background()
	tenantID = newUUID(t)
	userID = newUUID(t)

	if _, err := pool.Exec(ctx, `INSERT INTO tenant (id, slug, name) VALUES ($1,$2,$3)`,
		tenantID, "share-"+tenantID[:8], "分享测试租户"); err != nil {
		t.Fatalf("建租户失败: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO app_user (id, tenant_id, username, display_name) VALUES ($1,$2,$3,$4)`,
		userID, tenantID, "u_"+userID[:8], "测试用户"); err != nil {
		t.Fatalf("建用户失败: %v", err)
	}
	t.Cleanup(func() { dbtest.CleanupTenant(t, pool, tenantID) })
	return tenantID, userID
}

// seedSecondUser 在同一租户内建第二个用户，用于"审批人必须是他人的断言。
func seedSecondUser(t *testing.T, pool *pgxpool.Pool, tenantID string) string {
	t.Helper()
	id := newUUID(t)
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO app_user (id, tenant_id, username, display_name) VALUES ($1,$2,$3,$4)`,
		id, tenantID, "u_"+id[:8], "审批人"); err != nil {
		t.Fatalf("建第二个用户失败: %v", err)
	}
	return id
}

// 这是本项目的核心断言：一次性链接在并发下只能成功一次。
func TestOneTimeLinkOnlySucceedsOnce(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	tid, uid := seedTenantAndUser(t, pool)

	one := 1
	created, err := Create(ctx, pool, tid, uid, "node", newUUID(t), 0, Options{
		MaxUses: &one, Watermark: true, AllowDownload: false,
	})
	if err != nil {
		t.Fatalf("创建失败: %v", err)
	}

	const workers = 100
	var success, unavailable, other int64
	var wg sync.WaitGroup
	start := make(chan struct{})

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start // 同一时刻起跑，制造真实竞争
			_, err := Redeem(context.Background(), pool, created.Token, "", "203.0.113.9", "test-agent")
			switch {
			case err == nil:
				atomic.AddInt64(&success, 1)
			case err == ErrUnavailable:
				atomic.AddInt64(&unavailable, 1)
			default:
				atomic.AddInt64(&other, 1)
			}
		}()
	}
	close(start)
	wg.Wait()

	if other != 0 {
		t.Fatalf("出现非预期错误 %d 次（不应存在第三种结果）", other)
	}
	if success != 1 {
		t.Fatalf("一次性链接必须只成功 1 次，实际成功 %d 次", success)
	}
	if unavailable != workers-1 {
		t.Fatalf("其余应全部返回不可用，实际 %d", unavailable)
	}

	// 数据库侧的计数也必须恰好是 1
	var used int
	if err := pool.QueryRow(ctx, `SELECT used_count FROM share WHERE id=$1`, created.ID).Scan(&used); err != nil {
		t.Fatal(err)
	}
	if used != 1 {
		t.Fatalf("used_count 应为 1，实际 %d", used)
	}

	// 消费流水只能有 1 条成功记录
	var visits int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM share_visit WHERE share_id=$1 AND result='ok'`, created.ID).Scan(&visits); err != nil {
		t.Fatal(err)
	}
	if visits != 1 {
		t.Fatalf("成功消费流水应为 1 条，实际 %d", visits)
	}
}

func TestMultiUseLinkAllowsConfiguredTimes(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	tid, uid := seedTenantAndUser(t, pool)

	three := 3
	created, err := Create(ctx, pool, tid, uid, "node", newUUID(t), 0, Options{MaxUses: &three, Watermark: true})
	if err != nil {
		t.Fatal(err)
	}
	ok := 0
	for i := 0; i < 5; i++ {
		if _, err := Redeem(ctx, pool, created.Token, "", "", ""); err == nil {
			ok++
		}
	}
	if ok != 3 {
		t.Fatalf("应正好可用 3 次，实际 %d", ok)
	}
}

func TestRevokedLinkIsUnavailable(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	tid, uid := seedTenantAndUser(t, pool)

	created, err := Create(ctx, pool, tid, uid, "node", newUUID(t), 0, Options{Watermark: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Redeem(ctx, pool, created.Token, "", "", ""); err != nil {
		t.Fatalf("撤销前应可用: %v", err)
	}
	if err := Revoke(ctx, pool, tid, created.ID, uid); err != nil {
		t.Fatalf("撤销失败: %v", err)
	}
	if _, err := Redeem(ctx, pool, created.Token, "", "", ""); err != ErrUnavailable {
		t.Fatalf("撤销后必须不可用，实际 %v", err)
	}
}

func TestExpiredLinkIsUnavailable(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	tid, uid := seedTenantAndUser(t, pool)

	past := time.Now().Add(-time.Minute)
	created, err := Create(ctx, pool, tid, uid, "node", newUUID(t), 0, Options{ExpiresAt: &past, Watermark: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Redeem(ctx, pool, created.Token, "", "", ""); err != ErrUnavailable {
		t.Fatalf("过期链接必须不可用，实际 %v", err)
	}
}

// 不存在的链接与已用尽必须返回同一个错误，避免枚举。
func TestUnknownTokenSameErrorAsExhausted(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	tid, uid := seedTenantAndUser(t, pool)

	one := 1
	created, _ := Create(ctx, pool, tid, uid, "node", newUUID(t), 0, Options{MaxUses: &one})
	if _, err := Redeem(ctx, pool, created.Token, "", "", ""); err != nil {
		t.Fatal(err)
	}
	_, errExhausted := Redeem(ctx, pool, created.Token, "", "", "")
	_, errUnknown := Redeem(ctx, pool, "definitely-not-a-real-token", "", "", "")

	if errExhausted != ErrUnavailable || errUnknown != ErrUnavailable {
		t.Fatalf("两种情况必须返回同一错误：exhausted=%v unknown=%v", errExhausted, errUnknown)
	}
}

func TestTokenNotStoredInPlaintext(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	tid, uid := seedTenantAndUser(t, pool)

	created, _ := Create(ctx, pool, tid, uid, "node", newUUID(t), 0, Options{Watermark: true})

	// 库中不应出现明文 token（任何文本列都不该等于它）
	rows, err := pool.Query(ctx, `SELECT token_hint FROM share WHERE id=$1`, created.ID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var h string
		if err := rows.Scan(&h); err != nil {
			t.Fatal(err)
		}
		if h == created.Token {
			t.Fatal("token_hint 不得等于明文 token")
		}
	}
}

// 口令锁定必须按来源计数：别人锁不住你的链接。
//
// 缺陷原状：失败次数记在 share.failed_attempts（每条链接一份），
// 任何人拿到链接输错 6 次就能把它锁 30 分钟——**不需要知道口令**。
// 对"发给客户的交付链接"这是一次零成本的拒绝服务。
func TestPasswordLockoutIsPerSource(t *testing.T) {
	pool := testPool(t)
	tenantID, userID := seedTenantAndUser(t, pool)
	ctx := context.Background()

	hash, err := auth.HashPassword("join-2026")
	if err != nil {
		t.Fatalf("生成口令散列失败: %v", err)
	}
	c := newShare(t, pool, tenantID, userID, Options{PasswordHash: hash})

	const attacker = "203.0.113.9" // 攻击者所在网段
	const victim = "198.51.100.7"  // 真正的收件人所在网段

	// 攻击者在自己的网段里连错 6 次 → 只锁他自己
	for i := 1; i <= perSourceMaxAttempts; i++ {
		_, rerr := Redeem(ctx, pool, c.Token, "wrong-password", attacker, "ua")
		if i < perSourceMaxAttempts && rerr != ErrPasswordWrong {
			t.Fatalf("第 %d 次应只是口令错误，实际 %v", i, rerr)
		}
		if i == perSourceMaxAttempts && rerr != ErrLinkLocked {
			t.Fatalf("第 %d 次应触发锁定，实际 %v", i, rerr)
		}
	}

	// 同一来源即便口令正确也被锁（锁定期间不能继续尝试）
	if _, rerr := Redeem(ctx, pool, c.Token, "join-2026", attacker, "ua"); rerr != ErrLinkLocked {
		t.Fatalf("被锁来源即使口令正确也应拒绝，实际 %v", rerr)
	}

	// 关键断言：另一个来源仍然可以正常访问——链接没有被"锁死"
	if _, rerr := Redeem(ctx, pool, c.Token, "join-2026", victim, "ua"); rerr != nil {
		t.Fatalf("其他来源不应受影响，实际 %v", rerr)
	}

	// 链接本身不应被写成全局锁定（那正是原来被利用的字段）
	var locked *time.Time
	if err := pool.QueryRow(ctx,
		`SELECT locked_until FROM share WHERE id = $1`, c.ID).Scan(&locked); err != nil {
		t.Fatal(err)
	}
	if locked != nil {
		t.Fatalf("单来源爆破不应把整条链接锁死，实际 locked_until=%v", *locked)
	}
}
