package auth

import (
	"context"
	"crypto/rand"
	"docvault/internal/dbtest"
	"encoding/hex"
	"os"
	"testing"
	"time"

	"docvault/internal/db"
	"docvault/migrations"

	"github.com/jackc/pgx/v5/pgxpool"
)

func svcPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("DOCVAULT_TEST_DSN")
	if dsn == "" {
		t.Skip("未设置 DOCVAULT_TEST_DSN，跳过认证集成测试")
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

const testPassword = "correct-horse-battery-2026"

func seedUser(t *testing.T, pool *pgxpool.Pool) (tenantSlug, username, tenantID, userID string) {
	t.Helper()
	ctx := context.Background()
	tenantID = uuid(t)
	userID = uuid(t)
	tenantSlug = "t-" + tenantID[:8]
	username = "alice"

	if _, err := pool.Exec(ctx, `INSERT INTO tenant (id, slug, name) VALUES ($1,$2,$3)`,
		tenantID, tenantSlug, "认证测试租户"); err != nil {
		t.Fatalf("建租户失败: %v", err)
	}
	hash, err := HashPassword(testPassword)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx, `
		INSERT INTO app_user (id, tenant_id, username, display_name, password_hash, status, ceiling)
		VALUES ($1,$2,$3,$4,$5,'active',4)`, userID, tenantID, username, "Alice", hash); err != nil {
		t.Fatalf("建用户失败: %v", err)
	}
	t.Cleanup(func() { dbtest.CleanupTenant(t, pool, tenantID) })
	return
}

func newService(pool *pgxpool.Pool) *Service {
	cfg := DefaultConfig()
	cfg.MaxFailed = 3
	cfg.MinPasswordLen = 12
	return New(pool, []byte("0123456789abcdef0123456789abcdef"), cfg)
}

func TestLoginSuccessAndVerify(t *testing.T) {
	pool := svcPool(t)
	svc := newService(pool)
	slug, user, _, userID := seedUser(t, pool)

	tk, err := svc.Login(context.Background(), slug, user, testPassword, LoginLocal, "203.0.113.9", "ua")
	if err != nil {
		t.Fatalf("登录失败: %v", err)
	}
	if tk.Access == "" || tk.Refresh == "" {
		t.Fatal("应返回访问令牌与刷新令牌")
	}
	c, err := svc.Verify(context.Background(), tk.Access)
	if err != nil {
		t.Fatalf("校验失败: %v", err)
	}
	if c.Subject != userID {
		t.Fatalf("subject 不符: %s", c.Subject)
	}
}

// 账号不存在与口令错误必须表现一致，防枚举。
func TestLoginUnknownTenantAndWrongPasswordSameError(t *testing.T) {
	pool := svcPool(t)
	svc := newService(pool)
	slug, user, _, _ := seedUser(t, pool)

	_, err1 := svc.Login(context.Background(), slug, user, "wrong-password", LoginLocal, "", "")
	_, err2 := svc.Login(context.Background(), "no-such-tenant", user, testPassword, LoginLocal, "", "")
	if err1 != ErrInvalidCredentials || err2 != ErrInvalidCredentials {
		t.Fatalf("两种情况应返回同一错误: wrong=%v unknownTenant=%v", err1, err2)
	}
}

func TestLoginLocksAfterMaxFailures(t *testing.T) {
	pool := svcPool(t)
	svc := newService(pool) // MaxFailed = 3
	slug, user, _, _ := seedUser(t, pool)

	for i := 0; i < 2; i++ {
		if _, err := svc.Login(context.Background(), slug, user, "bad", LoginLocal, "", ""); err != ErrInvalidCredentials {
			t.Fatalf("第 %d 次应为凭据错误，实际 %v", i+1, err)
		}
	}
	// 第 3 次触发锁定
	if _, err := svc.Login(context.Background(), slug, user, "bad", LoginLocal, "", ""); err != ErrAccountLocked {
		t.Fatalf("第 3 次失败应锁定，实际 %v", err)
	}
	// 锁定期间即使口令正确也拒绝
	if _, err := svc.Login(context.Background(), slug, user, testPassword, LoginLocal, "", ""); err != ErrAccountLocked {
		t.Fatalf("锁定期间应拒绝正确口令，实际 %v", err)
	}
}

func TestRefreshRotationInvalidatesOldToken(t *testing.T) {
	pool := svcPool(t)
	svc := newService(pool)
	slug, user, _, _ := seedUser(t, pool)

	tk, err := svc.Login(context.Background(), slug, user, testPassword, LoginLocal, "", "")
	if err != nil {
		t.Fatal(err)
	}
	tk2, err := svc.Refresh(context.Background(), tk.Refresh, "", "")
	if err != nil {
		t.Fatalf("刷新失败: %v", err)
	}
	if tk2.Refresh == tk.Refresh {
		t.Fatal("刷新令牌必须旋转（新旧不能相同）")
	}
	// 旧刷新令牌必须立即失效
	if _, err := svc.Refresh(context.Background(), tk.Refresh, "", ""); err != ErrSessionInvalid {
		t.Fatalf("旧刷新令牌应失效，实际 %v", err)
	}
	// 新令牌仍可用
	if _, err := svc.Refresh(context.Background(), tk2.Refresh, "", ""); err != nil {
		t.Fatalf("新刷新令牌应可用: %v", err)
	}
}

func TestChangePasswordRevokesAllSessions(t *testing.T) {
	pool := svcPool(t)
	svc := newService(pool)
	slug, user, _, _ := seedUser(t, pool)

	tk, err := svc.Login(context.Background(), slug, user, testPassword, LoginLocal, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.ChangePassword(context.Background(), tk.Access, testPassword, "a-whole-new-passphrase"); err != nil {
		t.Fatalf("改密失败: %v", err)
	}
	// 改密后旧刷新令牌必须失效
	if _, err := svc.Refresh(context.Background(), tk.Refresh, "", ""); err != ErrSessionInvalid {
		t.Fatalf("改密后旧会话应失效，实际 %v", err)
	}
	// 新口令可登录
	if _, err := svc.Login(context.Background(), slug, user, "a-whole-new-passphrase", LoginLocal, "", ""); err != nil {
		t.Fatalf("新口令应可登录: %v", err)
	}
}

func TestChangePasswordRejectsShortAndWrongOld(t *testing.T) {
	pool := svcPool(t)
	svc := newService(pool)
	slug, user, _, _ := seedUser(t, pool)

	tk, _ := svc.Login(context.Background(), slug, user, testPassword, LoginLocal, "", "")
	if err := svc.ChangePassword(context.Background(), tk.Access, testPassword, "short"); err != ErrWeakPassword {
		t.Fatalf("过短口令应拒绝，实际 %v", err)
	}
	if err := svc.ChangePassword(context.Background(), tk.Access, "wrong-old-one", "a-whole-new-passphrase"); err != ErrInvalidCredentials {
		t.Fatalf("旧口令错误应拒绝，实际 %v", err)
	}
}

func TestLogoutRevokesRefresh(t *testing.T) {
	pool := svcPool(t)
	svc := newService(pool)
	slug, user, _, _ := seedUser(t, pool)

	tk, _ := svc.Login(context.Background(), slug, user, testPassword, LoginLocal, "", "")
	if err := svc.Logout(context.Background(), tk.Refresh); err != nil {
		t.Fatalf("登出失败: %v", err)
	}
	if _, err := svc.Refresh(context.Background(), tk.Refresh, "", ""); err != ErrSessionInvalid {
		t.Fatalf("登出后刷新应失效，实际 %v", err)
	}
}

var _ = time.Minute
