package auth

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// fakeSender 记录发出的验证码，避免测试依赖真实邮件通道。
type fakeSender struct {
	lastCode string
	lastTo   string
	err      error
	calls    int
}

func (f *fakeSender) SendCode(_ context.Context, _, to, _, code string) error {
	f.calls++
	f.lastTo = to
	f.lastCode = code
	return f.err
}

func seedUserWithMFA(t *testing.T, pool *pgxpool.Pool, email string) (slug, username, tenantID, userID string) {
	t.Helper()
	slug, username, tenantID, userID = seedUser(t, pool)
	if _, err := pool.Exec(context.Background(), `
		UPDATE app_user SET email = $2, mfa_required = true, principal_type = 'external' WHERE id = $1`,
		userID, email); err != nil {
		t.Fatalf("设置 MFA 失败: %v", err)
	}
	return slug, username, tenantID, userID
}

func newOTP(pool *pgxpool.Pool, cfg OTPConfig) *OTPStore {
	return NewOTPStore(pool, []byte("0123456789abcdef0123456789abcdef"), cfg)
}

func TestOTPIssueAndVerifyOnce(t *testing.T) {
	pool := svcPool(t)
	otp := newOTP(pool, DefaultOTPConfig())
	_, _, tenantID, _ := seedUser(t, pool)
	ctx := context.Background()

	code, expires, err := otp.Issue(ctx, tenantID, "user@example.com", "test")
	if err != nil {
		t.Fatal(err)
	}
	if len(code) != 6 {
		t.Fatalf("验证码应为 6 位，实际 %q", code)
	}
	if !expires.After(time.Now()) {
		t.Fatal("有效期应为将来")
	}
	if err := otp.Verify(ctx, tenantID, "user@example.com", "test", code); err != nil {
		t.Fatalf("首次校验应通过: %v", err)
	}
	// 一码一次：重放必须失败
	if err := otp.Verify(ctx, tenantID, "user@example.com", "test", code); err != ErrCodeInvalid {
		t.Fatalf("验证码重放应失败，实际 %v", err)
	}
}

func TestOTPWrongCodeCountsAttempts(t *testing.T) {
	pool := svcPool(t)
	cfg := DefaultOTPConfig()
	cfg.MaxAttempts = 3
	otp := newOTP(pool, cfg)
	_, _, tenantID, _ := seedUser(t, pool)
	ctx := context.Background()

	code, _, err := otp.Issue(ctx, tenantID, "user@example.com", "test")
	if err != nil {
		t.Fatal(err)
	}

	for i := 0; i < 3; i++ {
		if err := otp.Verify(ctx, tenantID, "user@example.com", "test", "000000"); err != ErrCodeInvalid {
			t.Fatalf("第 %d 次错误码应失败，实际 %v", i+1, err)
		}
	}
	// 达到上限后，即使输入正确码也必须拒绝（否则上限形同虚设）
	if err := otp.Verify(ctx, tenantID, "user@example.com", "test", code); err != ErrCodeInvalid {
		t.Fatalf("超过尝试上限后正确码也应被拒，实际 %v", err)
	}
}

func TestOTPExpired(t *testing.T) {
	pool := svcPool(t)
	cfg := DefaultOTPConfig()
	cfg.TTL = 30 * time.Millisecond
	otp := newOTP(pool, cfg)
	_, _, tenantID, _ := seedUser(t, pool)
	ctx := context.Background()

	code, _, err := otp.Issue(ctx, tenantID, "user@example.com", "test")
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(60 * time.Millisecond)
	if err := otp.Verify(ctx, tenantID, "user@example.com", "test", code); err != ErrCodeInvalid {
		t.Fatalf("过期验证码应失败，实际 %v", err)
	}
}

func TestOTPRateLimited(t *testing.T) {
	pool := svcPool(t)
	cfg := DefaultOTPConfig()
	cfg.MaxPerWindow = 3
	otp := newOTP(pool, cfg)
	_, _, tenantID, _ := seedUser(t, pool)
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		if _, _, err := otp.Issue(ctx, tenantID, "user@example.com", "test"); err != nil {
			t.Fatalf("第 %d 次签发应成功: %v", i+1, err)
		}
	}
	if _, _, err := otp.Issue(ctx, tenantID, "user@example.com", "test"); err != ErrTooManyCodes {
		t.Fatalf("超频应返回 ErrTooManyCodes，实际 %v", err)
	}
}

// 最新一条码才是有效码：先请求 3 次再试最早那条，"旧码"不能被接受。
func TestOTPOnlyLatestCodeValid(t *testing.T) {
	pool := svcPool(t)
	otp := newOTP(pool, DefaultOTPConfig())
	_, _, tenantID, _ := seedUser(t, pool)
	ctx := context.Background()

	first, _, err := otp.Issue(ctx, tenantID, "user@example.com", "test")
	if err != nil {
		t.Fatal(err)
	}
	second, _, err := otp.Issue(ctx, tenantID, "user@example.com", "test")
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Skip("随机生成相同码，概率极低，跳过")
	}
	if err := otp.Verify(ctx, tenantID, "user@example.com", "test", first); err != ErrCodeInvalid {
		t.Fatalf("旧码应被拒，实际 %v", err)
	}
	if err := otp.Verify(ctx, tenantID, "user@example.com", "test", second); err != nil {
		t.Fatalf("最新码应通过: %v", err)
	}
}

// ---------------- 登录二次验证 ----------------

func TestLoginRequiresMFAAndThenSucceeds(t *testing.T) {
	pool := svcPool(t)
	svc := newService(pool)
	sender := &fakeSender{}
	svc.SetMFA(newOTP(pool, DefaultOTPConfig()), sender)

	slug, user, tenantID, _ := seedUserWithMFA(t, pool, "External.User@Example.com")
	ctx := context.Background()

	_, err := svc.Login(ctx, slug, user, testPassword, LoginLocal, "203.0.113.9", "ua")
	var ch *MFAChallenge
	if !errors.As(err, &ch) {
		t.Fatalf("应要求二次验证，实际 %v", err)
	}
	if ch.Challenge == "" {
		t.Fatal("应返回挑战串")
	}
	// 邮箱回显必须脱敏
	if strings.Contains(ch.SentTo, "External.User") {
		t.Fatalf("回显应脱敏，实际 %s", ch.SentTo)
	}
	if sender.calls != 1 || len(sender.lastCode) != 6 {
		t.Fatalf("应发出一次 6 位验证码，实际 calls=%d code=%q", sender.calls, sender.lastCode)
	}

	// 关键：此时不应产生任何可用会话
	var sessions int
	// 必须带 tenant_id：各测试的租户不同但用户名都叫 alice，
	// 只按 username 查会命中多行（全量跑时必现的 21000 错误）。
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM session WHERE user_id = (
		SELECT id FROM app_user WHERE username = $1 AND tenant_id = $2::uuid)`,
		user, tenantID).Scan(&sessions); err != nil {
		t.Fatal(err)
	}
	if sessions != 0 {
		t.Fatalf("二次验证未完成前不得建会话，实际 %d 条", sessions)
	}

	tk, err := svc.VerifyMFA(ctx, ch.Challenge, sender.lastCode, "203.0.113.9", "ua")
	if err != nil {
		t.Fatalf("验证码正确应签发令牌: %v", err)
	}
	if _, err := svc.Verify(ctx, tk.Access); err != nil {
		t.Fatalf("签发的令牌应可用: %v", err)
	}
}

func TestMFAWrongCodeRejected(t *testing.T) {
	pool := svcPool(t)
	svc := newService(pool)
	sender := &fakeSender{}
	svc.SetMFA(newOTP(pool, DefaultOTPConfig()), sender)

	slug, user, _, _ := seedUserWithMFA(t, pool, "ext@example.com")
	ctx := context.Background()

	_, err := svc.Login(ctx, slug, user, testPassword, LoginLocal, "", "")
	var ch *MFAChallenge
	if !errors.As(err, &ch) {
		t.Fatalf("应要求二次验证，实际 %v", err)
	}

	wrong := "000000"
	if wrong == sender.lastCode {
		wrong = "111111"
	}
	if _, err := svc.VerifyMFA(ctx, ch.Challenge, wrong, "", ""); err != ErrCodeInvalid {
		t.Fatalf("错误验证码应失败，实际 %v", err)
	}
}

func TestMFAChallengeTamperRejected(t *testing.T) {
	pool := svcPool(t)
	svc := newService(pool)
	svc.SetMFA(newOTP(pool, DefaultOTPConfig()), &fakeSender{})

	slug, user, _, _ := seedUserWithMFA(t, pool, "ext@example.com")
	ctx := context.Background()
	_, err := svc.Login(ctx, slug, user, testPassword, LoginLocal, "", "")
	var ch *MFAChallenge
	if !errors.As(err, &ch) {
		t.Fatalf("应要求二次验证，实际 %v", err)
	}

	tampered := ch.Challenge[:len(ch.Challenge)-2] + "aa"
	if _, err := svc.VerifyMFA(ctx, tampered, "123456", "", ""); err != ErrChallengeStale {
		t.Fatalf("篡改挑战串应失败，实际 %v", err)
	}
}

// 未配置投递通道时必须拒登，而不是"跳过二次验证直接放行"。
func TestMFAWithoutSenderFailsClosed(t *testing.T) {
	pool := svcPool(t)
	svc := newService(pool) // 未 SetMFA

	slug, user, _, _ := seedUserWithMFA(t, pool, "ext@example.com")
	if _, err := svc.Login(context.Background(), slug, user, testPassword, LoginLocal, "", ""); err != ErrAccountDisabled {
		t.Fatalf("未配置通道应拒登，实际 %v", err)
	}
}

func TestMFASendFailureFailsClosed(t *testing.T) {
	pool := svcPool(t)
	svc := newService(pool)
	svc.SetMFA(newOTP(pool, DefaultOTPConfig()), &fakeSender{err: errors.New("SMTP 不可达")})

	slug, user, _, _ := seedUserWithMFA(t, pool, "ext@example.com")
	if _, err := svc.Login(context.Background(), slug, user, testPassword, LoginLocal, "", ""); err == nil {
		t.Fatal("验证码发不出去时不应返回成功")
	}
}
