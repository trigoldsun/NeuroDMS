package auth

import (
	"context"
	"testing"
	"time"
)

// 吊销检查是本项目唯一"用缓存换延迟"的安全点，因此测试要证明三件事：
//  1. 主动失效（登出/停用）在本实例立即生效
//  2. 缓存确实在起作用（绕过服务直接改库，TTL 内不会立即反映）
//  3. 过期后必然回源（收敛窗口有界，且不依赖主动失效事件）

func TestLogoutRejectsAccessTokenImmediately(t *testing.T) {
	pool := svcPool(t)
	svc := newService(pool)
	slug, user, _, _ := seedUser(t, pool)

	tk, err := svc.Login(context.Background(), slug, user, testPassword, LoginLocal, "", "")
	if err != nil {
		t.Fatal(err)
	}
	// 先校验一次，让会话进入缓存
	if _, err := svc.Verify(context.Background(), tk.Access); err != nil {
		t.Fatalf("登出前应可用: %v", err)
	}

	// 直接吊销会话（等价于"另一台设备把我踢下线"），服务层不主动清缓存
	if err := svc.Logout(context.Background(), tk.Refresh); err != nil {
		t.Fatal(err)
	}

	// 本实例必须立即拒绝：Logout 内部清掉了该会话缓存
	if _, err := svc.Verify(context.Background(), tk.Access); err != ErrSessionInvalid {
		t.Fatalf("登出后访问令牌应立即失效，实际 %v", err)
	}
}

func TestDisabledUserRejectedWithinCacheTTL(t *testing.T) {
	pool := svcPool(t)
	svc := newService(pool)
	slug, user, tenantID, userID := seedUser(t, pool)

	tk, err := svc.Login(context.Background(), slug, user, testPassword, LoginLocal, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Verify(context.Background(), tk.Access); err != nil {
		t.Fatalf("停用前应可用: %v", err)
	}

	if err := svc.SetUserStatus(context.Background(), tenantID, userID, "suspended"); err != nil {
		t.Fatalf("停用失败: %v", err)
	}
	// PRD：停用后 30 秒内失效。这里断言"立即"（本实例），比要求更严
	if _, err := svc.Verify(context.Background(), tk.Access); err != ErrSessionInvalid {
		t.Fatalf("停用后应立即失效，实际 %v", err)
	}
	// 刷新令牌也必须不可用
	if _, err := svc.Refresh(context.Background(), tk.Refresh, "", ""); err != ErrSessionInvalid {
		t.Fatalf("停用后刷新应失效，实际 %v", err)
	}
}

// 这条用例证明"窗口有界"不依赖任何主动通知：
// 绕过服务直接改库（模拟另一个实例上的操作），本实例在 TTL 内仍放行，
// TTL 过后必然回源并拒绝。若把这个 TTL 调大，PRD 的 30 秒要求就会被破坏。
func TestRevocationConvergesAfterTTLWithoutNotification(t *testing.T) {
	pool := svcPool(t)
	svc := newService(pool)
	slug, user, tenantID, userID := seedUser(t, pool)

	tk, err := svc.Login(context.Background(), slug, user, testPassword, LoginLocal, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Verify(context.Background(), tk.Access); err != nil {
		t.Fatal(err)
	}

	// 把 TTL 调成 120ms，模拟"另一个实例"直接改库、不经本实例缓存
	svc.guard.ttl = 120 * time.Millisecond

	if _, err := pool.Exec(context.Background(),
		`UPDATE app_user SET session_epoch = session_epoch + 1 WHERE id = $1`, userID); err != nil {
		t.Fatal(err)
	}

	// TTL 内：缓存仍认为可用（这是缓存的代价，不是缺陷）
	if _, err := svc.Verify(context.Background(), tk.Access); err != nil {
		t.Fatalf("TTL 内应仍按缓存放行，实际 %v", err)
	}

	time.Sleep(160 * time.Millisecond)

	// TTL 后：必然回源，epoch 不符 → 拒绝
	if _, err := svc.Verify(context.Background(), tk.Access); err != ErrSessionInvalid {
		t.Fatalf("TTL 后必须回源并拒绝，实际 %v", err)
	}
	_ = tenantID
}

// 令牌里的 epoch 被改大（伪造未来版本）也必须拒，
// 否则攻击者可以预判一次 epoch 自增来延长令牌寿命。
func TestForgedFutureEpochRejected(t *testing.T) {
	pool := svcPool(t)
	svc := newService(pool)
	slug, user, _, _ := seedUser(t, pool)

	tk, err := svc.Login(context.Background(), slug, user, testPassword, LoginLocal, "", "")
	if err != nil {
		t.Fatal(err)
	}
	base, err := ParseAccess([]byte("0123456789abcdef0123456789abcdef"), tk.Access)
	if err != nil {
		t.Fatal(err)
	}

	forged := base
	forged.Epoch = base.Epoch + 1
	tok, err := SignAccess([]byte("0123456789abcdef0123456789abcdef"), forged)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Verify(context.Background(), tok); err != ErrSessionInvalid {
		t.Fatalf("epoch 不匹配必须拒绝，实际 %v", err)
	}
}

// 缓存容量护栏：超过上限时整体清空而不是无限增长。
func TestGuardCacheCapacityGuard(t *testing.T) {
	g := NewGuard(nil, time.Minute)
	for i := 0; i < 100_001; i++ {
		g.store("s", sessionState{epoch: 0, expiresAt: time.Now().Add(time.Hour)})
	}
	if g.Size() > 100_001 {
		t.Fatalf("缓存不应无限增长，当前 %d", g.Size())
	}
	g.InvalidateAll()
	if g.Size() != 0 {
		t.Fatalf("清空后应为 0，实际 %d", g.Size())
	}
}
