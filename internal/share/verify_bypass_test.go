package share

// AC-50 / AC-51 的回归测试。
//
// 这里钉的不是"验证码对不对"，而是一条更基础的性质：
// **没走验证流程就不可能换到票据**。
// 曾经 Redeem 完全不看 share.require_verify，直接调
// GET /v1/public/shares/{token} 就能拿到 ticket，
// 白名单、一次性验证码、连错锁定全部形同虚设。

import (
	"context"
	"testing"
)

func TestRedeemRejectsWhenVerifyRequired(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	tid, uid := seedTenantAndUser(t, pool)

	created, err := Create(ctx, pool, tid, uid, "node", newUUID(t), 0, Options{
		RequireVerify:  true,
		EmailWhitelist: []string{"@example.com"},
	})
	if err != nil {
		t.Fatalf("创建失败: %v", err)
	}

	// 1) 跳过验证直接兑换：必须被拒，且不能消费链接
	if _, err := Redeem(ctx, pool, created.Token, "", "203.0.113.7", "t"); err != ErrVerifyRequired {
		t.Fatalf("未验证的兑换应返回 ErrVerifyRequired，实际 %v", err)
	}

	var used int
	if err := pool.QueryRow(ctx, `SELECT used_count FROM share WHERE id=$1`, created.ID).Scan(&used); err != nil {
		t.Fatal(err)
	}
	if used != 0 {
		t.Fatalf("被拒的兑换不应消耗链接，used_count=%d", used)
	}

	// 2) 这次尝试必须留下流水（否则"有人在绕过验证"永远查不到）
	var denied int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM share_visit WHERE share_id=$1 AND result='verify_required'`,
		created.ID).Scan(&denied); err != nil {
		t.Fatal(err)
	}
	if denied != 1 {
		t.Fatalf("应有 1 条 verify_required 流水，实际 %d", denied)
	}

	// 3) 走完验证流程后可以兑换；且验证记录被消费，不能再用第二次
	if _, _, err := RecordVerify(ctx, pool, VerifyPolicy{
		TenantID: tid, ShareID: created.ID, RequireVerify: true,
		Whitelist: []string{"@example.com"},
	}, "alice@example.com", "203.0.113.7", DefaultVerifyTTL); err != nil {
		t.Fatalf("记录验证失败: %v", err)
	}
	if _, err := RedeemWithVerify(ctx, pool, created.Token, "", "alice@example.com",
		"203.0.113.7", "t"); err != nil {
		t.Fatalf("验证后应能兑换，实际 %v", err)
	}

	if _, err := RedeemWithVerify(ctx, pool, created.Token, "", "alice@example.com",
		"203.0.113.7", "t"); err != ErrVerifyRequired {
		t.Fatalf("验证记录只能用一次，第二次应返回 ErrVerifyRequired，实际 %v", err)
	}
}

// 不需要验证的链接不能被误伤：这是"加了强制校验"最容易引入的回归。
func TestRedeemStillWorksWithoutVerify(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()
	tid, uid := seedTenantAndUser(t, pool)

	created, err := Create(ctx, pool, tid, uid, "node", newUUID(t), 0, Options{})
	if err != nil {
		t.Fatalf("创建失败: %v", err)
	}
	if _, err := Redeem(ctx, pool, created.Token, "", "203.0.113.8", "t"); err != nil {
		t.Fatalf("未要求验证的链接应能直接兑换，实际 %v", err)
	}
}
