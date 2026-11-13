package share

import (
	"context"
	"testing"
	"time"

	"docvault/internal/auth"
	"docvault/internal/db"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// objectID 用一个随机 uuid 即可：分享表不校验对象存在性（那是上层的职责），
// 这里只测策略与票据，不需要真的建节点。
func newShare(t *testing.T, pool *pgxpool.Pool, tenantID, userID string, opt Options) Created {
	t.Helper()
	c, err := Create(context.Background(), pool, tenantID, userID, "node", newUUID(t), 0, opt)
	if err != nil {
		t.Fatalf("创建分享失败: %v", err)
	}
	return c
}

func TestPasswordProtection(t *testing.T) {
	pool := testPool(t)
	tenantID, userID := seedTenantAndUser(t, pool)
	ctx := context.Background()

	hash, err := auth.HashPassword("SharePass-1")
	if err != nil {
		t.Fatal(err)
	}
	c := newShare(t, pool, tenantID, userID, Options{MaxUses: intp(2), PasswordHash: hash})

	// 不带口令：必须明确要求口令，而不是伪装成"链接无效"
	if _, err := Redeem(ctx, pool, c.Token, "", "203.0.113.7", "ua"); err != ErrPasswordRequired {
		t.Fatalf("无口令应返回 ErrPasswordRequired，实际 %v", err)
	}
	// 错误口令：必须明确报错，且不能消耗次数
	if _, err := Redeem(ctx, pool, c.Token, "wrong", "203.0.113.7", "ua"); err != ErrPasswordWrong {
		t.Fatalf("错误口令应返回 ErrPasswordWrong，实际 %v", err)
	}
	// 正确口令可用
	if _, err := Redeem(ctx, pool, c.Token, "SharePass-1", "203.0.113.7", "ua"); err != nil {
		t.Fatalf("正确口令应通过: %v", err)
	}

	// 关键断言：两次输错没有把次数吃掉，所以 max_uses=2 还剩 1 次
	if _, err := Redeem(ctx, pool, c.Token, "SharePass-1", "203.0.113.7", "ua"); err != nil {
		t.Fatalf("第二次使用应仍可用: %v", err)
	}
	if _, err := Redeem(ctx, pool, c.Token, "SharePass-1", "203.0.113.7", "ua"); err != ErrUnavailable {
		t.Fatalf("用尽后应不可用，实际 %v", err)
	}
}

func TestIPAllowlist(t *testing.T) {
	pool := testPool(t)
	tenantID, userID := seedTenantAndUser(t, pool)
	ctx := context.Background()

	c := newShare(t, pool, tenantID, userID, Options{IPAllowlist: []string{"203.0.113.0/24"}})

	if _, err := Redeem(ctx, pool, c.Token, "", "198.51.100.9", "ua"); err != ErrIPNotAllowed {
		t.Fatalf("白名单外应拒绝，实际 %v", err)
	}
	// 被拒也不能消耗次数
	if _, err := Redeem(ctx, pool, c.Token, "", "203.0.113.9", "ua"); err != nil {
		t.Fatalf("白名单内应放行: %v", err)
	}
}

func TestApprovalGate(t *testing.T) {
	pool := testPool(t)
	tenantID, userID := seedTenantAndUser(t, pool)
	ctx := context.Background()

	c := newShare(t, pool, tenantID, userID, Options{RequireApproval: true})

	if _, err := Redeem(ctx, pool, c.Token, "", "203.0.113.9", "ua"); err != ErrPendingApproval {
		t.Fatalf("待审批应拒绝，实际 %v", err)
	}

	// 审批必须由**他人**执行：自批会被拒（见 ErrSelfApproval）。
	approver := seedSecondUser(t, pool, tenantID)
	if err := Approve(ctx, pool, tenantID, c.ID, userID, false); err != ErrSelfApproval {
		t.Fatalf("自批应返回 ErrSelfApproval，实际 %v", err)
	}
	if err := Approve(ctx, pool, tenantID, c.ID, approver, false); err != nil {
		t.Fatalf("拒绝审批失败: %v", err)
	}
	if _, err := Redeem(ctx, pool, c.Token, "", "203.0.113.9", "ua"); err != ErrApprovalRejected {
		t.Fatalf("审批拒绝后应拒绝，实际 %v", err)
	}

	// 另一条链接走通过路径
	c2 := newShare(t, pool, tenantID, userID, Options{RequireApproval: true})
	if err := Approve(ctx, pool, tenantID, c2.ID, approver, true); err != nil {
		t.Fatalf("通过审批失败: %v", err)
	}
	if _, err := Redeem(ctx, pool, c2.Token, "", "203.0.113.9", "ua"); err != nil {
		t.Fatalf("审批通过后应可用: %v", err)
	}
}

func TestTicketLifecycle(t *testing.T) {
	pool := testPool(t)
	tenantID, userID := seedTenantAndUser(t, pool)
	ctx := context.Background()

	c := newShare(t, pool, tenantID, userID, Options{AllowDownload: true})
	res, err := Redeem(ctx, pool, c.Token, "", "203.0.113.9", "ua")
	if err != nil {
		t.Fatal(err)
	}

	ticket, expires, err := IssueTicket(ctx, pool, res, "203.0.113.9", time.Minute)
	if err != nil {
		t.Fatalf("签发票据失败: %v", err)
	}
	if !expires.After(time.Now()) {
		t.Fatal("票据应未过期")
	}

	got, err := ResolveTicket(ctx, pool, ticket, "203.0.113.9")
	if err != nil {
		t.Fatalf("票据应可用: %v", err)
	}
	if got.ShareID != res.ShareID || !got.AllowDownload {
		t.Fatalf("票据上下文不符: %+v", got)
	}

	// 换网段使用：票据绑定了来源网段，必须失败
	if _, err := ResolveTicket(ctx, pool, ticket, "198.51.100.9"); err != ErrTicketInvalid {
		t.Fatalf("跨网段使用票据应失败，实际 %v", err)
	}

	// 撤销分享后，已发出的票据必须立刻失效（这是"可收回"的关键）
	if err := Revoke(ctx, pool, tenantID, c.ID, userID); err != nil {
		t.Fatal(err)
	}
	if _, err := ResolveTicket(ctx, pool, ticket, "203.0.113.9"); err != ErrTicketInvalid {
		t.Fatalf("撤销后票据应失效，实际 %v", err)
	}
}

func TestExpiredTicketRejected(t *testing.T) {
	pool := testPool(t)
	tenantID, userID := seedTenantAndUser(t, pool)
	ctx := context.Background()

	c := newShare(t, pool, tenantID, userID, Options{})
	res, err := Redeem(ctx, pool, c.Token, "", "203.0.113.9", "ua")
	if err != nil {
		t.Fatal(err)
	}
	// 用极短 TTL 签票
	ticket, _, err := IssueTicket(ctx, pool, res, "203.0.113.9", 50*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(80 * time.Millisecond)
	if _, err := ResolveTicket(ctx, pool, ticket, "203.0.113.9"); err != ErrTicketInvalid {
		t.Fatalf("过期票据应失效，实际 %v", err)
	}
}

// 一次性链接的语义是"一个访客"，不是"一个字节"：
// 兑换后签出的票据在有效期内可以多次取字节（否则页面刷新就空白），
// 但链接本身不能被第二个访客再用。
func TestOneTimeTicketAllowsRepeatReadsWithinTTL(t *testing.T) {
	pool := testPool(t)
	tenantID, userID := seedTenantAndUser(t, pool)
	ctx := context.Background()

	c := newShare(t, pool, tenantID, userID, Options{MaxUses: intp(1)})
	res, err := Redeem(ctx, pool, c.Token, "", "203.0.113.9", "ua")
	if err != nil {
		t.Fatal(err)
	}
	ticket, _, err := IssueTicket(ctx, pool, res, "203.0.113.9", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if _, err := ResolveTicket(ctx, pool, ticket, "203.0.113.9"); err != nil {
			t.Fatalf("第 %d 次读取票据应成功: %v", i+1, err)
		}
	}
	// 但链接不能再换一张票据
	if _, err := Redeem(ctx, pool, c.Token, "", "203.0.113.9", "ua"); err != ErrUnavailable {
		t.Fatalf("一次性链接不应能再次兑换，实际 %v", err)
	}
}

func intp(v int) *int { return &v }

// 单测 ipPrefix 的归一化规则：IPv4 取 /24、IPv6 取 /64、非法输入返回空。
func TestIPPrefixNormalization(t *testing.T) {
	cases := map[string]string{
		"203.0.113.45": "203.0.113.0/24",
		"2001:db8::1":  "2001:db8::/64",
		"not-an-ip":    "",
	}
	for in, want := range cases {
		if got := ipPrefix(in); got != want {
			t.Fatalf("ipPrefix(%q) = %q, want %q", in, got, want)
		}
	}
}

// 确保撤销真的会 revoke 票据行，而不是只改 share 表（两道保险都要有）
func TestRevokeBulkRevokesTickets(t *testing.T) {
	pool := testPool(t)
	tenantID, userID := seedTenantAndUser(t, pool)
	ctx := context.Background()

	c := newShare(t, pool, tenantID, userID, Options{})
	res, err := Redeem(ctx, pool, c.Token, "", "203.0.113.9", "ua")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if _, _, err := IssueTicket(ctx, pool, res, "203.0.113.9", time.Minute); err != nil {
			t.Fatal(err)
		}
	}
	if err := Revoke(ctx, pool, tenantID, c.ID, userID); err != nil {
		t.Fatal(err)
	}
	var live int
	if err := db.WithTenant(ctx, pool, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT count(*) FROM share_ticket WHERE share_id = $1 AND revoked_at IS NULL`, c.ID).Scan(&live)
	}); err != nil {
		t.Fatal(err)
	}
	if live != 0 {
		t.Fatalf("撤销后不应有未失效票据，实际 %d", live)
	}
}
