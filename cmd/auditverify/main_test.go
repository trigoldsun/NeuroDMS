package main

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"docvault/internal/audit"
	"docvault/internal/db"
	"docvault/internal/dbtest"
	"docvault/migrations"

	"github.com/jackc/pgx/v5/pgxpool"
)

func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("DOCVAULT_TEST_DSN")
	if dsn == "" {
		t.Skip("未设置 DOCVAULT_TEST_DSN，跳过校验器测试")
	}
	pool, err := db.Connect(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	if _, err := db.Migrate(context.Background(), pool, migrations.Files); err != nil {
		t.Fatal(err)
	}
	return pool
}

func seed(t *testing.T, pool *pgxpool.Pool, n int) string {
	t.Helper()
	ctx := context.Background()
	var id string
	if err := pool.QueryRow(ctx,
		`INSERT INTO tenant (id, slug, name) VALUES (gen_random_uuid(), $1, $2) RETURNING id::text`,
		fmt.Sprintf("verify-%d", time.Now().UnixNano()), "校验器测试").Scan(&id); err != nil {
		t.Fatal(err)
	}
	// 用统一清理：审计表有只追加规则，手工 DELETE 会静默失效并留下残留租户
	t.Cleanup(func() { dbtest.CleanupTenant(t, pool, id) })

	for i := 0; i < n; i++ {
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, `SELECT set_config('app.tenant_id', $1, true)`, id); err != nil {
			_ = tx.Rollback(ctx)
			t.Fatal(err)
		}
		if err := audit.Append(ctx, tx, id, audit.Event{
			ActorType: "user", Action: "verify.test", Result: audit.ResultOK,
			Detail: map[string]any{"i": i},
		}); err != nil {
			_ = tx.Rollback(ctx)
			t.Fatal(err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
	}
	return id
}

func toVerifyBundle(t *testing.T, pool *pgxpool.Pool, tenantID string, secret string) (bundle, []byte) {
	t.Helper()
	ctx := context.Background()
	if _, err := audit.AnchorDay(ctx, pool, tenantID, time.Now().UTC(), []byte(secret)); err != nil {
		t.Fatal(err)
	}
	raw, err := audit.Export(ctx, pool, tenantID, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	var b bundle
	if err := json.Unmarshal(raw, &b); err != nil {
		t.Fatalf("证据包应可解析: %v", err)
	}
	return b, raw
}

func TestVerifierAcceptsGenuineBundle(t *testing.T) {
	pool := testPool(t)
	tenantID := seed(t, pool, 3)
	secret := "anchor-secret-0123456789abcdef"
	b, _ := toVerifyBundle(t, pool, tenantID, secret)

	if problems := verifyChain(b.Events); len(problems) != 0 {
		t.Fatalf("真实数据不应有问题: %v", problems)
	}
	if problems := verifyAnchors(b.Events, b.Anchors, secret); len(problems) != 0 {
		t.Fatalf("锚点校验不应有问题: %v", problems)
	}
}

// 改动事件内容后，哈希必然不匹配——这是校验器的核心价值。
func TestVerifierDetectsEditedEvent(t *testing.T) {
	pool := testPool(t)
	tenantID := seed(t, pool, 3)
	secret := "anchor-secret-0123456789abcdef"
	b, _ := toVerifyBundle(t, pool, tenantID, secret)

	b.Events[1].Action = "tampered.action"
	problems := verifyChain(b.Events)
	if len(problems) == 0 {
		t.Fatal("内容被改后必须报错")
	}
}

// 删掉一条事件：链断 + 锚点计数不符，两道都要报。
func TestVerifierDetectsRemovedEvent(t *testing.T) {
	pool := testPool(t)
	tenantID := seed(t, pool, 3)
	secret := "anchor-secret-0123456789abcdef"
	b, _ := toVerifyBundle(t, pool, tenantID, secret)

	b.Events = append(b.Events[:1], b.Events[2:]...)
	problems := verifyChain(b.Events)
	if len(problems) == 0 {
		t.Fatal("删除事件后链校验必须失败")
	}
	if p := verifyAnchors(b.Events, b.Anchors, secret); len(p) == 0 {
		t.Fatal("删除事件后锚点计数必须不符")
	}
}

// 关键交叉验证：独立实现的 anchorInput 必须与服务端逐字节一致，
// 否则"客户端验签"会永远失败（这类不一致极难排查）。
func TestAnchorInputMatchesServerImplementation(t *testing.T) {
	pool := testPool(t)
	tenantID := seed(t, pool, 2)
	secret := "anchor-secret-0123456789abcdef"
	b, _ := toVerifyBundle(t, pool, tenantID, secret)
	if len(b.Anchors) != 1 {
		t.Fatalf("应有 1 个锚点，实际 %d", len(b.Anchors))
	}
	a := b.Anchors[0]

	root, _ := hex.DecodeString(a.MerkleRoot)
	head, _ := hex.DecodeString(a.ChainHead)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(anchorInput(a.TenantID, a.Day, a.SeqFrom, a.SeqTo, a.Count, root, head))
	if got := hex.EncodeToString(mac.Sum(nil)); got != a.Signature {
		t.Fatalf("独立实现算出的签名与服务端不一致\n want %s\n got  %s", a.Signature, got)
	}
}

// 未给密钥时应跳过签名校验，但仍然校验链与 Merkle 根。
func TestVerifierWithoutSecretStillChecksChain(t *testing.T) {
	pool := testPool(t)
	tenantID := seed(t, pool, 2)
	b, _ := toVerifyBundle(t, pool, tenantID, "anchor-secret-0123456789abcdef")

	if problems := verifyAnchors(b.Events, b.Anchors, ""); len(problems) != 0 {
		t.Fatalf("不给密钥时不应报签名问题: %v", problems)
	}
	b.Events[0].Result = "ok-but-modified"
	if problems := verifyChain(b.Events); len(problems) == 0 {
		t.Fatal("即使没有密钥，链校验也必须能发现问题")
	}
}
