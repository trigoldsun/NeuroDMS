package audit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func appendEvents(t *testing.T, pool *pgxpool.Pool, tenantID string, n int) {
	t.Helper()
	ctx := context.Background()
	for i := 0; i < n; i++ {
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.Exec(ctx, `SELECT set_config('app.tenant_id', $1, true)`, tenantID); err != nil {
			_ = tx.Rollback(ctx)
			t.Fatal(err)
		}
		if err := Append(ctx, tx, tenantID, Event{
			ActorType: "user", Action: "test.event", Result: ResultOK,
			Detail: map[string]any{"index": i},
		}); err != nil {
			_ = tx.Rollback(ctx)
			t.Fatal(err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatal(err)
		}
	}
}

// 造一条哈希链（测试用），返回事件哈希。
func makeChain(t *testing.T, n int) ([][]byte, [][]byte) {
	t.Helper()
	var hashes [][]byte
	var bodies [][]byte
	var prev []byte
	for i := 0; i < n; i++ {
		body := []byte{byte(i), byte(i >> 8)}
		h := sha256.New()
		h.Write(prev)
		h.Write(body)
		sum := h.Sum(nil)
		hashes = append(hashes, sum)
		bodies = append(bodies, body)
		prev = sum
	}
	return hashes, bodies
}

func TestMerkleRootDeterministic(t *testing.T) {
	hashes, _ := makeChain(t, 5)
	r1 := MerkleRoot(hashes)
	r2 := MerkleRoot(hashes)
	if !bytes.Equal(r1, r2) {
		t.Fatal("同一输入必须得到同一根")
	}
	if len(r1) != 32 {
		t.Fatalf("Merkle 根应为 32 字节，实际 %d", len(r1))
	}

	// 奇数节点会复制末节点：3 个与 4 个（末位重复）应得到相同根
	h3 := hashes[:3]
	h4 := append(append([][]byte{}, hashes[:3]...), hashes[2])
	if !bytes.Equal(MerkleRoot(h3), MerkleRoot(h4)) {
		t.Fatal("奇数节点复制末节点的规则应一致")
	}

	// 换一个叶子必须换根
	hashes[0] = bytes.Repeat([]byte{0xFF}, 32)
	if bytes.Equal(MerkleRoot(hashes), r1) {
		t.Fatal("叶子变化后根必须变化")
	}
}

func TestAnchorAndVerify(t *testing.T) {
	pool := testPool(t)
	tenantID := seedTenant(t, pool)
	ctx := context.Background()
	secret := []byte("anchor-secret-0123456789abcdef")

	appendEvents(t, pool, tenantID, 3)

	day := time.Now().UTC()
	a, err := AnchorDay(ctx, pool, tenantID, day, secret)
	if err != nil {
		t.Fatalf("结算失败: %v", err)
	}
	if a.Count != 3 {
		t.Fatalf("应锚定 3 条事件，实际 %d", a.Count)
	}
	if a.SeqFrom != 1 || a.SeqTo != 3 {
		t.Fatalf("序号范围不符: %d-%d", a.SeqFrom, a.SeqTo)
	}

	if err := VerifyAnchor(ctx, pool, a, secret); err != nil {
		t.Fatalf("刚生成的锚点应校验通过: %v", err)
	}

	// 幂等：同一天再结算一次不新增记录（但值相同）
	a2, err := AnchorDay(ctx, pool, tenantID, day, secret)
	if err != nil {
		t.Fatal(err)
	}
	if a2.MerkleRoot != a.MerkleRoot {
		t.Fatal("同一天重复结算应得到相同根")
	}

	// 换密钥校验必须失败：否则密钥轮换/泄漏无法被发现
	if err := VerifyAnchor(ctx, pool, a, []byte("wrong-secret-0123456789abcdef")); err == nil {
		t.Fatal("错误密钥应校验失败")
	}
}

// 两件事一起验证：
//  1. 事件表是只追加的（DELETE 被规则挡掉），所以"删一条再改锚点"这条路走不通；
//  2. 即使攻击者能改锚点行，签名校验也会失败。
func TestAnchorDetectsTamperAttempts(t *testing.T) {
	pool := testPool(t)
	tenantID := seedTenant(t, pool)
	ctx := context.Background()
	secret := []byte("anchor-secret-0123456789abcdef")

	appendEvents(t, pool, tenantID, 2)
	day := time.Now().UTC()
	a, err := AnchorDay(ctx, pool, tenantID, day, secret)
	if err != nil {
		t.Fatal(err)
	}

	// 尝试删除一条事件：append-only 规则应让删除无效（0 行受影响）
	ct, err := pool.Exec(ctx, `DELETE FROM audit_event WHERE tenant_id=$1 AND seq=2`, tenantID)
	if err != nil {
		t.Fatalf("删除应被规则静默忽略而不是报错: %v", err)
	}
	var remaining int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM audit_event WHERE tenant_id=$1`, tenantID).Scan(&remaining); err != nil {
		t.Fatal(err)
	}
	if remaining != 2 {
		t.Fatalf("审计事件不应被删除，实际剩 %d 条（影响行数 %d）", remaining, ct.RowsAffected())
	}

	// 篡改锚点字段 → 签名不匹配
	tampered := a
	tampered.Count = a.Count + 1
	if err := VerifyAnchor(ctx, pool, tampered, secret); err == nil {
		t.Fatal("篡改锚点后校验必须失败")
	}
	tampered = a
	tampered.MerkleRoot = strings.Repeat("00", 32)
	if err := VerifyAnchor(ctx, pool, tampered, secret); err == nil {
		t.Fatal("篡改 Merkle 根后校验必须失败")
	}

	// 原锚点仍然有效，证明上面的失败是篡改导致而非代码缺陷
	if err := VerifyAnchor(ctx, pool, a, secret); err != nil {
		t.Fatalf("原始锚点应仍有效: %v", err)
	}
}

// 没有事件的那天不该生成锚点（否则会产生大量空锚点）。
func TestAnchorEmptyDay(t *testing.T) {
	pool := testPool(t)
	tenantID := seedTenant(t, pool)
	ctx := context.Background()

	old := time.Now().UTC().AddDate(0, 0, -30)
	if _, err := AnchorDay(ctx, pool, tenantID, old, []byte("k")); err != ErrNoEvents {
		t.Fatalf("无事件应返回 ErrNoEvents，实际 %v", err)
	}
}

func TestExportBundleShape(t *testing.T) {
	pool := testPool(t)
	tenantID := seedTenant(t, pool)
	ctx := context.Background()
	secret := []byte("anchor-secret-0123456789abcdef")

	appendEvents(t, pool, tenantID, 2)
	if _, err := AnchorDay(ctx, pool, tenantID, time.Now().UTC(), secret); err != nil {
		t.Fatal(err)
	}

	raw, err := Export(ctx, pool, tenantID, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}

	var b Bundle
	if err := json.Unmarshal(raw, &b); err != nil {
		t.Fatalf("证据包应是合法 JSON: %v", err)
	}
	if b.Format != "docvault-evidence-v1" {
		t.Fatalf("格式标识不符: %s", b.Format)
	}
	if b.EventCount != 2 || len(b.Events) != 2 {
		t.Fatalf("应含 2 条事件，实际 %d", len(b.Events))
	}
	if len(b.Anchors) != 1 {
		t.Fatalf("应含 1 个锚点，实际 %d", len(b.Anchors))
	}
	if len(b.Verify.Steps) == 0 {
		t.Fatal("必须给出校验步骤，否则接收方无从复算")
	}
	// 哈希必须以 hex 出现在包里（否则无法复算）
	if len(b.Events[0].Hash) != 64 {
		t.Fatalf("事件哈希应为 64 位 hex，实际 %q", b.Events[0].Hash)
	}
	if _, err := hex.DecodeString(b.Events[0].Hash); err != nil {
		t.Fatalf("哈希不是合法 hex: %v", err)
	}
}
