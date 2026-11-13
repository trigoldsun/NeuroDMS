package audit

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"docvault/internal/db"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Anchor 是某租户某一天的结算锚点。
type Anchor struct {
	TenantID   string
	Day        string // YYYY-MM-DD（UTC）
	SeqFrom    int64
	SeqTo      int64
	Count      int
	MerkleRoot string // hex
	ChainHead  string // hex
	Signature  string // hex
	Algorithm  string
	CreatedAt  time.Time
}

// ErrNoEvents 表示当天没有任何审计事件，无需结算。
var ErrNoEvents = errors.New("当天没有审计事件")

// MerkleRoot 计算叶子哈希的 Merkle 根。
//
// 奇数个节点时把最后一个复制一份再两两合并（Bitcoin 的做法）：
// 这样任意时刻的树形是确定的，任何人复算都得到同一结果。
func MerkleRoot(leaves [][]byte) []byte {
	if len(leaves) == 0 {
		return nil
	}
	level := make([][]byte, len(leaves))
	copy(level, leaves)
	for len(level) > 1 {
		if len(level)%2 == 1 {
			level = append(level, level[len(level)-1])
		}
		next := make([][]byte, 0, len(level)/2)
		for i := 0; i < len(level); i += 2 {
			h := sha256.New()
			h.Write(level[i])
			h.Write(level[i+1])
			next = append(next, h.Sum(nil))
		}
		level = next
	}
	return level[0]
}

// anchorInput 是签名的规范化输入。跨语言/跨进程复算时必须逐字节一致，
// 因此不用 JSON（键顺序、浮点表示都可能不同），改用固定长度拼接。
func anchorInput(tenantID, day string, seqFrom, seqTo int64, count int, merkle, head []byte) []byte {
	var buf []byte
	buf = append(buf, []byte("docvault-anchor-v1")...)
	buf = append(buf, 0)
	buf = append(buf, []byte(tenantID)...)
	buf = append(buf, 0)
	buf = append(buf, []byte(day)...)
	var num [8]byte
	for _, v := range []int64{seqFrom, seqTo, int64(count)} {
		binary.BigEndian.PutUint64(num[:], uint64(v))
		buf = append(buf, num[:]...)
	}
	buf = append(buf, merkle...)
	buf = append(buf, head...)
	return buf
}

// BuildAnchor 结算某一天的锚点（不写库，便于离线复算与测试）。
func BuildAnchor(ctx context.Context, pool *pgxpool.Pool, tenantID string, day time.Time, secret []byte) (Anchor, error) {
	dayStr := day.UTC().Format("2006-01-02")
	from := time.Date(day.Year(), day.Month(), day.Day(), 0, 0, 0, 0, time.UTC)
	to := from.Add(24 * time.Hour)

	rows, err := pool.Query(ctx, `
		SELECT seq, hash FROM audit_event
		 WHERE tenant_id = $1 AND created_at >= $2 AND created_at < $3
		 ORDER BY seq`, tenantID, from, to)
	if err != nil {
		return Anchor{}, err
	}
	defer rows.Close()

	var (
		seqs   []int64
		hashes [][]byte
	)
	for rows.Next() {
		var seq int64
		var h []byte
		if err := rows.Scan(&seq, &h); err != nil {
			return Anchor{}, err
		}
		seqs = append(seqs, seq)
		hashes = append(hashes, h)
	}
	if err := rows.Err(); err != nil {
		return Anchor{}, err
	}
	if len(hashes) == 0 {
		return Anchor{}, ErrNoEvents
	}

	root := MerkleRoot(hashes)
	head := hashes[len(hashes)-1]

	mac := hmac.New(sha256.New, secret)
	mac.Write(anchorInput(tenantID, dayStr, seqs[0], seqs[len(seqs)-1], len(hashes), root, head))

	return Anchor{
		TenantID: tenantID, Day: dayStr,
		SeqFrom: seqs[0], SeqTo: seqs[len(seqs)-1], Count: len(hashes),
		MerkleRoot: hex.EncodeToString(root),
		ChainHead:  hex.EncodeToString(head),
		Signature:  hex.EncodeToString(mac.Sum(nil)),
		Algorithm:  "hmac-sha256",
	}, nil
}

// AnchorDay 结算并写入锚点。重复执行同一天不会产生第二条（幂等）。
func AnchorDay(ctx context.Context, pool *pgxpool.Pool, tenantID string, day time.Time, secret []byte) (Anchor, error) {
	a, err := BuildAnchor(ctx, pool, tenantID, day, secret)
	if err != nil {
		return Anchor{}, err
	}

	err = db.WithTenant(ctx, pool, tenantID, func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `
			INSERT INTO audit_anchor
				(id, tenant_id, day, seq_from, seq_to, event_count, merkle_root, chain_head, signature, algorithm)
			VALUES (gen_random_uuid(), $1, $2, $3, $4, $5, decode($6,'hex'), decode($7,'hex'), decode($8,'hex'), $9)
			ON CONFLICT (tenant_id, day) DO NOTHING`,
			a.TenantID, a.Day, a.SeqFrom, a.SeqTo, a.Count,
			a.MerkleRoot, a.ChainHead, a.Signature, a.Algorithm)
		return e
	})
	if err != nil {
		return Anchor{}, err
	}
	return a, nil
}

// VerifyAnchor 校验锚点签名与数据库现状是否一致。
//
// 返回 error 表示"锚点与实际数据不符"——这正是篡改的信号：
// 要么事件被改/删，要么锚点被改，两种都不该被接受。
func VerifyAnchor(ctx context.Context, pool *pgxpool.Pool, a Anchor, secret []byte) error {
	root, err := hex.DecodeString(a.MerkleRoot)
	if err != nil {
		return fmt.Errorf("merkle_root 非法: %w", err)
	}
	head, err := hex.DecodeString(a.ChainHead)
	if err != nil {
		return fmt.Errorf("chain_head 非法: %w", err)
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write(anchorInput(a.TenantID, a.Day, a.SeqFrom, a.SeqTo, a.Count, root, head))
	want := hex.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(want), []byte(a.Signature)) {
		return errors.New("锚点签名不匹配")
	}

	// 重新按当前数据结算，与锚点比对
	day, err := time.Parse("2006-01-02", a.Day)
	if err != nil {
		return err
	}
	actual, err := BuildAnchor(ctx, pool, a.TenantID, day, secret)
	if errors.Is(err, ErrNoEvents) {
		// 明细已被保留期清理删除，锚点仍在。签名已在上面验过，
		// 这一天"曾经存在且当时未被改写"由 merkle 根与链头承诺，
		// 不能因为明细按策略删除就报篡改。
		return nil
	}
	if err != nil {
		return fmt.Errorf("复算锚点失败: %w", err)
	}
	if actual.MerkleRoot != a.MerkleRoot || actual.Count != a.Count ||
		actual.SeqTo != a.SeqTo || actual.ChainHead != a.ChainHead {
		return fmt.Errorf("锚点与当前数据不一致（count %d→%d，head %s→%s）",
			a.Count, actual.Count, short(a.ChainHead), short(actual.ChainHead))
	}
	return nil
}

// ListAnchors 读取某租户的锚点。
func ListAnchors(ctx context.Context, pool *pgxpool.Pool, tenantID string, limit int) ([]Anchor, error) {
	if limit <= 0 {
		limit = 90
	}
	var out []Anchor
	err := db.WithTenant(ctx, pool, tenantID, func(tx pgx.Tx) error {
		rows, e := tx.Query(ctx, `
			SELECT tenant_id::text, to_char(day,'YYYY-MM-DD'), seq_from, seq_to, event_count,
			       encode(merkle_root,'hex'), encode(chain_head,'hex'), encode(signature,'hex'),
			       algorithm, created_at
			  FROM audit_anchor WHERE tenant_id = $1 ORDER BY day DESC LIMIT $2`, tenantID, limit)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var a Anchor
			if e := rows.Scan(&a.TenantID, &a.Day, &a.SeqFrom, &a.SeqTo, &a.Count,
				&a.MerkleRoot, &a.ChainHead, &a.Signature, &a.Algorithm, &a.CreatedAt); e != nil {
				return e
			}
			out = append(out, a)
		}
		return rows.Err()
	})
	return out, err
}

func short(s string) string {
	if len(s) <= 12 {
		return s
	}
	return s[:12] + "…"
}
