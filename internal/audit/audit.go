// Package audit 实现防篡改审计链。
//
// 三条纪律（对应 SAD §9.5）：
//  1. 与业务同事务写入：写不进审计，业务就回滚（fail-closed）。
//  2. 按租户串行化链头：用 session 级 advisory lock，避免并发下哈希链分叉。
//  3. 哈希输入规范化：键排序、时间截断到微秒、禁止浮点，保证跨进程可复算。
package audit

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Result 取值。
const (
	ResultOK     = "ok"
	ResultDenied = "denied"
	ResultError  = "error"
)

// Event 是一次审计事件。Detail 用结构化 map，不用字符串拼 JSON
// （上一版曾因文件名含引号导致 detail 生成列报错、业务 500）。
type Event struct {
	ActorID    string
	ActorType  string
	Action     string
	ObjectType string
	ObjectID   string
	Result     string
	Detail     map[string]any
	IP         string
	RequestID  string
}

type record struct {
	Seq       int64  `json:"seq"`
	ActorID   string `json:"actor_id"`
	ActorType string `json:"actor_type"`
	Action    string `json:"action"`
	ObjType   string `json:"object_type"`
	ObjID     string `json:"object_id"`
	Result    string `json:"result"`
	Detail    any    `json:"detail"`
	IP        string `json:"ip"`
	RequestID string `json:"request_id"`
	CreatedAt string `json:"created_at"`
}

// Append 在给定事务内追加一条审计事件。
//
// 必须在业务事务内调用：这样业务成功而审计失败会自动整体回滚。
func Append(ctx context.Context, tx pgx.Tx, tenantID string, ev Event) error {
	if tenantID == "" {
		return errors.New("审计缺少租户上下文")
	}
	if ev.Action == "" || ev.Result == "" {
		return errors.New("审计事件缺少 action 或 result")
	}

	// 串行化同一租户的链头：否则两个并发事务会读到同一个 prev_hash 而分叉
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, tenantID); err != nil {
		return fmt.Errorf("获取链头锁失败: %w", err)
	}

	var prev []byte
	var lastSeq int64
	err := tx.QueryRow(ctx,
		`SELECT hash, seq FROM audit_event WHERE tenant_id = $1 ORDER BY seq DESC LIMIT 1`,
		tenantID).Scan(&prev, &lastSeq)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("读取链头失败: %w", err)
	}
	if errors.Is(err, pgx.ErrNoRows) {
		// 明细可能已被保留期清理删除。此时若从 0 重新开始，
		// 序号会与历史锚点的 seq 区间撞车，链也会断成两截。
		// 用最后一个锚点的 chain_head 续上：新链的第一条 prev_hash
		// 正是锚点承诺过的链头，跨清理边界仍然可验。
		lastSeq, prev = 0, nil
		var head []byte
		var seqTo int64
		if e := tx.QueryRow(ctx, `
			SELECT seq_to, chain_head FROM audit_anchor
			 WHERE tenant_id = $1 ORDER BY seq_to DESC LIMIT 1`,
			tenantID).Scan(&seqTo, &head); e == nil {
			lastSeq, prev = seqTo, head
		}
	}

	now := time.Now().UTC().Truncate(time.Microsecond)
	rec := record{
		Seq: lastSeq + 1, ActorID: ev.ActorID, ActorType: defaultStr(ev.ActorType, "user"),
		Action: ev.Action, ObjType: ev.ObjectType, ObjID: ev.ObjectID,
		Result: ev.Result, Detail: normalizeDetail(ev.Detail), IP: ev.IP,
		RequestID: ev.RequestID, CreatedAt: now.Format(time.RFC3339Nano),
	}
	body, err := canonical(rec)
	if err != nil {
		return err
	}
	h := sha256.New()
	h.Write(prev)
	h.Write(body)
	sum := h.Sum(nil)

	_, err = tx.Exec(ctx, `
		INSERT INTO audit_event
			(id, tenant_id, seq, actor_id, actor_type, action, object_type, object_id,
			 result, detail, ip, request_id, prev_hash, hash, created_at)
		VALUES
			(gen_random_uuid(), $1, $2, nullif($3,'')::uuid, $4, $5, nullif($6,''), nullif($7,'')::uuid,
			 $8, $9, nullif($10,'')::inet, nullif($11,''), $12, $13, $14)`,
		tenantID, rec.Seq, rec.ActorID, rec.ActorType, rec.Action, rec.ObjType, rec.ObjID,
		rec.Result, orEmptyMap(ev.Detail), rec.IP, rec.RequestID, prev, sum, now)
	if err != nil {
		return fmt.Errorf("写入审计事件失败: %w", err)
	}
	return nil
}

// Verify 复算某租户全部事件，返回校验条数与首个不一致的位置。
func Verify(ctx context.Context, pool *pgxpool.Pool, tenantID string) (int, error) {
	rows, err := pool.Query(ctx, `
		SELECT seq, coalesce(actor_id::text,''), actor_type, action,
		       coalesce(object_type,''), coalesce(object_id::text,''),
		       result, detail, coalesce(ip::text,''), coalesce(request_id,''),
		       coalesce(prev_hash,''::bytea), hash, created_at
		FROM audit_event WHERE tenant_id = $1 ORDER BY seq`, tenantID)
	if err != nil {
		return 0, err
	}
	defer rows.Close()

	// prev 从**首条保留记录的 prev_hash** 起算，而不是从空开始。
	//
	// 保留期清理会删掉被锚点覆盖的旧前缀，此时首条记录的 prev_hash 指向
	// 已删除的行（或某个日结锚点的 chain_head）。若仍从空起算，
	// 一次正常清理就会让校验报"审计链断裂"，把维护动作误报成篡改。
	// 边界之前的完整性由 audit_anchor 负责，不在这里重复证明。
	var prev []byte
	var count int
	firstRow := true
	for rows.Next() {
		var (
			seq                    int64
			actorID, actorType     string
			action, objType, oid   string
			result, ip, reqID      string
			detail                 []byte
			storedPrev, storedHash []byte
			createdAt              time.Time
		)
		if err := rows.Scan(&seq, &actorID, &actorType, &action, &objType, &oid,
			&result, &detail, &ip, &reqID, &storedPrev, &storedHash, &createdAt); err != nil {
			return count, err
		}

		var detailAny any
		if len(detail) > 0 {
			if err := json.Unmarshal(detail, &detailAny); err != nil {
				return count, fmt.Errorf("seq=%d detail 解析失败: %w", seq, err)
			}
		}

		rec := record{
			Seq: seq, ActorID: actorID, ActorType: actorType, Action: action,
			ObjType: objType, ObjID: oid, Result: result, Detail: detailAny,
			IP: normalizeIPText(ip), RequestID: reqID,
			CreatedAt: createdAt.UTC().Truncate(time.Microsecond).Format(time.RFC3339Nano),
		}
		if firstRow {
			prev = storedPrev
			firstRow = false
		}

		body, err := canonical(rec)
		if err != nil {
			return count, err
		}
		h := sha256.New()
		h.Write(prev)
		h.Write(body)
		if string(h.Sum(nil)) != string(storedHash) {
			return count, fmt.Errorf("审计链在第 %d 条断裂（哈希不匹配）", seq)
		}
		if len(storedPrev) > 0 && string(storedPrev) != string(prev) {
			return count, fmt.Errorf("审计链在第 %d 条断裂（前序哈希不匹配）", seq)
		}
		prev = storedHash
		count++
	}
	return count, rows.Err()
}

// normalizeIPText 把 PostgreSQL 的 inet 文本还原成写入时用的主机地址形式。
//
// 这是曾经让整条审计链"永远校验失败"的原因：
//   - 写入时哈希的是 clientIP(r)，形如 "172.25.0.1"（不带掩码）；
//   - 读取时 ip::text 会补成 "172.25.0.1/32"（IPv6 为 /128）；
//   - 两者不一致 → 每条带 IP 的记录都报"哈希不匹配"。
//
// 后果不是"少一条校验"，而是运维看到红灯后逐渐忽略告警——
// 真的被篡改时也没人再当回事。
func normalizeIPText(s string) string {
	switch {
	case strings.HasSuffix(s, "/32"):
		return strings.TrimSuffix(s, "/32")
	case strings.HasSuffix(s, "/128"):
		return strings.TrimSuffix(s, "/128")
	}
	return s
}

// canonical 生成稳定的字节表示：map 键由 encoding/json 排序，
// 不使用浮点，时间已截断到微秒。
func canonical(v any) ([]byte, error) {
	return json.Marshal(v)
}

func normalizeDetail(m map[string]any) any {
	if m == nil {
		return map[string]any{}
	}
	return m
}

func orEmptyMap(m map[string]any) map[string]any {
	if m == nil {
		return map[string]any{}
	}
	return m
}

func defaultStr(s, d string) string {
	if s == "" {
		return d
	}
	return s
}
