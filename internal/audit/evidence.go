package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Bundle 是证据包：可直接交给第三方，不依赖本系统即可校验。
//
// 关键设计：包里带"原始行 + 校验方法"，而不是只给一份"校验通过"的结论。
// 结论可以被伪造，数据不能。
type Bundle struct {
	Format     string        `json:"format"`
	TenantID   string        `json:"tenantId"`
	From       string        `json:"from"`
	To         string        `json:"to"`
	ExportedAt string        `json:"exportedAt"`
	EventCount int           `json:"eventCount"`
	Events     []BundleEvent `json:"events"`
	Anchors    []Anchor      `json:"anchors"`
	Verify     BundleVerify  `json:"verify"`
}

// BundleEvent 是证据包里的单条事件（含哈希链字段）。
type BundleEvent struct {
	Seq        int64          `json:"seq"`
	ActorID    string         `json:"actorId"`
	ActorType  string         `json:"actorType"`
	Action     string         `json:"action"`
	ObjectType string         `json:"objectType"`
	ObjectID   string         `json:"objectId"`
	Result     string         `json:"result"`
	Detail     map[string]any `json:"detail"`
	IP         string         `json:"ip"`
	RequestID  string         `json:"requestId"`
	PrevHash   string         `json:"prevHash"`
	Hash       string         `json:"hash"`
	CreatedAt  string         `json:"createdAt"`
}

// BundleVerify 描述校验步骤，让接收方知道该怎么验、能验出什么。
type BundleVerify struct {
	Steps []string `json:"steps"`
	Note  string   `json:"note"`
}

// Export 生成某租户某时间段的证据包。
func Export(ctx context.Context, pool *pgxpool.Pool, tenantID string, from, to time.Time) ([]byte, error) {
	b := Bundle{
		Format:     "docvault-evidence-v1",
		TenantID:   tenantID,
		From:       from.UTC().Format(time.RFC3339),
		To:         to.UTC().Format(time.RFC3339),
		ExportedAt: time.Now().UTC().Format(time.RFC3339),
	}

	rows, err := pool.Query(ctx, `
		SELECT seq, coalesce(actor_id::text,''), actor_type, action,
		       coalesce(object_type,''), coalesce(object_id::text,''),
		       result, coalesce(detail,'{}'::jsonb), coalesce(ip::text,''), coalesce(request_id,''),
		       coalesce(encode(prev_hash,'hex'),''), encode(hash,'hex'), created_at
		  FROM audit_event
		 WHERE tenant_id = $1 AND created_at >= $2 AND created_at < $3
		 ORDER BY seq`, tenantID, from, to)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var e BundleEvent
		var detail []byte
		var createdAt time.Time
		if err := rows.Scan(&e.Seq, &e.ActorID, &e.ActorType, &e.Action, &e.ObjectType, &e.ObjectID,
			&e.Result, &detail, &e.IP, &e.RequestID, &e.PrevHash, &e.Hash, &createdAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(detail, &e.Detail)
		e.CreatedAt = createdAt.UTC().Format(time.RFC3339Nano)
		b.Events = append(b.Events, e)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	b.EventCount = len(b.Events)

	anchors, err := ListAnchors(ctx, pool, tenantID, 1000)
	if err != nil {
		return nil, err
	}
	b.Anchors = anchors

	b.Verify = BundleVerify{
		Steps: []string{
			"1. 按 seq 升序重算每条事件的 SHA-256：输入为 prev_hash 拼接规范化 JSON（键排序、时间截断到微秒、RFC3339Nano）",
			"2. 校验每条事件的 prev_hash 等于前一条的 hash（首条为空）",
			"3. 对每个锚点：用 events 中同一天的事件哈希重算 Merkle 根（奇数节点复制末节点），与 merkle_root 比对",
			"4. 用公开的锚点密钥校验每个锚点的 HMAC-SHA256 签名",
			"5. 任一环节不一致即判定为篡改，不得采信",
		},
		Note: "本工具只提供数据与算法；请用独立实现的校验器复算，不要采信导出方的自我结论。",
	}

	return json.MarshalIndent(b, "", "  ")
}

// 让 BundleEvent 与内部 record 的字段名保持一致，便于离线复算。
// 若这里改了 JSON tag，必须同步改 cmd/auditverify 与文档，否则历史证据包无法复算。
var _ = fmt.Sprintf
