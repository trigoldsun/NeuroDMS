package audit

import (
	"context"
	"time"

	"docvault/internal/db"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// QueryFilter 是审计查询的过滤条件。
//
// 刻意做成"白名单字段"而不是任意 SQL 拼接：
// 审计数据的查询入口一旦能注入，攻击者就能用查询语句去读不该读的东西，
// 或者用大量全表扫描把库拖垮。
type QueryFilter struct {
	Action string
	// Actions 是动作的 SQL LIKE 模式集合（如 "node.%"、"acl.%"）。
	//
	// 面向人的日志页要按"分类"筛（下载/分享/权限变更），
	// 而分类天然是前缀，逐个枚举动作字面量会在新增埋点时静默漏掉。
	// 仍是白名单语义：模式由服务端按角色生成，不直接取自请求参数。
	Actions  []string
	ObjectID string
	ActorID  string
	Result   string
	From     *time.Time
	To       *time.Time
	Limit    int
	Offset   int
}

// EventRow 是审计事件的读模型。
type EventRow struct {
	Seq       int64
	ActorID   string
	ActorName string // 读模型补充字段，由查询层填充；空表示未知账号
	ActorType string
	Action    string
	ObjectID  string
	Result    string
	Detail    []byte
	IP        string
	RequestID string
	CreatedAt time.Time
}

// whereSQL 是 Query 与 Count 共用的过滤条件。
//
// 两个查询必须共用同一段条件：一旦各写一份，翻页时出现的现象是
// "第 3 页显示 40 条"或"最后一页永远有内容"，而且很难被发现。
//
// 参数位固定为 $1..$7：
//
//	$1 action（精确） $2 actor $3 result $4 from $5 to
//	$6 动作模式数组   $7 object_id
const whereSQL = `
 WHERE ($1 = '' OR action = $1)
   AND ($2 = '' OR actor_id = nullif($2, '')::uuid)
   AND ($3 = '' OR result = $3)
   AND ($4::timestamptz IS NULL OR created_at >= $4)
   AND ($5::timestamptz IS NULL OR created_at < $5)
   AND ($6::text[] IS NULL OR EXISTS (
         SELECT 1 FROM unnest($6::text[]) AS p WHERE action LIKE p
       ))
   AND ($7 = '' OR object_id = nullif($7, '')::uuid)`

func whereArgs(f QueryFilter) []any {
	var actions []string
	if len(f.Actions) > 0 {
		actions = f.Actions
	}
	return []any{f.Action, f.ActorID, f.Result, f.From, f.To, actions, f.ObjectID}
}

// Query 按条件分页读取审计事件（新→旧）。
//
// 上限强制 500 条：审计表是全库增长最快的表之一，
// 一次"导出全部"的查询就足以让生产库进入长时间 IO 等待。
func Query(ctx context.Context, pool *pgxpool.Pool, tenantID string, f QueryFilter) ([]EventRow, error) {
	if f.Limit <= 0 || f.Limit > 500 {
		f.Limit = 200
	}
	if f.Offset < 0 {
		f.Offset = 0
	}

	var out []EventRow
	err := db.WithTenant(ctx, pool, tenantID, func(tx pgx.Tx) error {
		args := append(whereArgs(f), f.Limit, f.Offset)
		rows, err := tx.Query(ctx, `
			SELECT seq, COALESCE(actor_id::text,''), actor_type, action,
			       COALESCE(object_id::text,''), result, detail, COALESCE(ip::text,''),
			       COALESCE(request_id,''), created_at
			  FROM audit_event`+whereSQL+`
			 ORDER BY seq DESC
			 LIMIT $8 OFFSET $9`, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var r EventRow
			if err := rows.Scan(&r.Seq, &r.ActorID, &r.ActorType, &r.Action, &r.ObjectID,
				&r.Result, &r.Detail, &r.IP, &r.RequestID, &r.CreatedAt); err != nil {
				return err
			}
			out = append(out, r)
		}
		return rows.Err()
	})
	return out, err
}

// Count 返回同一条件命中的总条数。
//
// 前端要显示"共 N 条 / 第 x 页"，并在没有下一页时禁用按钮。
// 不给总数的替代方案是"多取一条判断有没有下一页"，
// 但那样用户永远不知道还剩多少，翻到第 30 页才发现已经到底。
func Count(ctx context.Context, pool *pgxpool.Pool, tenantID string, f QueryFilter) (int64, error) {
	var n int64
	err := db.WithTenant(ctx, pool, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT count(*) FROM audit_event`+whereSQL, whereArgs(f)...).Scan(&n)
	})
	return n, err
}
