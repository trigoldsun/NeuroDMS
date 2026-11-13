package ace

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
)

// ErrNotANode 表示对空间根执行了只适用于文件/目录的继承操作。
//
// 空间是租户内的权限边界，`space.inherit_broken` 只能由空间管理员在空间级设定，
// 不能通过"断开某个文件的继承"来间接改变——否则一次节点操作就会影响整个空间。
var ErrNotANode = errors.New("继承操作只适用于文件或目录")

// InheritState 描述一个节点的继承状态。
type InheritState struct {
	NodeID        string
	Broken        bool
	InheritedACEs int
}

// InheritStateOf 读取节点的继承状态。
func InheritStateOf(ctx context.Context, tx pgx.Tx, nodeID string) (InheritState, error) {
	var st InheritState
	st.NodeID = nodeID
	if err := tx.QueryRow(ctx,
		`SELECT inherit_broken FROM node WHERE id = $1`, nodeID).Scan(&st.Broken); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return st, ErrNotANode
		}
		return st, err
	}
	if err := tx.QueryRow(ctx, `
		SELECT count(*) FROM ace
		 WHERE object_type = 'node' AND object_id = $1 AND origin = 'inherited'`, nodeID).
		Scan(&st.InheritedACEs); err != nil {
		return st, err
	}
	return st, nil
}

// BreakInheritance 断开节点的权限继承。
//
// 做法不是"简单停止向上查找"，而是：
//  1. 把当前从祖先链（含空间根）实际生效的 ACE 复制一份到本对象，标记 origin='inherited'；
//  2. 再置 inherit_broken=true，让判定不再向上取。
//
// 为什么必须复制：只截断会让对象瞬间失去全部访问权，管理界面表现为
// "点一下断开继承，文件从所有人的列表里消失"——这是真实的运维事故形态。
//
// 为什么快照连 deny 一起复制：如果不复制 deny，断开继承就变成了
// "绕过上层拒绝"的提权手法。复制 + 禁止单删（见 ErrInheritedACE）才能封住这条路。
//
// 幂等：已断开的节点重复调用返回 copied=0，不报错（重试友好）。
func BreakInheritance(ctx context.Context, tx pgx.Tx, tenantID, nodeID string) (copied int, err error) {
	var (
		broken  bool
		spaceID string
	)
	err = tx.QueryRow(ctx,
		`SELECT inherit_broken, space_id::text FROM node WHERE id = $1`, nodeID).
		Scan(&broken, &spaceID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, ErrNotANode
		}
		return 0, err
	}
	if broken {
		return 0, nil
	}

	// 取祖先链上仍然有效的 ACE（不含本对象自身的直接授权，不含已到期条目）
	rows, err := tx.Query(ctx, `
		WITH RECURSIVE chain AS (
			SELECT id, parent_id, 0 AS hop FROM node WHERE id = $1
			UNION ALL
			SELECT n.id, n.parent_id, c.hop + 1
			  FROM node n JOIN chain c ON n.id = c.parent_id
		)
		SELECT a.subject_type, COALESCE(a.subject_id::text, ''), a.allow_bits, a.deny_bits,
		       a.conditions::text, a.preset, a.expires_at::text, a.granted_by::text,
		       a.object_type, a.object_id::text
		  FROM ace a
		  LEFT JOIN chain c ON a.object_type = 'node' AND a.object_id = c.id
		 WHERE ((a.object_type = 'node' AND a.object_id IN (SELECT id FROM chain) AND a.object_id <> $1::uuid)
		     OR (a.object_type = 'space' AND a.object_id = $2))
		   AND (a.expires_at IS NULL OR a.expires_at > now())
		 ORDER BY a.object_type, c.hop DESC`, nodeID, spaceID)
	if err != nil {
		return 0, err
	}

	type snapshot struct {
		subjectType string
		subjectID   string
		allow       int64
		deny        int64
		conditions  string
		preset      *string
		expiresAt   *string
		grantedBy   *string
		originType  string
		originID    string
	}

	var snaps []snapshot
	for rows.Next() {
		var s snapshot
		if err := rows.Scan(&s.subjectType, &s.subjectID, &s.allow, &s.deny, &s.conditions,
			&s.preset, &s.expiresAt, &s.grantedBy, &s.originType, &s.originID); err != nil {
			rows.Close()
			return 0, err
		}
		snaps = append(snaps, s)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}

	for _, s := range snaps {
		tag, err := tx.Exec(ctx, `
			INSERT INTO ace (id, tenant_id, object_type, object_id, subject_type, subject_id,
			                 allow_bits, deny_bits, conditions, preset, expires_at, granted_by,
			                 origin, origin_object_type, origin_object_id)
			VALUES (gen_random_uuid(), $1, 'node', $2, $3, nullif($4,'')::uuid,
			        $5, $6, $7, $8, $9::timestamptz, $10::uuid, 'inherited', $11, $12::uuid)
			ON CONFLICT (tenant_id, object_type, object_id, subject_type,
			             COALESCE(subject_id, '00000000-0000-0000-0000-000000000000'::uuid))
			DO NOTHING`,
			tenantID, nodeID, s.subjectType, s.subjectID, s.allow, s.deny, s.conditions,
			s.preset, s.expiresAt, s.grantedBy, s.originType, s.originID)
		if err != nil {
			return copied, err
		}
		copied += int(tag.RowsAffected())
	}

	if _, err := tx.Exec(ctx, `UPDATE node SET inherit_broken = true, updated_at = now() WHERE id = $1`, nodeID); err != nil {
		return copied, err
	}
	return copied, nil
}

// RestoreInheritance 恢复继承：删除全部 inherited 快照并置 inherit_broken=false。
//
// 先删快照再置标记：若中途失败，事务回滚，不会留下"标记已恢复但仍残留快照"的半状态。
func RestoreInheritance(ctx context.Context, tx pgx.Tx, nodeID string) (removed int, err error) {
	var broken bool
	if err := tx.QueryRow(ctx, `SELECT inherit_broken FROM node WHERE id = $1`, nodeID).Scan(&broken); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, ErrNotANode
		}
		return 0, err
	}

	tag, err := tx.Exec(ctx, `
		DELETE FROM ace WHERE object_type = 'node' AND object_id = $1 AND origin = 'inherited'`, nodeID)
	if err != nil {
		return 0, err
	}
	if _, err := tx.Exec(ctx, `UPDATE node SET inherit_broken = false, updated_at = now() WHERE id = $1`, nodeID); err != nil {
		return 0, err
	}
	return int(tag.RowsAffected()), nil
}
