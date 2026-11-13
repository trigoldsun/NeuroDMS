package content

import (
	"context"
	"errors"
	"strings"

	"docvault/internal/db"

	"github.com/jackc/pgx/v5"
)

// validateName 校验对象名：不能为空、不能含路径分隔符与控制字符、长度受限。
//
// 为什么不只靠前端校验：文件名会进入 Content-Disposition、日志、审计与
// 未来的文件系统路径，任何一处没转义都可能变成注入点。
func validateName(name string) error {
	name = strings.TrimSpace(name)
	if name == "" || len([]rune(name)) > 255 {
		return ErrBadInput
	}
	if name == "." || name == ".." {
		return ErrBadInput
	}
	for _, r := range name {
		if r == '/' || r == '\\' || r < 0x20 || r == 0x7f {
			return ErrBadInput
		}
	}
	return nil
}

// RenameNode 修改对象名。同目录重名返回 ErrNameTaken。
func (s *Store) RenameNode(ctx context.Context, tenantID, nodeID, name string) error {
	if err := validateName(name); err != nil {
		return err
	}
	return db.WithTenant(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		ct, err := tx.Exec(ctx, `
			UPDATE node SET name = $2, updated_at = now()
			 WHERE id = $1 AND deleted_at IS NULL`, nodeID, strings.TrimSpace(name))
		if err != nil {
			if isUniqueViolation(err) {
				return ErrNameTaken
			}
			return err
		}
		if ct.RowsAffected() == 0 {
			return ErrNotFound
		}
		return nil
	})
}

// MoveNode 把对象移动到新目录（newParentID 为空表示移到空间根）。
//
// 三条约束都必须在一个事务里成立：
//  1. 目标父节点存在、同属一个空间、且必须是目录；
//  2. 不能把目录移进自己的子树（否则形成环，遍历会死循环）；
//  3. 子树的 depth 要整体平移，否则深层节点会与父节点深度矛盾。
func (s *Store) MoveNode(ctx context.Context, tenantID, nodeID, newParentID string) error {
	return db.WithTenant(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		return moveOne(ctx, tx, nodeID, newParentID)
	})
}

// MoveNodes 在一个事务里移动多个节点。
//
// 为什么必须单事务：批量移动如果是"逐个提交"，中途失败会留下
// "一半移走、一半没动"的中间态，用户看到的目录结构是坏的，且无法自动恢复。
func (s *Store) MoveNodes(ctx context.Context, tenantID string, nodeIDs []string, newParentID string) (int, error) {
	moved := 0
	err := db.WithTenant(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		for _, id := range nodeIDs {
			if err := moveOne(ctx, tx, id, newParentID); err != nil {
				return err
			}
			moved++
		}
		return nil
	})
	return moved, err
}

// moveOne 是单节点移动的实际实现（供单个与批量共用，避免两套语义漂移）。
func moveOne(ctx context.Context, tx pgx.Tx, nodeID, newParentID string) error {
	var spaceID string
	var oldDepth int
	if err := tx.QueryRow(ctx,
		`SELECT space_id::text, depth FROM node WHERE id = $1 AND deleted_at IS NULL`, nodeID).
		Scan(&spaceID, &oldDepth); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}

	newDepth := 0
	if newParentID != "" {
		var parentSpace, parentKind string
		var parentDepth int
		if err := tx.QueryRow(ctx,
			`SELECT space_id::text, kind, depth FROM node WHERE id = $1 AND deleted_at IS NULL`,
			newParentID).Scan(&parentSpace, &parentKind, &parentDepth); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrNotFound
			}
			return err
		}
		if parentSpace != spaceID {
			// 跨空间移动等同于"复制再删除"，这里直接拒绝：
			// 它会让目标空间的配额、权限、审计全部错位。
			return ErrBadInput
		}
		if parentKind != "folder" {
			return ErrBadInput
		}
		newDepth = parentDepth + 1

		// 环检测：目标父节点不能是自身或自身后代。
		// 只在有具体父节点时执行——空间根用的是 NULL/空串，不是 uuid。
		var cycle int
		if err := tx.QueryRow(ctx, `
			WITH RECURSIVE sub AS (
				SELECT id FROM node WHERE id = $1 AND deleted_at IS NULL
				UNION ALL
				SELECT n.id FROM node n JOIN sub ON n.parent_id = sub.id WHERE n.deleted_at IS NULL
			)
			SELECT count(*) FROM sub WHERE id = $2`, nodeID, newParentID).Scan(&cycle); err != nil {
			return err
		}
		if cycle > 0 {
			return ErrBadInput
		}
	}

	var parentArg any
	if newParentID != "" {
		parentArg = newParentID
	}
	if _, err := tx.Exec(ctx, `
		UPDATE node SET parent_id = $2, depth = $3, updated_at = now()
		 WHERE id = $1`, nodeID, parentArg, newDepth); err != nil {
		if isUniqueViolation(err) {
			return ErrNameTaken
		}
		return err
	}

	// 子树深度整体平移
	if delta := newDepth - oldDepth; delta != 0 {
		if _, err := tx.Exec(ctx, `
			WITH RECURSIVE sub AS (
				SELECT id FROM node WHERE parent_id = $1 AND deleted_at IS NULL
				UNION ALL
				SELECT n.id FROM node n JOIN sub ON n.parent_id = sub.id WHERE n.deleted_at IS NULL
			)
			UPDATE node SET depth = depth + $2
			 WHERE id IN (SELECT id FROM sub)`, nodeID, delta); err != nil {
			return err
		}
	}
	return nil
}

// SoftDeleteNode 软删除对象，目录会级联标记整棵子树。返回受影响节点数。
//
// 为什么软删除：权限继承按 parent_id 链走，物理删除会让子节点的 ACE 变成孤儿；
// 审计与恢复也需要"曾经存在"这件事可查。真正的内容回收由后台清理任务负责。
func (s *Store) SoftDeleteNode(ctx context.Context, tenantID, nodeID string) (int, error) {
	var affected int
	err := db.WithTenant(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		var exists bool
		if err := tx.QueryRow(ctx,
			`SELECT true FROM node WHERE id = $1 AND deleted_at IS NULL`, nodeID).Scan(&exists); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrNotFound
			}
			return err
		}

		ct, err := tx.Exec(ctx, `
			WITH RECURSIVE sub AS (
				SELECT id FROM node WHERE id = $1 AND deleted_at IS NULL
				UNION ALL
				SELECT n.id FROM node n JOIN sub ON n.parent_id = sub.id WHERE n.deleted_at IS NULL
			)
			UPDATE node SET deleted_at = now(), updated_at = now()
			 WHERE id IN (SELECT id FROM sub)`, nodeID)
		if err != nil {
			return err
		}
		affected = int(ct.RowsAffected())

		// 软删除后同名对象应可重新创建，因此把名字改成不可见形式：
		// 唯一索引 uq_node_sibling_file 对 deleted_at IS NULL 生效，
		// 若只置 deleted_at，新对象不受影响；但为了审计时"名字可辨"，
		// 这里保留原名不改，依赖部分索引即可。
		return nil
	})
	if err != nil {
		return 0, err
	}
	return affected, nil
}

// ResolveNodeTenant 返回节点所属租户（跨租户的平台级查询）。
//
// 为什么需要它：文档服务的回调里没有租户信息，只有它回传的 key。
// 用"客户端声称的租户"是不可接受的（可伪造），只能按节点反查。
// 这条查询刻意不带 WithTenant —— 它本身就是**用来确定**租户边界的那一步。
func (s *Store) ResolveNodeTenant(ctx context.Context, nodeID string) (string, error) {
	var tenantID string
	err := s.pool.QueryRow(ctx,
		`SELECT tenant_id::text FROM node WHERE id = $1 AND deleted_at IS NULL`, nodeID).Scan(&tenantID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", ErrNotFound
		}
		return "", err
	}
	return tenantID, nil
}
