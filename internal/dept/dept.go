// Package dept 管理租户内的部门树。
//
// 为什么单独成一个包：部门不只是"成员的一个属性"——它同时是
// ACL 的授权主体（`subjectType=dept`，按 `path <@` 命中子树）、
// 空间归属的载体、以及目录同步的产物。三处写入口（手工建/改/删、目录同步）
// 必须共用同一套路径规则，否则"手工建的部门授了权、同步建的部门授不到"。
package dept

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"docvault/internal/db"
)

var (
	ErrNotFound          = errors.New("部门不存在")
	ErrInvalidInput      = errors.New("部门名不合法")
	ErrNameTaken         = errors.New("同级下已有同名部门")
	ErrDirectoryManaged  = errors.New("该部门由目录同步维护，请在目录里改")
	ErrHasChildren       = errors.New("该部门下还有子部门")
	ErrHasMembers        = errors.New("该部门下还有成员")
	ErrHasSpaces         = errors.New("该部门下还有空间")
	ErrCycle             = errors.New("不能把部门移动到它自己或它的下级")
	ErrTooDeep           = errors.New("部门层级过深")
	ErrNoParent          = errors.New("上级部门不存在")
	ErrCannotDeleteRoot  = errors.New("根部门不能删除")
	ErrAmbiguousRootPick = errors.New("存在多个顶层部门，请指定上级")
)

// MaxDepth 是部门树的最大层数。
//
// 不设上限的后果不是"树很深很难看"，而是 ltree 路径无限增长，
// 最终撞上索引行宽上限；12 层对组织结构足够，超了通常是同步配置出了问题。
const MaxDepth = 12

// maxNameLen 是部门名长度上限（按字符数，不是字节数）。
const maxNameLen = 64

// Node 是部门树的一个节点。
type Node struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	// ParentID 为 null 表示顶层。手工建的部门一律挂在某个上级下，
	// 只有目录同步会产生新的顶层（如 AD 里的根 OU）。
	ParentID *string `json:"parentId"`
	// Path 是 ltree 路径（如 root.Data_Tech_f6137b9f）。
	// 它是对外契约的一部分：ACL 按路径前缀匹配子树，前端也据此算缩进层级。
	Path string `json:"path"`
	// Depth 从 1 开始（根部门为 1），前端据此缩进，不用自己拆 path。
	Depth int `json:"depth"`
	Sort  int `json:"sort"`
	// Directory 为真表示这条来自目录同步（有 ldap_dn），本地不允许改名/删除，
	// 否则下一次同步会把它建回来，或者与 AD 里的名字长期不一致。
	Directory   bool `json:"directory"`
	MemberCount int  `json:"memberCount"`
	// SpaceCount 用来拦住"删掉一个还挂着空间部门的部门"。
	SpaceCount int `json:"spaceCount"`
}

// Change 记录一次改动的前后值，供审计使用。
type Change struct {
	ID      string `json:"id"`
	Before  Node   `json:"before"`
	After   Node   `json:"after"`
	MovedTo string `json:"movedTo,omitempty"`
}

// Service 是部门树的写入口。
type Service struct {
	pool *pgxpool.Pool
}

func New(pool *pgxpool.Pool) *Service { return &Service{pool: pool} }

// List 返回租户内全部部门（扁平列表，按路径排序即树的先序）。
func (s *Service) List(ctx context.Context, tenantID string) ([]Node, error) {
	out := make([]Node, 0, 16)
	err := db.WithTenant(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT d.id::text, d.name, d.parent_id::text, d.path::text, nlevel(d.path), d.sort,
			       d.ldap_dn IS NOT NULL,
			       (SELECT count(*) FROM app_user u
			         WHERE u.dept_id = d.id AND u.deleted_at IS NULL)::int,
			       (SELECT count(*) FROM space sp
			         WHERE sp.dept_id = d.id AND sp.deleted_at IS NULL)::int
			  FROM dept d
			 WHERE d.deleted_at IS NULL
			 ORDER BY d.path`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var n Node
			if err := rows.Scan(&n.ID, &n.Name, &n.ParentID, &n.Path, &n.Depth, &n.Sort,
				&n.Directory, &n.MemberCount, &n.SpaceCount); err != nil {
				return err
			}
			out = append(out, n)
		}
		return rows.Err()
	})
	return out, err
}

// Create 在 parentID 下新建部门；parentID 为空时挂到顶层部门下。
func (s *Service) Create(ctx context.Context, tenantID, name, parentID string) (Node, error) {
	name, err := cleanName(name)
	if err != nil {
		return Node{}, err
	}
	var out Node
	err = db.WithTenant(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		parent, perr := resolveParent(ctx, tx, tenantID, parentID)
		if perr != nil {
			return perr
		}
		if err := assertNameFree(ctx, tx, parent.ID, name, ""); err != nil {
			return err
		}
		path := joinPath(parent.Path, name)
		if strings.Count(path, ".")+1 > MaxDepth {
			return fmt.Errorf("%w：最多 %d 层", ErrTooDeep, MaxDepth)
		}
		var sortOrder int
		_ = tx.QueryRow(ctx,
			`SELECT coalesce(max(sort), 0) + 10 FROM dept
			  WHERE tenant_id = $1 AND parent_id IS NOT DISTINCT FROM $2 AND deleted_at IS NULL`,
			tenantID, parent.ID).Scan(&sortOrder)

		var parentArg any
		if parent.ID != "" {
			parentArg = parent.ID
		}
		if err := tx.QueryRow(ctx, `
			INSERT INTO dept (id, tenant_id, parent_id, path, name, sort)
			VALUES (gen_random_uuid(), $1, $2, text2ltree($3), $4, $5)
			RETURNING id::text, parent_id::text, path::text, nlevel(path), sort`,
			tenantID, parentArg, path, name, sortOrder).
			Scan(&out.ID, &out.ParentID, &out.Path, &out.Depth, &out.Sort); err != nil {
			return err
		}
		out.Name = name
		return nil
	})
	return out, err
}

// Rename 改部门显示名。
//
// 只改 name，**不动 path**：path 是对外契约（ACL 存的是路径前缀、浏览器可能已经拿到），
// 更重要是改 path 要连带重写整棵子树，代价与风险都不成比例。
// 代价是"路径里的标签与名字可能不一致"——它是标识符，本来就不该当名字用。
func (s *Service) Rename(ctx context.Context, tenantID, id, name string) (Change, error) {
	name, err := cleanName(name)
	if err != nil {
		return Change{}, err
	}
	var ch Change
	err = db.WithTenant(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		before, gerr := get(ctx, tx, id)
		if gerr != nil {
			return gerr
		}
		if before.Directory {
			return ErrDirectoryManaged
		}
		if before.Name == name {
			ch = Change{ID: id, Before: before, After: before}
			return nil
		}
		if e := assertNameFree(ctx, tx, deref(before.ParentID), name, before.ID); e != nil {
			return e
		}
		if _, e := tx.Exec(ctx,
			`UPDATE dept SET name = $2 WHERE id = $1 AND deleted_at IS NULL`, id, name); e != nil {
			return e
		}
		after, e := get(ctx, tx, id)
		if e != nil {
			return e
		}
		ch = Change{ID: id, Before: before, After: after}
		return nil
	})
	return ch, err
}

// Move 把部门（连同整棵子树）挂到新上级下。newParentID 为空表示挂到顶层。
func (s *Service) Move(ctx context.Context, tenantID, id, newParentID string) (Change, error) {
	var ch Change
	err := db.WithTenant(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		before, gerr := get(ctx, tx, id)
		if gerr != nil {
			return gerr
		}
		if before.Directory {
			// 目录里的层级由 DN 决定，本地挪走会在下次同步时被拉回来
			return ErrDirectoryManaged
		}
		parent, perr := resolveParent(ctx, tx, tenantID, newParentID)
		if perr != nil {
			return perr
		}
		if parent.ID == id {
			return ErrCycle
		}
		// 目标在自己子树里 = 成环。用 ltree 的包含判断，比在 Go 里爬父链可靠。
		//
		// 注意方向：`A <@ B` 表示 A 是 B 的后代（或相等）。
		// 要判的是"新上级是不是自己的后代"，所以左边是 parent.path、右边是自己的路径。
		// 写成 `text2ltree($path) <@ path` 会把判断反过来——挪到祖先下被误拒，
		// 挪到后代下被放行（那正是把树拧成环的那一步）。
		if parent.ID != "" {
			var inside bool
			if e := tx.QueryRow(ctx,
				`SELECT path <@ text2ltree($2) FROM dept WHERE id = $1 AND deleted_at IS NULL`,
				parent.ID, before.Path).Scan(&inside); e != nil {
				return e
			}
			if inside {
				return ErrCycle
			}
		}
		if err := assertNameFree(ctx, tx, parent.ID, before.Name, before.ID); err != nil {
			return err
		}
		newPath := joinPath(parent.Path, before.Name)
		if strings.Count(newPath, ".")+1 > MaxDepth {
			return fmt.Errorf("%w：最多 %d 层", ErrTooDeep, MaxDepth)
		}

		var parentArg any
		if parent.ID != "" {
			parentArg = parent.ID
		}
		if _, e := tx.Exec(ctx,
			`UPDATE dept SET parent_id = $2 WHERE id = $1 AND deleted_at IS NULL`, id, parentArg); e != nil {
			return e
		}
		// 子树整体换前缀：subpath(path, nlevel(旧)) 取出旧前缀之后的部分，接到新前缀上。
		// 一条语句完成，避免"改一半失败"留下悬挂的路径。
		// 被移动的节点本身也要一起改，但它的路径长度等于旧前缀，
		// subpath(path, nlevel(old)) 会越界（PostgreSQL 报 "invalid positions"）。
		// 因此单独取下界：叶子节点直接换成新路径，其余接上旧前缀之后的部分。
		if _, e := tx.Exec(ctx, `
			UPDATE dept
			   SET path = CASE
			                WHEN nlevel(path) = nlevel(text2ltree($3)) THEN text2ltree($2)
			                ELSE text2ltree($2) || subpath(path, nlevel(text2ltree($3)))
			              END
			 WHERE tenant_id = $1 AND path <@ text2ltree($3) AND deleted_at IS NULL`,
			tenantID, newPath, before.Path); e != nil {
			return e
		}
		after, e := get(ctx, tx, id)
		if e != nil {
			return e
		}
		ch = Change{ID: id, Before: before, After: after, MovedTo: parent.ID}
		return nil
	})
	return ch, err
}

// Delete 软删除部门。三条护栏都是"删了会留下坏数据"的情形，宁可拒绝也不级联：
// 子部门、成员、空间。级联删除会把人的归属悄悄改掉，属于不可接受的行为。
func (s *Service) Delete(ctx context.Context, tenantID, id string) (Node, error) {
	var before Node
	err := db.WithTenant(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		b, gerr := get(ctx, tx, id)
		if gerr != nil {
			return gerr
		}
		before = b
		if b.Directory {
			return ErrDirectoryManaged
		}
		if b.ParentID == nil {
			// 根部门是"成员没选部门"时的兜底容器，删掉会让成员无处可挂
			return ErrCannotDeleteRoot
		}
		if b.MemberCount > 0 {
			return fmt.Errorf("%w（%d 人）", ErrHasMembers, b.MemberCount)
		}
		if b.SpaceCount > 0 {
			return fmt.Errorf("%w（%d 个）", ErrHasSpaces, b.SpaceCount)
		}
		var kids int
		if e := tx.QueryRow(ctx,
			`SELECT count(*) FROM dept WHERE parent_id = $1 AND deleted_at IS NULL`, id).Scan(&kids); e != nil {
			return e
		}
		if kids > 0 {
			return fmt.Errorf("%w（%d 个）", ErrHasChildren, kids)
		}
		_, e := tx.Exec(ctx, `UPDATE dept SET deleted_at = now() WHERE id = $1 AND deleted_at IS NULL`, id)
		return e
	})
	return before, err
}

// ---------------- 内部 ----------------

func cleanName(raw string) (string, error) {
	name := strings.TrimSpace(raw)
	if name == "" {
		return "", fmt.Errorf("%w：不能为空", ErrInvalidInput)
	}
	if len([]rune(name)) > maxNameLen {
		return "", fmt.Errorf("%w：最多 %d 个字符", ErrInvalidInput, maxNameLen)
	}
	if strings.ContainsAny(name, "\r\n\t\x00") {
		return "", fmt.Errorf("%w：不能包含换行或制表符", ErrInvalidInput)
	}
	return name, nil
}

// resolveParent 找出上级部门；parentID 为空时挑一个顶层。
//
// 不直接"新建一个顶层"：多顶层会让"成员的部门"没有唯一根，
// 而按部门授权是靠路径前缀展开的，两个根各自成树、互不相干——
// 界面上看不出差别，授权时却少了一半人。
func resolveParent(ctx context.Context, tx pgx.Tx, tenantID, parentID string) (Node, error) {
	if parentID != "" {
		var n Node
		var path string
		err := tx.QueryRow(ctx, `
			SELECT id::text, name, parent_id::text, path::text, nlevel(path)
			  FROM dept WHERE id = $1 AND deleted_at IS NULL`, parentID).
			Scan(&n.ID, &n.Name, &n.ParentID, &path, &n.Depth)
		if errors.Is(err, pgx.ErrNoRows) {
			return Node{}, ErrNoParent
		}
		if err != nil {
			return Node{}, err
		}
		n.Path = path
		return n, nil
	}

	rows, err := tx.Query(ctx, `
		SELECT id::text, name, path::text, nlevel(path)
		  FROM dept WHERE parent_id IS NULL AND deleted_at IS NULL
		 ORDER BY (path::text = 'root') DESC, path`)
	if err != nil {
		return Node{}, err
	}
	defer rows.Close()
	var roots []Node
	for rows.Next() {
		var n Node
		if err := rows.Scan(&n.ID, &n.Name, &n.Path, &n.Depth); err != nil {
			return Node{}, err
		}
		roots = append(roots, n)
	}
	if err := rows.Err(); err != nil {
		return Node{}, err
	}
	switch len(roots) {
	case 0:
		// 没有任何部门（理论上不会发生：开通即建「总部」）。
		// 这里返回"空上级"，由调用方按顶层插入，避免把租户卡死。
		return Node{}, nil
	case 1:
		return roots[0], nil
	default:
		return Node{}, ErrAmbiguousRootPick
	}
}

// assertNameFree 校验同级下没有同名部门（不区分大小写）。
//
// 同一父级下重名不是"小事"：按部门授权时两个"财务"在界面上无法区分，
// 选错一个就意味着给了错的人权限。
func assertNameFree(ctx context.Context, tx pgx.Tx, parentID, name, excludeID string) error {
	query := `SELECT 1 FROM dept
	           WHERE parent_id IS NOT DISTINCT FROM $1
	             AND lower(name) = lower($2) AND deleted_at IS NULL`
	args := []any{nullable(parentID), name}
	if excludeID != "" {
		query += ` AND id <> $3`
		args = append(args, excludeID)
	}
	var one int
	err := tx.QueryRow(ctx, query+` LIMIT 1`, args...).Scan(&one)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	return ErrNameTaken
}

// get 读单个部门（含占用计数）。改名前后的快照都靠它，避免两处拼字段。
func get(ctx context.Context, tx pgx.Tx, id string) (Node, error) {
	var n Node
	err := tx.QueryRow(ctx, `
		SELECT d.id::text, d.name, d.parent_id::text, d.path::text, nlevel(d.path), d.sort,
		       d.ldap_dn IS NOT NULL,
		       (SELECT count(*) FROM app_user u WHERE u.dept_id = d.id AND u.deleted_at IS NULL)::int,
		       (SELECT count(*) FROM space sp WHERE sp.dept_id = d.id AND sp.deleted_at IS NULL)::int
		  FROM dept d WHERE d.id = $1 AND d.deleted_at IS NULL`, id).
		Scan(&n.ID, &n.Name, &n.ParentID, &n.Path, &n.Depth, &n.Sort,
			&n.Directory, &n.MemberCount, &n.SpaceCount)
	if errors.Is(err, pgx.ErrNoRows) {
		return Node{}, ErrNotFound
	}
	return n, err
}

// joinPath 把上级路径与名字拼成 ltree 路径；上级为空表示顶层。
func joinPath(parentPath, name string) string {
	label := LTLabel(name)
	if parentPath == "" {
		return label
	}
	return parentPath + "." + label
}

// LTLabel 把部门名转成合法的 ltree 标签（只允许字母数字下划线）。
//
// 中文与 & 一律换成下划线，因此名称不同也可能撞标签：末尾追加名称哈希的前 8 位，
// 保证"同父下不同名"永远不会拿到同一个标签。
// 目录同步（internal/directory）也走这里，两处生成的路径才能一致。
func LTLabel(name string) string {
	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	label := b.String()
	if len(label) > 40 {
		label = label[:40]
	}
	sum := sha256.Sum256([]byte(name))
	return fmt.Sprintf("%s_%x", label, sum[:4])
}

func nullable(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
