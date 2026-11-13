package iam

// 账号与空间所有权的耦合检查。
//
// 停用/删除账号时不检查"他名下还有没有空间"，结果是空间 owner_id 指向一个
// 再也登不进来的人；而空间根上的 ACE 往往只有他一条 —— 这个空间从此
// 谁也进不去，管理员在空间列表里也看不到（列表按"我是所有者或有 ACE"过滤）。
//
// 所以这两条路径都必须先看名下空间：有就拒绝，把清单交回去，
// 让操作者先去"移交"再回来。这是唯一能保证资产不丢的时机。

import (
	"context"
	"errors"
	"fmt"

	"docvault/internal/db"

	"github.com/jackc/pgx/v5"
)

// OwnedSpace 是"停用前必须交代清楚"的一行。
type OwnedSpace struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Granted    int    `json:"granted"`
	OnlyMine   bool   `json:"onlyMine"`
	ClassLevel int    `json:"classification"`
}

// ErrOwnsSpaces 表示账号名下仍有空间，操作被拒绝。
var ErrOwnsSpaces = errors.New("账号名下仍有文档空间，需先移交")

// OwnsSpacesError 携带具体清单，接口据此返回 409 + data.spaces。
type OwnsSpacesError struct {
	Spaces []OwnedSpace
}

func (e *OwnsSpacesError) Error() string {
	if len(e.Spaces) == 1 {
		return fmt.Sprintf("该账号名下还有 1 个文档空间「%s」，请先移交再停用", e.Spaces[0].Name)
	}
	return fmt.Sprintf("该账号名下还有 %d 个文档空间，请先移交再停用", len(e.Spaces))
}

func (e *OwnsSpacesError) Unwrap() error { return ErrOwnsSpaces }

// ownedSpacesTx 查出该用户名下的空间，并对这些空间行加锁。
//
// 加锁的理由：调用方紧接着要改 app_user。不加锁的话，另一笔事务可以
// 在"检查通过"和"停用生效"之间给他新建一个空间，检查就白做了。
// 移交写空间行用的也是这把锁，两边天然互斥。
func ownedSpacesTx(ctx context.Context, tx pgx.Tx, tenantID, userID string) ([]OwnedSpace, error) {
	rows, err := tx.Query(ctx, `
		SELECT id FROM space
		 WHERE tenant_id = $1 AND owner_id = $2 AND deleted_at IS NULL
		 FOR UPDATE`, tenantID, userID)
	if err != nil {
		return nil, err
	}
	ids := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(ids) == 0 {
		return nil, nil
	}

	out := make([]OwnedSpace, 0, len(ids))
	rs, err := tx.Query(ctx, `
		SELECT s.id::text, s.name, s.classification,
		       (SELECT count(*) FROM ace a
		         WHERE a.tenant_id = s.tenant_id AND a.object_type = 'space' AND a.object_id = s.id)::int,
		       NOT EXISTS (
		         SELECT 1 FROM ace a
		          WHERE a.tenant_id = s.tenant_id AND a.object_type = 'space' AND a.object_id = s.id
		            AND NOT (a.subject_type = 'user' AND a.subject_id = s.owner_id)
		       )
		  FROM space s
		 WHERE s.tenant_id = $1 AND s.id = ANY($2::uuid[])
		 ORDER BY lower(s.name)`, tenantID, ids)
	if err != nil {
		return nil, err
	}
	defer rs.Close()
	for rs.Next() {
		var o OwnedSpace
		if err := rs.Scan(&o.ID, &o.Name, &o.ClassLevel, &o.Granted, &o.OnlyMine); err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return out, rs.Err()
}

// IsSysAdmin 判断某人是否系统管理员。
//
// 空间移交是"所有者或系统管理员"二选一的入口，而令牌里不带角色
// （角色随时可被撤销，塞进令牌会让撤销延迟到过期）。所以这里现查一次。
func (s *Service) IsSysAdmin(ctx context.Context, tenantID, userID string) (bool, error) {
	var ok bool
	err := db.WithTenant(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
			SELECT EXISTS (
				SELECT 1 FROM user_role ur
				  JOIN role r ON r.id = ur.role_id
				 WHERE ur.tenant_id = $1 AND ur.user_id = $2 AND r.code = 'sysadmin')`,
			tenantID, userID).Scan(&ok)
	})
	return ok, err
}
