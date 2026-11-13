package content

// 版本保留清理。
//
// 版本历史是唯一"只增不减"的数据：每次保存、每次回退都追加一行，
// 客户删文件也只会进回收站。没有上限时，一个被反复编辑的文件能堆出几千个版本，
// 其中绝大多数永远不会被回退到。
//
// 清理的边界必须写死：只删"超过保留数量的非当前版本"。
// 当前版本由触发器标记为 effective，任何情况下都不能删。

import (
	"context"

	"docvault/internal/db"

	"github.com/jackc/pgx/v5"
)

// PruneVersions 删除节点超出保留数量的旧版本，返回删除条数。
//
// 两个明确的行为边界：
//  1. 永不删 state='effective' 的版本，即使它的 version_no 落在删除区间内；
//  2. 删除会触发 blob.ref_count 递减，但**不会删除 blob 行与物理文件**。
//     真正释放磁盘属于存储治理的 blob GC（docs/20 §3），尚未实施——
//     在它上线前，"清理版本"只减少版本条目，不会让磁盘占用下降。
func (s *Store) PruneVersions(ctx context.Context, tenantID, nodeID string, keep int) (int, error) {
	if keep < 1 {
		keep = 1
	}

	var removed int64
	err := db.WithTenant(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		ct, err := tx.Exec(ctx, `
			DELETE FROM version
			 WHERE node_id = $1
			   AND state <> 'effective'
			   AND version_no <= (
			       SELECT COALESCE(max(version_no), 0) FROM version WHERE node_id = $1
			   ) - $2`,
			nodeID, keep)
		if err != nil {
			return err
		}
		removed = ct.RowsAffected()
		return nil
	})
	return int(removed), err
}
