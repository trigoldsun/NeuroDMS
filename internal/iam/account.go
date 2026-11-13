package iam

// 账号注销与数字资产交接。
//
// 为什么不能"直接删掉一行"：
// 这个系统里"用户"不只是登录凭据，还是**资产的宿主**——
//   - space.owner_id / node.owner_id 指向他；
//   - ace 表里可能只有他一个是 owner 级授权（删掉之后目录就没人能管了）；
//   - share 表里有他创建的外发链接（链接仍然有效）。
//
// 只把 app_user 置成 deleted，结果是一堆资产失去负责人、若干外链继续对外开放。
// 所以注销必须先"交接"，再"删除"，两步在同一个事务里完成。

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"docvault/internal/db"

	"github.com/jackc/pgx/v5"
)

// HandoverSummary 是注销前给用户看的"会发生什么"。
type HandoverSummary struct {
	Spaces        int `json:"spaces"`
	Nodes         int `json:"nodes"`
	Grants        int `json:"grants"`
	RevokedShares int `json:"revokedShares"`
}

// ErrNoSuccessor 表示未指定继任者或继任者不可用。
var ErrNoSuccessor = errors.New("接收方账号不存在或不可用")

// Candidate 是可接收资产的账号（只暴露辨认所需的最小字段）。
type Candidate struct {
	ID          string `json:"id"`
	Username    string `json:"username"`
	DisplayName string `json:"displayName"`
}

// Candidates 列出可接收资产的账号。
//
// 只返回同租户、可登录、未过期的其他账号；不返回密级/封顶等安全属性——
// 交接只需要"选个人"，不需要把组织的人员画像摊开。
func (s *Service) Candidates(ctx context.Context, tenantID, userID, q string) ([]Candidate, error) {
	out := []Candidate{}
	err := db.WithTenant(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT id::text, username, display_name
			  FROM app_user
			 WHERE tenant_id = $1
			   AND id <> $2
			   AND deleted_at IS NULL AND status = 'active'
			   AND (expires_at IS NULL OR expires_at > now())
			   AND ($3 = '' OR username ILIKE $3 OR display_name ILIKE $3)
			 ORDER BY lower(display_name), lower(username)
			 LIMIT 50`, tenantID, userID, likePattern(q))
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var c Candidate
			if err := rows.Scan(&c.ID, &c.Username, &c.DisplayName); err != nil {
				return err
			}
			out = append(out, c)
		}
		return rows.Err()
	})
	return out, err
}

// HandoverPreview 只读统计，用于在确认页上"先看清再动手"。
func (s *Service) HandoverPreview(ctx context.Context, tenantID, userID string) (HandoverSummary, error) {
	var sum HandoverSummary
	err := db.WithTenant(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		var e error
		sum, e = summarize(ctx, tx, tenantID, userID)
		return e
	})
	return sum, err
}

func summarize(ctx context.Context, tx pgx.Tx, tenantID, userID string) (HandoverSummary, error) {
	var sum HandoverSummary
	const q = `
		SELECT
		  (SELECT count(*) FROM space WHERE tenant_id = $1 AND owner_id = $2 AND deleted_at IS NULL),
		  (SELECT count(*) FROM node  WHERE tenant_id = $1 AND owner_id = $2 AND deleted_at IS NULL),
		  (SELECT count(*) FROM ace   WHERE tenant_id = $1 AND subject_type = 'user' AND subject_id = $2),
		  (SELECT count(*) FROM share WHERE tenant_id = $1 AND creator_id = $2 AND revoked_at IS NULL)`
	if err := tx.QueryRow(ctx, q, tenantID, userID).
		Scan(&sum.Spaces, &sum.Nodes, &sum.Grants, &sum.RevokedShares); err != nil {
		return HandoverSummary{}, err
	}
	return sum, nil
}

// SelfDelete 注销自己的账号。
//
// 顺序（不可调换）：
//  1. 校验确认串与继任者 —— 这两项任一不对就在写任何数据之前失败；
//  2. 最后一个可用管理员保护 —— 注销掉的若是唯一 sysadmin，租户将永久失去管理入口；
//  3. 交接空间/节点归属；
//  4. 交接权限条目（先与继任者已有的条目合并位图，再改归属，避免唯一索引冲突）；
//  5. 撤销本人创建的外发链接（链接属于人，不该跟着资产走）；
//  6. 清掉未完成的分片上传（否则临时文件永远留在磁盘上）；
//  7. 软删账号 + 吊销全部会话。
func (s *Service) SelfDelete(ctx context.Context, tenantID, userID, successorID, confirm string) (HandoverSummary, error) {
	successorID = strings.TrimSpace(successorID)
	if successorID == "" || successorID == userID {
		return HandoverSummary{}, fmt.Errorf("%w: 必须指定一位其他账号", ErrNoSuccessor)
	}

	var sum HandoverSummary
	err := db.WithTenant(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		var username, status string
		if err := tx.QueryRow(ctx, `
			SELECT username, status FROM app_user
			 WHERE id = $1 AND deleted_at IS NULL`, userID).Scan(&username, &status); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrNotFound
			}
			return err
		}
		// 确认串用用户名：注销是不可逆操作，要求用户手打自己的账号名，
		// 避免"点错一下就把号删了"。
		if strings.TrimSpace(confirm) != username {
			return fmt.Errorf("%w: 请输入自己的账号名以确认", ErrInvalidInput)
		}

		// 继任者必须可用：停用/过期的账号接管资产等于把资产放进死信箱
		var ok bool
		if err := tx.QueryRow(ctx, `
			SELECT EXISTS (
				SELECT 1 FROM app_user
				 WHERE id = $1 AND tenant_id = $2 AND deleted_at IS NULL AND status = 'active'
				   AND (expires_at IS NULL OR expires_at > now()))`,
			successorID, tenantID).Scan(&ok); err != nil {
			return err
		}
		if !ok {
			return ErrNoSuccessor
		}

		if err := ensureNotLastAdmin(ctx, tx, tenantID, userID); err != nil {
			return err
		}

		var e error
		if sum, e = summarize(ctx, tx, tenantID, userID); e != nil {
			return e
		}

		// 3) 归属交接
		if _, e := tx.Exec(ctx,
			`UPDATE space SET owner_id = $2 WHERE tenant_id = $1 AND owner_id = $3`,
			tenantID, successorID, userID); e != nil {
			return e
		}
		if _, e := tx.Exec(ctx,
			`UPDATE node SET owner_id = $2 WHERE tenant_id = $1 AND owner_id = $3`,
			tenantID, successorID, userID); e != nil {
			return e
		}

		// 4) 权限条目：先把我的位图并进继任者已有的那条，再把剩余的改归属。
		//
		// 直接改归属会撞 uq_ace_object_subject（同一对象同一主体只能有一条）。
		// 合并时 deny 位取并集：宁可保留一条拒绝，也不要在交接中悄悄放开权限。
		//
		// 注意 WHERE 里必须显式用上 $1（tenant_id）。只写 m.tenant_id = t.tenant_id
		// 的话 $1 就成了"未使用参数"，PostgreSQL 无法推断它的类型，
		// 直接报 could not determine data type of parameter $1（42P18）。
		if _, e := tx.Exec(ctx, `
			UPDATE ace t
			   SET allow_bits = t.allow_bits | m.allow_bits,
			       deny_bits  = t.deny_bits  | m.deny_bits,
			       updated_at = now()
			  FROM ace m
			 WHERE m.tenant_id = $1 AND t.tenant_id = $1
			   AND m.subject_type = 'user' AND m.subject_id = $3
			   AND t.subject_type = 'user' AND t.subject_id = $2
			   AND t.object_type = m.object_type AND t.object_id = m.object_id`,
			tenantID, successorID, userID); e != nil {
			return e
		}
		if _, e := tx.Exec(ctx,
			// 合并之后必须把我方那条**删掉**。
			//
			// 只合位图是不够的：紧接着把剩余条目改成继任者时，这条会与刚合并过的那条
			// 落在同一个 (租户, 对象, 主体) 上，直接撞 uq_ace_object_subject。
			// 这是实测暴露的：合并成功、改归属 500，整笔事务回滚。
			`DELETE FROM ace m
			  WHERE m.tenant_id = $1
			    AND m.subject_type = 'user' AND m.subject_id = $3
			    AND EXISTS (
			          SELECT 1 FROM ace t
			           WHERE t.tenant_id = m.tenant_id
			             AND t.subject_type = 'user' AND t.subject_id = $2
			             AND t.object_type = m.object_type AND t.object_id = m.object_id)`,
			tenantID, successorID, userID); e != nil {
			return e
		}
		if _, e := tx.Exec(ctx,
			`UPDATE ace SET subject_id = $2, granted_by = $2, updated_at = now()
			  WHERE tenant_id = $1 AND subject_type = 'user' AND subject_id = $3`,
			tenantID, successorID, userID); e != nil {
			return e
		}

		// 5) 撤销本人创建的外发链接：链接是"人的凭证"，不随资产转移。
		if _, e := tx.Exec(ctx, `
			UPDATE share SET revoked_at = now(), revoked_by = $2
			 WHERE tenant_id = $1 AND creator_id = $3 AND revoked_at IS NULL`,
			tenantID, successorID, userID); e != nil {
			return e
		}
		if _, e := tx.Exec(ctx, `
			UPDATE share_ticket t SET revoked_at = now()
			  FROM share s
			 WHERE s.id = t.share_id AND s.tenant_id = $1 AND s.creator_id = $2
			   AND t.revoked_at IS NULL`, tenantID, userID); e != nil {
			return e
		}

		// 6) 未完成的分片上传：分片文件在磁盘上，必须连记录一起清
		if _, e := tx.Exec(ctx, `
			DELETE FROM upload_part
			 WHERE session_id IN (SELECT id FROM upload_session WHERE tenant_id = $1 AND created_by = $2)`,
			tenantID, userID); e != nil {
			return e
		}
		if _, e := tx.Exec(ctx,
			`DELETE FROM upload_session WHERE tenant_id = $1 AND created_by = $2`,
			tenantID, userID); e != nil {
			return e
		}

		// 7) 软删 + 吊销会话
		if _, e := tx.Exec(ctx, `
			UPDATE app_user
			   SET status = 'deleted', deleted_at = now(),
			       session_epoch = session_epoch + 1, updated_at = now()
			 WHERE id = $1`, userID); e != nil {
			return e
		}
		_, e = tx.Exec(ctx,
			`UPDATE session SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL`, userID)
		return e
	})
	if err != nil {
		return HandoverSummary{}, err
	}
	return sum, nil
}
