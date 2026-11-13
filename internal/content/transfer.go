package content

// 空间所有权移交。
//
// 一条空间的所有权落在三个地方，必须同时改，否则会出现"名字变了、权限没变"
// 这种比不做更糟的中间态：
//   1. space.owner_id            —— 谁是负责人
//   2. node.owner_id（本空间内）  —— 文件归属，列表页"归属"列读的就是它
//   3. ace(object_type='space')  —— 真正决定能不能进得去
//
// 另外两种组合的生效方式不同：
//   - 所有者自己移交 / 管理员转给第三方 → 立即生效；
//   - 管理员转给自己 → 必须原所有者确认（利益冲突，不能自己说了算）。
// 这一层只负责"改数据"，谁能发起、要不要确认由 httpapi 判定。

import (
	"context"
	"errors"
	"strings"
	"time"

	"docvault/internal/db"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

var (
	// ErrSpaceNotFound 空间不存在或已删除。
	ErrSpaceNotFound = errors.New("空间不存在")
	// ErrNotSpaceOwner 调用方不是该空间的所有者。
	ErrNotSpaceOwner = errors.New("只有空间所有者可以执行移交")
	// ErrSameOwner 目标已经是该空间的所有者。
	ErrSameOwner = errors.New("接收人已经是该空间的所有者")
	// ErrTargetUnavailable 接收人不可用（停用、已删除、已过期）。
	ErrTargetUnavailable = errors.New("接收人账号不可用")
	// ErrTargetClearance 接收人密级低于空间密级：移交了也打不开，等于制造孤儿。
	ErrTargetClearance = errors.New("接收人密级低于空间密级")
	// ErrTargetDenied 接收人在该空间上有显式拒绝。不静默清掉 deny——那是安全策略。
	ErrTargetDenied = errors.New("接收人在该空间上有显式拒绝")
	// ErrTransferExists 该空间已有待确认的请求。
	ErrTransferExists = errors.New("该空间已有待确认的移交请求")
	// ErrTransferNotFound 请求不存在、已处理或不属于调用方。
	ErrTransferNotFound = errors.New("移交请求不存在或已处理")
	// ErrTransferExpired 请求已过期。
	ErrTransferExpired = errors.New("移交请求已过期")
	// ErrTransferStale 审批期间空间所有者变了，请求失效。
	ErrTransferStale = errors.New("空间所有者已变更，请重新发起")
)

// SpaceOwner 是移交判定需要的空间侧信息。
type SpaceOwner struct {
	ID             string
	Name           string
	Kind           string
	OwnerID        string
	OwnerName      string
	OwnerStatus    string
	Classification int
	CreatedAt      time.Time
}

// TransferRequest 是待确认的移交请求（也用于回显已处理的请求）。
type TransferRequest struct {
	ID            string     `json:"id"`
	SpaceID       string     `json:"spaceId"`
	SpaceName     string     `json:"spaceName"`
	FromUserID    string     `json:"fromUserId"`
	FromName      string     `json:"fromName"`
	ToUserID      string     `json:"toUserId"`
	ToName        string     `json:"toName"`
	InitiatedBy   string     `json:"initiatedBy"`
	InitiatorName string     `json:"initiatorName"`
	Mode          string     `json:"mode"`
	Status        string     `json:"status"`
	Reason        string     `json:"reason"`
	CreatedAt     time.Time  `json:"createdAt"`
	ExpiresAt     time.Time  `json:"expiresAt"`
	DecidedAt     *time.Time `json:"decidedAt,omitempty"`
}

// SpaceOverview 是管理台"空间台账"的一行。
//
// 只回元数据，不回内容：系统管理员管的是"谁的东西、有没有人管"，
// 而不是"里面写了什么"。
type SpaceOverview struct {
	ID             string     `json:"id"`
	Name           string     `json:"name"`
	Kind           string     `json:"kind"`
	OwnerID        string     `json:"ownerId"`
	OwnerName      string     `json:"ownerName"`
	OwnerStatus    string     `json:"ownerStatus"`
	Classification int        `json:"classification"`
	UsedBytes      int64      `json:"usedBytes"`
	QuotaBytes     *int64     `json:"quotaBytes"`
	CreatedAt      time.Time  `json:"createdAt"`
	LastActivity   *time.Time `json:"lastActivity,omitempty"`
	// Granted 是直接挂在该空间上的授权条目数（不含继承）。
	Granted int `json:"granted"`
	// OnlyOwner 表示除所有者本人之外没有任何用户/部门/角色/组授权。
	// 这一列是"离职即失联"的预警信号。
	OnlyOwner    bool   `json:"onlyOwner"`
	PendingID    string `json:"pendingId,omitempty"`
	PendingTo    string `json:"pendingTo,omitempty"`
	PendingUntil string `json:"pendingUntil,omitempty"`
}

// GetSpaceOwner 读取空间与所有者信息（不做权限判定，调用方自己判）。
func (s *Store) GetSpaceOwner(ctx context.Context, tenantID, spaceID string) (SpaceOwner, error) {
	var out SpaceOwner
	err := db.WithTenant(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
			SELECT s.id::text, s.name, s.kind, s.owner_id::text,
			       COALESCE(u.display_name, ''), COALESCE(u.status, ''),
			       s.classification, s.created_at
			  FROM space s
			  LEFT JOIN app_user u ON u.id = s.owner_id
			 WHERE s.id = $1 AND s.deleted_at IS NULL`, spaceID).
			Scan(&out.ID, &out.Name, &out.Kind, &out.OwnerID, &out.OwnerName,
				&out.OwnerStatus, &out.Classification, &out.CreatedAt)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return SpaceOwner{}, ErrSpaceNotFound
	}
	return out, err
}

// TransferNow 立即移交（所有者本人、或管理员转给第三方）。
//
// fromUserID 是调用方认为的"当前所有者"。事务内会重新读一遍并比对：
// 两次点击之间别人已经移交过，就不能按旧假设覆盖。
func (s *Store) TransferNow(ctx context.Context, tenantID, spaceID, fromUserID, toUserID, initiatorID string) error {
	return db.WithTenant(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		return transferSpaceTx(ctx, tx, tenantID, spaceID, fromUserID, toUserID, initiatorID)
	})
}

// RequestTransfer 创建一条待确认请求（管理员转给自己时使用）。
func (s *Store) RequestTransfer(ctx context.Context, tenantID, spaceID, fromUserID, toUserID, initiatorID, reason string) (TransferRequest, error) {
	var id string
	err := db.WithTenant(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		var ownerID string
		var cls int
		if err := tx.QueryRow(ctx, `
			SELECT owner_id::text, classification FROM space
			 WHERE id = $1 AND tenant_id = $2 AND deleted_at IS NULL
			 FOR UPDATE`, spaceID, tenantID).Scan(&ownerID, &cls); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrSpaceNotFound
			}
			return err
		}
		if ownerID != fromUserID {
			return ErrTransferStale
		}
		if toUserID == ownerID {
			return ErrSameOwner
		}
		if err := checkTarget(ctx, tx, tenantID, spaceID, cls, toUserID); err != nil {
			return err
		}
		// 先让过期请求落位，否则唯一索引会挡住新请求（用户看到的却是"已有请求"）。
		if _, err := tx.Exec(ctx, `
			UPDATE space_transfer SET status = 'expired', decided_at = now()
			 WHERE space_id = $1 AND tenant_id = $2 AND status = 'pending' AND expires_at < now()`,
			spaceID, tenantID); err != nil {
			return err
		}
		return tx.QueryRow(ctx, `
			INSERT INTO space_transfer (tenant_id, space_id, from_user_id, to_user_id, initiated_by, mode, reason)
			VALUES ($1, $2, $3, $4, $5, 'admin_to_self', $6)
			RETURNING id::text`,
			tenantID, spaceID, fromUserID, toUserID, initiatorID, reason).Scan(&id)
	})
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return TransferRequest{}, ErrTransferExists
		}
		return TransferRequest{}, err
	}
	return s.getTransfer(ctx, tenantID, id)
}

// DecideTransfer 由原所有者批准或拒绝一条请求。
//
// 拒绝要真的落库：管理员会反复发起，没有"已驳回"这个状态，
// 所有者每次都得重新点一遍，久了就变成无脑点同意。
func (s *Store) DecideTransfer(ctx context.Context, tenantID, requestID, ownerID string, approve bool) (TransferRequest, error) {
	// 过期是"要提交的事实"，不能从事务函数里 return 出去：
	// 那样事务回滚，状态永远停在 pending（刷新令牌重放踩过同一个坑）。
	var expired bool
	var stale bool
	err := db.WithTenant(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		var spaceID, fromID, toID, status string
		var expires time.Time
		if err := tx.QueryRow(ctx, `
			SELECT space_id::text, from_user_id::text, to_user_id::text, status, expires_at
			  FROM space_transfer
			 WHERE id = $1 AND tenant_id = $2
			 FOR UPDATE`, requestID, tenantID).Scan(&spaceID, &fromID, &toID, &status, &expires); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrTransferNotFound
			}
			return err
		}
		if status != "pending" {
			return ErrTransferNotFound
		}
		if fromID != ownerID {
			return ErrNotSpaceOwner
		}
		if expires.Before(time.Now()) {
			expired = true
			_, e := tx.Exec(ctx, `
				UPDATE space_transfer SET status = 'expired', decided_at = now()
				 WHERE id = $1 AND tenant_id = $2`, requestID, tenantID)
			return e
		}
		if !approve {
			_, e := tx.Exec(ctx, `
				UPDATE space_transfer SET status = 'rejected', decided_at = now(), decided_by = $3
				 WHERE id = $1 AND tenant_id = $2`, requestID, tenantID, ownerID)
			return e
		}
		if e := transferSpaceTx(ctx, tx, tenantID, spaceID, fromID, toID, ownerID); e != nil {
			if errors.Is(e, ErrTransferStale) {
				stale = true
				_, x := tx.Exec(ctx, `
					UPDATE space_transfer SET status = 'cancelled', decided_at = now(), decided_by = $3
					 WHERE id = $1 AND tenant_id = $2`, requestID, tenantID, ownerID)
				return x
			}
			return e
		}
		// transferSpaceTx 会把同空间的 pending 全置为 cancelled（含本条），
		// 所以这里必须再写成 approved，否则记录最终状态是"已取消"。
		_, e := tx.Exec(ctx, `
			UPDATE space_transfer SET status = 'approved', decided_at = now(), decided_by = $3
			 WHERE id = $1 AND tenant_id = $2`, requestID, tenantID, ownerID)
		return e
	})
	switch {
	case expired:
		return TransferRequest{}, ErrTransferExpired
	case stale:
		return TransferRequest{}, ErrTransferStale
	}
	if err != nil {
		return TransferRequest{}, err
	}
	return s.getTransfer(ctx, tenantID, requestID)
}

// CancelTransfer 撤销一条待确认请求：发起人可以撤，管理员也可以撤。
func (s *Store) CancelTransfer(ctx context.Context, tenantID, requestID, actorID string, isAdmin bool) error {
	return db.WithTenant(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		var initiator, status string
		if err := tx.QueryRow(ctx, `
			SELECT initiated_by::text, status FROM space_transfer
			 WHERE id = $1 AND tenant_id = $2 FOR UPDATE`, requestID, tenantID).
			Scan(&initiator, &status); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrTransferNotFound
			}
			return err
		}
		if status != "pending" {
			return ErrTransferNotFound
		}
		if !isAdmin && initiator != actorID {
			return ErrTransferNotFound
		}
		_, err := tx.Exec(ctx, `
			UPDATE space_transfer SET status = 'cancelled', decided_at = now(), decided_by = $3
			 WHERE id = $1 AND tenant_id = $2`, requestID, tenantID, actorID)
		return err
	})
}

// PendingForOwner 返回"等我确认"的请求。
//
// 顺带把已过期的标掉：界面上的"剩 0 天"没有任何意义，而且会让用户以为还能点。
func (s *Store) PendingForOwner(ctx context.Context, tenantID, ownerID string) ([]TransferRequest, error) {
	out := []TransferRequest{}
	err := db.WithTenant(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `
			UPDATE space_transfer SET status = 'expired', decided_at = now()
			 WHERE tenant_id = $1 AND from_user_id = $2 AND status = 'pending' AND expires_at < now()`,
			tenantID, ownerID); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `
			SELECT t.id::text, t.space_id::text, s.name, t.from_user_id::text,
			       COALESCE(fu.display_name, ''), t.to_user_id::text, COALESCE(tu.display_name, ''),
			       t.initiated_by::text, COALESCE(iu.display_name, ''), t.mode, t.status,
			       t.reason, t.created_at, t.expires_at
			  FROM space_transfer t
			  JOIN space s ON s.id = t.space_id AND s.deleted_at IS NULL
			  LEFT JOIN app_user fu ON fu.id = t.from_user_id
			  LEFT JOIN app_user tu ON tu.id = t.to_user_id
			  LEFT JOIN app_user iu ON iu.id = t.initiated_by
			 WHERE t.tenant_id = $1 AND t.from_user_id = $2 AND t.status = 'pending'
			 ORDER BY t.created_at DESC`, tenantID, ownerID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var r TransferRequest
			if err := rows.Scan(&r.ID, &r.SpaceID, &r.SpaceName, &r.FromUserID, &r.FromName,
				&r.ToUserID, &r.ToName, &r.InitiatedBy, &r.InitiatorName, &r.Mode, &r.Status,
				&r.Reason, &r.CreatedAt, &r.ExpiresAt); err != nil {
				return err
			}
			out = append(out, r)
		}
		return rows.Err()
	})
	return out, err
}

// ListSpaceOverview 管理台空间台账：全租户，只元数据。
func (s *Store) ListSpaceOverview(ctx context.Context, tenantID string) ([]SpaceOverview, error) {
	out := []SpaceOverview{}
	err := db.WithTenant(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT s.id::text, s.name, s.kind, s.owner_id::text,
			       COALESCE(u.display_name, ''), COALESCE(u.status, ''),
			       s.classification, s.used_bytes, s.quota_bytes, s.created_at,
			       (SELECT count(*) FROM ace a
			         WHERE a.tenant_id = s.tenant_id AND a.object_type = 'space' AND a.object_id = s.id),
			       NOT EXISTS (
			         SELECT 1 FROM ace a
			          WHERE a.tenant_id = s.tenant_id AND a.object_type = 'space' AND a.object_id = s.id
			            AND NOT (a.subject_type = 'user' AND a.subject_id = s.owner_id)
			       ),
			       (SELECT max(n.updated_at) FROM node n
			         WHERE n.tenant_id = s.tenant_id AND n.space_id = s.id AND n.deleted_at IS NULL),
			       COALESCE(pt.id::text, ''), COALESCE(ptu.display_name, ''),
			       COALESCE(to_char(pt.expires_at, 'YYYY-MM-DD"T"HH24:MI:SSOF'), '')
			  FROM space s
			  LEFT JOIN app_user u ON u.id = s.owner_id
			  LEFT JOIN space_transfer pt ON pt.space_id = s.id AND pt.status = 'pending'
			  LEFT JOIN app_user ptu ON ptu.id = pt.to_user_id
			 WHERE s.tenant_id = $1 AND s.deleted_at IS NULL
			 ORDER BY s.created_at DESC`, tenantID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var o SpaceOverview
			if err := rows.Scan(&o.ID, &o.Name, &o.Kind, &o.OwnerID, &o.OwnerName, &o.OwnerStatus,
				&o.Classification, &o.UsedBytes, &o.QuotaBytes, &o.CreatedAt,
				&o.Granted, &o.OnlyOwner, &o.LastActivity,
				&o.PendingID, &o.PendingTo, &o.PendingUntil); err != nil {
				return err
			}
			out = append(out, o)
		}
		return rows.Err()
	})
	return out, err
}

// ---------------- 内部 ----------------

// checkTarget 校验接收人可用性与密级。必须在事务内、且空间行已加锁时调用。
func checkTarget(ctx context.Context, tx pgx.Tx, tenantID, spaceID string, spaceClass int, toUserID string) error {
	var status string
	var classification int
	var expires, deleted *time.Time
	err := tx.QueryRow(ctx, `
		SELECT status, classification, expires_at, deleted_at
		  FROM app_user WHERE id = $1 AND tenant_id = $2`, toUserID, tenantID).
		Scan(&status, &classification, &expires, &deleted)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrTargetUnavailable
	}
	if err != nil {
		return err
	}
	if deleted != nil || status != "active" || (expires != nil && expires.Before(time.Now())) {
		return ErrTargetUnavailable
	}
	// 密级不够就是"换个人也打不开"，不如当场拒绝，别制造新的孤儿
	if classification < spaceClass {
		return ErrTargetClearance
	}
	var deny int64
	if err := tx.QueryRow(ctx, `
		SELECT COALESCE(sum(deny_bits), 0)::bigint FROM ace
		 WHERE tenant_id = $1 AND object_type = 'space' AND object_id = $2
		   AND subject_type = 'user' AND subject_id = $3`,
		tenantID, spaceID, toUserID).Scan(&deny); err != nil {
		return err
	}
	if deny != 0 {
		return ErrTargetDenied
	}
	return nil
}

// transferSpaceTx 是移交的唯一写入口，调用方必须已经在事务里锁过空间行。
func transferSpaceTx(ctx context.Context, tx pgx.Tx, tenantID, spaceID, fromUserID, toUserID, initiatorID string) error {
	var ownerID string
	var cls int
	if err := tx.QueryRow(ctx, `
		SELECT owner_id::text, classification FROM space
		 WHERE id = $1 AND tenant_id = $2 AND deleted_at IS NULL
		 FOR UPDATE`, spaceID, tenantID).Scan(&ownerID, &cls); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrSpaceNotFound
		}
		return err
	}
	if ownerID != fromUserID {
		return ErrTransferStale
	}
	if toUserID == ownerID {
		return ErrSameOwner
	}
	if err := checkTarget(ctx, tx, tenantID, spaceID, cls, toUserID); err != nil {
		return err
	}

	// 同一空间不允许有两条在途请求：这次移交生效后，其余请求全部作废
	if _, err := tx.Exec(ctx, `
		UPDATE space_transfer SET status = 'cancelled', decided_at = now(), decided_by = $3
		 WHERE tenant_id = $1 AND space_id = $2 AND status = 'pending'`,
		tenantID, spaceID, initiatorID); err != nil {
		return err
	}

	if _, err := tx.Exec(ctx, `
		UPDATE space SET owner_id = $3 WHERE id = $1 AND tenant_id = $2`,
		spaceID, tenantID, toUserID); err != nil {
		return err
	}
	// 只改"属于原所有者"的文件：空间里别人名下的文件不该跟着换主人
	if _, err := tx.Exec(ctx, `
		UPDATE node SET owner_id = $3
		 WHERE tenant_id = $1 AND space_id = $2 AND owner_id = $4`,
		tenantID, spaceID, toUserID, fromUserID); err != nil {
		return err
	}

	// 目标若已有条目，先删掉（前面已确认它没有 deny 位），避免撞唯一索引
	if _, err := tx.Exec(ctx, `
		DELETE FROM ace
		 WHERE tenant_id = $1 AND object_type = 'space' AND object_id = $2
		   AND subject_type = 'user' AND subject_id = $3`,
		tenantID, spaceID, toUserID); err != nil {
		return err
	}
	ct, err := tx.Exec(ctx, `
		UPDATE ace
		   SET subject_id = $3, allow_bits = $4, deny_bits = 0,
		       preset = 'owner', expires_at = NULL, granted_by = $5, updated_at = now()
		 WHERE tenant_id = $1 AND object_type = 'space' AND object_id = $2
		   AND subject_type = 'user' AND subject_id = $6`,
		tenantID, spaceID, toUserID, int64(ownerBits), initiatorID, fromUserID)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		// 历史数据里可能只有 space.owner_id 而没有对应 ACE；补一条，
		// 否则新所有者"是所有者却进不去"。
		if _, err := tx.Exec(ctx, `
			INSERT INTO ace (id, tenant_id, object_type, object_id, subject_type, subject_id,
			                 allow_bits, deny_bits, preset, granted_by)
			VALUES (gen_random_uuid(), $1, 'space', $2, 'user', $3, $4, 0, 'owner', $5)
			ON CONFLICT DO NOTHING`,
			tenantID, spaceID, toUserID, int64(ownerBits), initiatorID); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) getTransfer(ctx context.Context, tenantID, id string) (TransferRequest, error) {
	var r TransferRequest
	err := db.WithTenant(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `
			SELECT t.id::text, t.space_id::text, COALESCE(s.name, ''),
			       t.from_user_id::text, COALESCE(fu.display_name, ''),
			       t.to_user_id::text, COALESCE(tu.display_name, ''),
			       t.initiated_by::text, COALESCE(iu.display_name, ''),
			       t.mode, t.status, t.reason, t.created_at, t.expires_at, t.decided_at
			  FROM space_transfer t
			  LEFT JOIN space s ON s.id = t.space_id
			  LEFT JOIN app_user fu ON fu.id = t.from_user_id
			  LEFT JOIN app_user tu ON tu.id = t.to_user_id
			  LEFT JOIN app_user iu ON iu.id = t.initiated_by
			 WHERE t.id = $1 AND t.tenant_id = $2`, id, tenantID).
			Scan(&r.ID, &r.SpaceID, &r.SpaceName, &r.FromUserID, &r.FromName,
				&r.ToUserID, &r.ToName, &r.InitiatedBy, &r.InitiatorName,
				&r.Mode, &r.Status, &r.Reason, &r.CreatedAt, &r.ExpiresAt, &r.DecidedAt)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrTransferNotFound
		}
		return err
	})
	return r, err
}

// ExpireStaleTransfers 供定时任务调用：把过期请求标掉，避免台账一直显示"待确认"。
func (s *Store) ExpireStaleTransfers(ctx context.Context, tenantID string) (int64, error) {
	var n int64
	err := db.WithTenant(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		ct, err := tx.Exec(ctx, `
			UPDATE space_transfer SET status = 'expired', decided_at = now()
			 WHERE tenant_id = $1 AND status = 'pending' AND expires_at < now()`, tenantID)
		if err != nil {
			return err
		}
		n = ct.RowsAffected()
		return nil
	})
	return n, err
}

// trimReason 限制理由长度：审计详情会被检索，超长文本没有价值。
func trimReason(s string) string {
	s = strings.TrimSpace(s)
	if len([]rune(s)) > 200 {
		return string([]rune(s)[:200])
	}
	return s
}
