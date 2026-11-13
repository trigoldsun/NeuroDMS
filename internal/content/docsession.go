package content

// 在线编辑会话。
//
// 存在的原因：回退与"正在编辑的人点保存"是天然冲突的——对方一保存，
// 回退结果就被覆盖，而用户只会看到"回退没生效"，无法解释。
//
// 这里不依赖 node.locked：那个字段在 schema 里存在，但全仓没有任何地方写它，
// 属于死字段。用一张带心跳的会话表，才能真实判断"现在有没有人在编辑"。

import (
	"context"
	"time"

	"docvault/internal/db"

	"github.com/jackc/pgx/v5"
)

// DocSession 是一次在线编辑会话。
type DocSession struct {
	NodeID     string
	SessionKey string
	UserID     string
	StartedAt  time.Time
	LastSeenAt time.Time
}

// TouchDocSession 登记或续期一个编辑会话。
//
// sessionKey 由 OnlyOffice 的文档 key 充当（含打开时间戳），每次打开都不同，
// 所以"回退后旧会话再续期"不会发生；即便发生，也会因为 invalidated_at 被清空
// 而重新生效，属于预期行为（用户重新打开了文档）。
func (s *Store) TouchDocSession(ctx context.Context, tenantID, nodeID, sessionKey, userID string) error {
	if sessionKey == "" {
		return ErrBadInput
	}
	return db.WithTenant(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			INSERT INTO doc_session (tenant_id, node_id, session_key, user_id, last_seen_at)
			VALUES ($1, $2, $3, nullif($4,'')::uuid, now())
			ON CONFLICT (node_id, session_key)
			DO UPDATE SET last_seen_at = now(),
			              invalidated_at = NULL,
			              user_id = COALESCE(EXCLUDED.user_id, doc_session.user_id)`,
			tenantID, nodeID, sessionKey, userID)
		return err
	})
}

// HasActiveDocSession 判断某文件是否存在活跃编辑会话。
//
// 过期由 last_seen_at 惰性判定，不依赖后台清理任务：
// 任务一旦停摆，不能让回退被永久拒绝。阈值与 RestoreVersion 内部保持一致。
func (s *Store) HasActiveDocSession(ctx context.Context, tenantID, nodeID string) (bool, error) {
	var active bool
	err := db.WithTenant(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
			SELECT EXISTS (
				SELECT 1 FROM doc_session
				 WHERE node_id = $1
				   AND invalidated_at IS NULL
				   AND last_seen_at > now() - interval '10 minutes')`, nodeID).Scan(&active)
	})
	return active, err
}

// InvalidateDocSessions 让某文件的全部编辑会话立即失效。
func (s *Store) InvalidateDocSessions(ctx context.Context, tenantID, nodeID string) error {
	return db.WithTenant(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			UPDATE doc_session SET invalidated_at = now()
			 WHERE node_id = $1 AND invalidated_at IS NULL`, nodeID)
		return err
	})
}

// ListDocSessions 列出某文件当前的活跃会话（用于管理界面提示）。
func (s *Store) ListDocSessions(ctx context.Context, tenantID, nodeID string) ([]DocSession, error) {
	var out []DocSession
	err := db.WithTenant(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT node_id::text, session_key, COALESCE(user_id::text,''), started_at, last_seen_at
			  FROM doc_session
			 WHERE node_id = $1
			   AND invalidated_at IS NULL
			   AND last_seen_at > now() - interval '10 minutes'
			 ORDER BY last_seen_at DESC`, nodeID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var d DocSession
			if err := rows.Scan(&d.NodeID, &d.SessionKey, &d.UserID, &d.StartedAt, &d.LastSeenAt); err != nil {
				return err
			}
			out = append(out, d)
		}
		return rows.Err()
	})
	return out, err
}
