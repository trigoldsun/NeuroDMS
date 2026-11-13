package httpapi

// 登录后的个人工作台。
//
// 设计取舍：一个聚合接口，而不是让前端并发打五六个接口。
//   - 工作台是登录后的第一屏，首屏请求数直接影响"打开有多快"；
//   - 待办条数与审批页必须一致，各写一套 SQL 迟早出现"首页说有 3 条、点进去 0 条"，
//     所以待办数字直接复用审批/移交的同一份查询。
//
// 权限：这里返回的每一条都经过与正常接口相同的判定（空间走 visibleSpaces，
// 最近文件逐条 check Display），不因为"只是首页"就放宽。首页泄露文件名同样是泄露。

import (
	"context"
	"errors"
	"net/http"
	"sort"
	"strconv"
	"time"

	"docvault/internal/auth"
	"docvault/internal/authz"
	"docvault/internal/db"

	"github.com/jackc/pgx/v5"
)

func (a *API) registerWorkspace(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/workspace", a.requireAuth(a.handleWorkspace))
}

type recentTouched struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Kind      string    `json:"kind"`
	SpaceID   string    `json:"spaceId"`
	SpaceName string    `json:"spaceName"`
	Action    string    `json:"action"`
	At        time.Time `json:"at"`
}

func (a *API) handleWorkspace(w http.ResponseWriter, r *http.Request) {
	c, _ := claimsFrom(r.Context())
	ctx := r.Context()

	spaces, err := a.visibleSpaces(ctx, c)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "读取工作台失败")
		return
	}
	roles, err := a.roleCodes(ctx, c)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "读取角色失败")
		return
	}
	recent, err := a.recentTouched(ctx, c)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "读取最近访问失败")
		return
	}

	transfers := []map[string]any{}
	if a.Content != nil {
		list, terr := a.Content.PendingForOwner(ctx, c.TenantID, c.Subject)
		if terr != nil {
			writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "读取待确认移交失败")
			return
		}
		for _, t := range list {
			transfers = append(transfers, map[string]any{
				"kind": "transfer", "id": t.ID, "title": t.SpaceName,
				"detail": t.InitiatorName + " 请求移交给他自己",
				"url":    "/files/" + t.SpaceID, "expiresAt": t.ExpiresAt,
			})
		}
	}

	shareTodos := []map[string]any{}
	if shares, serr := a.pendingShareApprovals(ctx, c); serr == nil {
		for _, s := range shares {
			shareTodos = append(shareTodos, map[string]any{
				"kind": "share", "id": s["shareId"], "title": s["name"],
				"detail": "外发链接等待审批 · 发起人 " + toStr(s["creator"]),
				"url":    "/approvals",
			})
		}
	}

	var activeShares int
	err = db.WithTenant(ctx, a.Pool, c.TenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
			SELECT count(*) FROM share
			 WHERE tenant_id = $1 AND creator_id = $2 AND revoked_at IS NULL
			   AND (expires_at IS NULL OR expires_at > now())`, c.TenantID, c.Subject).Scan(&activeShares)
	})
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "读取外发统计失败")
		return
	}

	// 空间卡片：最近有动静的排前面；从没内容的按创建时间兜底
	sorted := make([]spaceItem, len(spaces))
	copy(sorted, spaces)
	sort.SliceStable(sorted, func(i, j int) bool {
		a1, a2 := sorted[i].LastActivity, sorted[j].LastActivity
		if a1 == nil && a2 == nil {
			return sorted[i].CreatedAt.After(sorted[j].CreatedAt)
		}
		if a1 == nil {
			return false
		}
		if a2 == nil {
			return true
		}
		return a1.After(*a2)
	})
	// 不截断：侧栏也要用这份列表，截了就会出现"侧栏里少一个空间"。
	// 首页只取前 6 张卡片，是前端的事。

	owned, used := 0, int64(0)
	for _, s := range spaces {
		if s.OwnerID == c.Subject {
			owned++
		}
		used += s.UsedBytes
	}

	todos := append(transfers, shareTodos...)

	out := map[string]any{
		"spaces": sorted,
		"recent": recent,
		"todos":  todos,
		"roles":  roles,
		"stats": map[string]any{
			"ownedSpaces":           owned,
			"sharedSpaces":          len(spaces) - owned,
			"totalSpaces":           len(spaces),
			"storageUsedBytes":      used,
			"pendingTransfers":      len(transfers),
			"pendingShareApprovals": len(shareTodos),
			"activeShares":          activeShares,
			"recentCount":           len(recent),
		},
	}
	if hasRole(roles, "sysadmin") {
		out["sysadmin"] = a.workspaceSysadmin(ctx, c)
	}
	if hasRole(roles, "secadmin") {
		out["secadmin"] = a.workspaceSecadmin(ctx, c)
	}
	if hasRole(roles, "auditor") {
		out["auditor"] = a.workspaceAuditor(ctx, c)
	}
	writeOK(w, r, out)
}

// recentTouched 从审计日志里还原"我最近动过哪些文件"。
//
// 为什么不新建一张"最近访问"表：审计已经记了每一次预览/下载/上传，且带时间与动作，
// 再维护一张表只会多一个会写歪的副本。代价是查日志，所以限定 60 天 + 去重后取 8 条。
//
// 权限复核不可省：文件名本身也是信息，授权被收回后不该继续出现在首页。
func (a *API) recentTouched(ctx context.Context, c auth.Claims) ([]recentTouched, error) {
	var hits []recentTouched
	err := db.WithTenant(ctx, a.Pool, c.TenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			WITH touched AS (
				SELECT object_id, max(created_at) AS at,
				       (array_agg(action ORDER BY created_at DESC))[1] AS action
				  FROM audit_event
				 WHERE tenant_id = $1 AND actor_id = $2
				   AND action IN ('node.preview', 'node.download', 'node.upload',
				                  'node.rename', 'node.version.restore', 'node.edit')
				   AND created_at > now() - interval '60 days'
				 GROUP BY object_id
				 ORDER BY at DESC
				 LIMIT 24
			)
			SELECT t.object_id::text, n.name, n.kind, n.space_id::text, s.name, t.action, t.at
			  FROM touched t
			  JOIN node n ON n.id = t.object_id AND n.deleted_at IS NULL
			  JOIN space s ON s.id = n.space_id AND s.deleted_at IS NULL
			 ORDER BY t.at DESC
			 LIMIT 16`, c.TenantID, c.Subject)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var h recentTouched
			if err := rows.Scan(&h.ID, &h.Name, &h.Kind, &h.SpaceID, &h.SpaceName, &h.Action, &h.At); err != nil {
				return err
			}
			hits = append(hits, h)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}

	out := make([]recentTouched, 0, 8)
	for _, h := range hits {
		if len(out) >= 8 {
			break
		}
		d, derr := a.check(ctx, c, h.SpaceID, h.ID, authz.Display)
		if derr != nil || !d.allowed {
			continue
		}
		out = append(out, h)
	}
	return out, nil
}

func (a *API) roleCodes(ctx context.Context, c auth.Claims) ([]string, error) {
	out := []string{}
	err := db.WithTenant(ctx, a.Pool, c.TenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT r.code FROM user_role ur
			  JOIN role r ON r.id = ur.role_id
			 WHERE ur.tenant_id = $1 AND ur.user_id = $2
			 ORDER BY r.code`, c.TenantID, c.Subject)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var code string
			if err := rows.Scan(&code); err != nil {
				return err
			}
			out = append(out, code)
		}
		return rows.Err()
	})
	return out, err
}

func hasRole(roles []string, code string) bool {
	for _, r := range roles {
		if r == code {
			return true
		}
	}
	return false
}

// workspaceSysadmin 管理员的首页口径：资产有没有人管，比"总共有多少文件"更重要。
func (a *API) workspaceSysadmin(ctx context.Context, c auth.Claims) map[string]any {
	out := map[string]any{}
	err := db.WithTenant(ctx, a.Pool, c.TenantID, func(tx pgx.Tx) error {
		var users, spaces, files int
		var bytes int64
		if err := tx.QueryRow(ctx, `
			SELECT
			  (SELECT count(*) FROM app_user WHERE deleted_at IS NULL AND status = 'active'),
			  (SELECT count(*) FROM space WHERE deleted_at IS NULL),
			  (SELECT count(*) FROM node WHERE deleted_at IS NULL AND kind = 'file'),
			  (SELECT COALESCE(sum(size_bytes),0) FROM node WHERE deleted_at IS NULL AND kind = 'file')`,
		).Scan(&users, &spaces, &files, &bytes); err != nil {
			return err
		}
		var onlyOwner, orphan int
		if err := tx.QueryRow(ctx, `
			SELECT count(*) FILTER (WHERE NOT other_ace),
			       count(*) FILTER (WHERE NOT other_ace AND (owner_status <> 'active' OR owner_deleted))
			  FROM (
			    SELECT s.id,
			           COALESCE(u.status, '') AS owner_status,
			           u.deleted_at IS NOT NULL AS owner_deleted,
			           EXISTS (
			             SELECT 1 FROM ace a
			              WHERE a.tenant_id = s.tenant_id AND a.object_type = 'space' AND a.object_id = s.id
			                AND NOT (a.subject_type = 'user' AND a.subject_id = s.owner_id)
			           ) AS other_ace
			      FROM space s
			      LEFT JOIN app_user u ON u.id = s.owner_id
			     WHERE s.deleted_at IS NULL
			  ) t`).Scan(&onlyOwner, &orphan); err != nil {
			return err
		}
		out["users"] = users
		out["spaces"] = spaces
		out["files"] = files
		out["usedBytes"] = bytes
		out["onlyOwnerSpaces"] = onlyOwner
		out["orphanSpaces"] = orphan
		return nil
	})
	if err != nil {
		a.logErr("读取管理首页统计失败", "err", err)
	}
	return out
}

// workspaceSecadmin 安全管理员的首页口径：密级分布与待审降密。
func (a *API) workspaceSecadmin(ctx context.Context, c auth.Claims) map[string]any {
	out := map[string]any{}
	err := db.WithTenant(ctx, a.Pool, c.TenantID, func(tx pgx.Tx) error {
		var pending int
		if err := tx.QueryRow(ctx, `
			SELECT count(*) FROM classification_change WHERE tenant_id = $1 AND status = 'pending'`,
			c.TenantID).Scan(&pending); err != nil {
			return err
		}
		dist := map[string]int{}
		rows, err := tx.Query(ctx, `
			SELECT classification, count(*) FROM node
			 WHERE tenant_id = $1 AND deleted_at IS NULL AND kind = 'file'
			 GROUP BY classification ORDER BY classification`, c.TenantID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var lv, n int
			if err := rows.Scan(&lv, &n); err != nil {
				return err
			}
			dist[strconv.Itoa(lv)] = n
		}
		out["pendingDowngrades"] = pending
		out["distribution"] = dist
		return rows.Err()
	})
	if err != nil {
		a.logErr("读取安全首页统计失败", "err", err)
	}
	return out
}

// workspaceAuditor 审计员的首页口径：链是否连续、最近有没有被拒的访问。
func (a *API) workspaceAuditor(ctx context.Context, c auth.Claims) map[string]any {
	out := map[string]any{}
	err := db.WithTenant(ctx, a.Pool, c.TenantID, func(tx pgx.Tx) error {
		var events, denied int
		if err := tx.QueryRow(ctx, `
			SELECT count(*) FILTER (WHERE created_at > now() - interval '24 hours'),
			       count(*) FILTER (WHERE created_at > now() - interval '24 hours' AND result = 'denied')
			  FROM audit_event WHERE tenant_id = $1`, c.TenantID).Scan(&events, &denied); err != nil {
			return err
		}
		// 锚点在 audit_anchor（audit_daily_root 是老表，实际写入走 anchor）
		var day *time.Time
		var count int
		if err := tx.QueryRow(ctx, `
			SELECT day::timestamptz, event_count FROM audit_anchor
			 WHERE tenant_id = $1 ORDER BY day DESC LIMIT 1`, c.TenantID).Scan(&day, &count); err != nil {
			if !errors.Is(err, pgx.ErrNoRows) {
				return err
			}
		}
		out["events24h"] = events
		out["denied24h"] = denied
		if day != nil {
			out["lastAnchorDay"] = day.Format("2006-01-02")
			out["lastAnchorCount"] = count
		}
		return nil
	})
	if err != nil {
		a.logErr("读取审计首页统计失败", "err", err)
	}
	return out
}

func toStr(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}
