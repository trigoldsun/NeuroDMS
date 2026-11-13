package httpapi

import (
	"context"
	"net/http"
	"time"

	"docvault/internal/auth"
	"docvault/internal/authz"
	"docvault/internal/db"

	"github.com/jackc/pgx/v5"
)

// registerDirectory 注册"我的空间"与"可选用户"两个只读列表接口。
// 前端需要它们才能完成"选空间 → 看文件"和"选人 → 授权"两步。
func (a *API) registerDirectory(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/spaces", a.requireAuth(a.handleListSpaces))
	mux.HandleFunc("GET /v1/users", a.requireAuth(a.handleListUsers))
}

type spaceItem struct {
	ID             string     `json:"id"`
	Kind           string     `json:"kind"`
	Name           string     `json:"name"`
	OwnerID        string     `json:"ownerId"`
	OwnerName      string     `json:"ownerName"`
	UsedBytes      int64      `json:"usedBytes"`
	QuotaBytes     *int64     `json:"quotaBytes"`
	Classification int        `json:"classification"`
	Preset         string     `json:"defaultPreset"`
	CreatedAt      time.Time  `json:"createdAt"`
	LastActivity   *time.Time `json:"lastActivity,omitempty"`
}

// handleListSpaces 返回"当前用户可见的空间"。
func (a *API) handleListSpaces(w http.ResponseWriter, r *http.Request) {
	c, _ := claimsFrom(r.Context())
	visible, err := a.visibleSpaces(r.Context(), c)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "读取空间失败")
		return
	}
	writeOK(w, r, map[string]any{"items": visible, "count": len(visible)})
}

// visibleSpaces 返回当前用户可见的空间。
//
// 可见 = 自己是所有者，或自己（含所属部门/角色/组）在某空间根上有任何 ACE。
// 先取**候选集**（SQL 只做"可能存在"的粗筛，刻意忽略 deny、过期与密级），
// 再交给判定内核逐条确认：否则会出现"列表里看得到、点进去 403"，
// 或者反过来的"该看到却不在列表里"——两套逻辑漂移是这类页面的老问题。
//
// 抽成方法是因为工作台也要用同一份数据；复制一份 SQL 必然会在某次改动后分叉。
func (a *API) visibleSpaces(ctx context.Context, c auth.Claims) ([]spaceItem, error) {
	var items []spaceItem
	err := db.WithTenant(ctx, a.Pool, c.TenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			WITH me AS (
				SELECT $1::uuid AS uid
			), my_depts AS (
				SELECT d.id FROM dept d
				 WHERE d.path @> (SELECT d2.path FROM dept d2
				                   JOIN app_user u ON u.dept_id = d2.id
				                  WHERE u.id = $1)
				   AND d.deleted_at IS NULL
			), my_roles AS (
				SELECT role_id FROM user_role WHERE user_id = $1
			), my_groups AS (
				SELECT group_id FROM group_member WHERE user_id = $1
			)
			SELECT s.id::text, s.kind, s.name, s.owner_id::text,
			       COALESCE(u.display_name, ''), s.used_bytes, s.quota_bytes,
			       s.classification, s.default_preset, s.created_at,
			       (SELECT max(n.updated_at) FROM node n
			         WHERE n.tenant_id = s.tenant_id AND n.space_id = s.id AND n.deleted_at IS NULL)
			  FROM space s
			  LEFT JOIN app_user u ON u.id = s.owner_id
			 WHERE s.deleted_at IS NULL
			   AND (
			     s.owner_id = $1
			     OR EXISTS (
			       SELECT 1 FROM ace x
			        WHERE x.object_type = 'space' AND x.object_id = s.id
			          AND (
			            (x.subject_type = 'user'  AND x.subject_id = $1)
			            OR (x.subject_type = 'dept'  AND x.subject_id IN (SELECT id FROM my_depts))
			            OR (x.subject_type = 'role'  AND x.subject_id IN (SELECT role_id FROM my_roles))
			            OR (x.subject_type = 'group' AND x.subject_id IN (SELECT group_id FROM my_groups))
			          )
			     )
			   )
			 ORDER BY s.created_at DESC`, c.Subject)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var s spaceItem
			if err := rows.Scan(&s.ID, &s.Kind, &s.Name, &s.OwnerID, &s.OwnerName,
				&s.UsedBytes, &s.QuotaBytes, &s.Classification, &s.Preset, &s.CreatedAt,
				&s.LastActivity); err != nil {
				return err
			}
			items = append(items, s)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}

	visible := make([]spaceItem, 0, len(items))
	for _, it := range items {
		d, derr := a.check(ctx, c, it.ID, it.ID, authz.Display)
		if derr != nil {
			return nil, derr
		}
		if d.allowed {
			visible = append(visible, it)
		}
	}
	return visible, nil
}

// handleListUsers 返回租户内可选用户，用于授权时选人。
//
// 只暴露 id / username / displayName 三项：授权选择器不需要邮箱与手机号，
// 少暴露一个字段就少一处泄漏面。
func (a *API) handleListUsers(w http.ResponseWriter, r *http.Request) {
	c, _ := claimsFrom(r.Context())

	type userItem struct {
		ID          string `json:"id"`
		Username    string `json:"username"`
		DisplayName string `json:"displayName"`
	}
	var items []userItem

	err := db.WithTenant(r.Context(), a.Pool, c.TenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(r.Context(), `
			SELECT id::text, username, display_name
			  FROM app_user
			 WHERE deleted_at IS NULL AND status <> 'deleted'
			 ORDER BY lower(username) LIMIT 200`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var u userItem
			if err := rows.Scan(&u.ID, &u.Username, &u.DisplayName); err != nil {
				return err
			}
			items = append(items, u)
		}
		return rows.Err()
	})
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "读取用户失败")
		return
	}
	if items == nil {
		items = []userItem{}
	}
	writeOK(w, r, map[string]any{"items": items, "count": len(items)})
}
