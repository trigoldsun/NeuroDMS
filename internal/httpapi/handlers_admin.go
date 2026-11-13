package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"docvault/internal/audit"
	"docvault/internal/db"
	"docvault/internal/rbac"

	"github.com/jackc/pgx/v5"
)

// registerAdmin 注册管理面路由。
//
// 与业务面（/v1/*）分离的意义：管理面的每个端点都必须显式声明所需角色，
// 且**全部**写审计——包括被拒绝的尝试。管理面是内部提权的首选目标，
// "谁在什么时候试图进管理面但被拦了"本身就是高价值的安全信号。
func (a *API) registerAdmin(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/admin/roles", a.requireRole(rbac.SysAdmin, rbac.SecAdmin, rbac.Auditor)(a.handleAdminRoles))
	mux.HandleFunc("GET /v1/admin/users/{id}/roles", a.requireRole(rbac.SysAdmin)(a.handleUserRoles))
	mux.HandleFunc("POST /v1/admin/users/{id}/roles", a.requireRole(rbac.SysAdmin)(a.handleGrantRole))
	mux.HandleFunc("DELETE /v1/admin/users/{id}/roles/{code}", a.requireRole(rbac.SysAdmin)(a.handleRevokeRole))
	mux.HandleFunc("GET /v1/admin/summary", a.requireRole(rbac.SysAdmin)(a.handleAdminSummary))
	mux.HandleFunc("POST /v1/admin/users/{id}/expiry", a.requireRole(rbac.SysAdmin)(a.handleSetUserExpiry))
	mux.HandleFunc("DELETE /v1/admin/users/{id}", a.requireRole(rbac.SysAdmin)(a.handleDeleteUser))
	// 审计数据只给审计管理员：系统管理员能改配置，让他同时能读审计就等于取消独立性。
	mux.HandleFunc("GET /v1/admin/audit/events", a.requireRole(rbac.Auditor)(a.handleAuditEvents))
	mux.HandleFunc("GET /v1/admin/audit/verify", a.requireRole(rbac.Auditor)(a.handleAuditVerify))
}

// requireRole 要求调用者具备任一指定角色。
//
// 三层判定（顺序不可换）：
//  1. 有角色吗（没有 → 403，且审计"越权尝试"）
//  2. 角色组合合法吗（三权分立冲突 → 403，且明确报冲突，方便管理员自查）
//  3. 放行
//
// 返回 403 而不是 404：管理面路径是公开已知的（文档与管理工具在用），
// 用 404 伪装既挡不住探测，又会让排障的人以为是路由配错。
func (a *API) requireRole(roles ...string) func(http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return a.requireAuth(func(w http.ResponseWriter, r *http.Request) {
			c, _ := claimsFrom(r.Context())

			var held []string
			err := db.WithTenant(r.Context(), a.Pool, c.TenantID, func(tx pgx.Tx) error {
				rs, e := rbac.RolesOf(r.Context(), tx, c.TenantID, c.Subject)
				held = rs
				return e
			})
			if err != nil {
				writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "读取角色失败")
				return
			}

			if v := rbac.SeparationViolation(held); v != "" {
				_ = a.emit(r, c.TenantID, AuditEntry{
					ActorID: c.Subject, Action: "admin.denied", Result: "denied",
					Detail: map[string]any{"reason": "separation_violation", "detail": v, "path": r.URL.Path},
				})
				writeErr(w, r, http.StatusForbidden, "SEPARATION_VIOLATION", "角色配置违反三权分立："+v)
				return
			}

			if !rbac.Contains(held, roles...) {
				_ = a.emit(r, c.TenantID, AuditEntry{
					ActorID: c.Subject, Action: "admin.denied", Result: "denied",
					Detail: map[string]any{"reason": "missing_role", "required": roles,
						"held": held, "path": r.URL.Path},
				})
				writeErr(w, r, http.StatusForbidden, "FORBIDDEN", "需要管理角色")
				return
			}
			next(w, r)
		})
	}
}

func (a *API) handleAdminRoles(w http.ResponseWriter, r *http.Request) {
	writeOK(w, r, map[string]any{"items": rbac.Describe()})
}

func (a *API) handleUserRoles(w http.ResponseWriter, r *http.Request) {
	c, _ := claimsFrom(r.Context())
	userID := r.PathValue("id")

	var roles []string
	err := db.WithTenant(r.Context(), a.Pool, c.TenantID, func(tx pgx.Tx) error {
		var exists bool
		if err := tx.QueryRow(r.Context(),
			`SELECT true FROM app_user WHERE id = $1 AND deleted_at IS NULL`, userID).Scan(&exists); err != nil {
			return err
		}
		rs, e := rbac.RolesOf(r.Context(), tx, c.TenantID, userID)
		roles = rs
		return e
	})
	if err != nil {
		writeErr(w, r, http.StatusNotFound, "NOT_FOUND", "用户不存在")
		return
	}
	writeOK(w, r, map[string]any{"userId": userID, "roles": roles})
}

// errSelfGrant 表示"给自己授予角色"（提权），需要整体回滚。
var errSelfGrant = errors.New("不能给自己授予角色")

func (a *API) handleGrantRole(w http.ResponseWriter, r *http.Request) {
	c, _ := claimsFrom(r.Context())
	userID := r.PathValue("id")

	var req struct {
		Code string `json:"code"`
	}
	if !decode(w, r, &req) {
		return
	}
	if !rbac.Known(req.Code) {
		writeErr(w, r, http.StatusBadRequest, "INVALID_ARGUMENT", "未知内置角色")
		return
	}
	var roles []string
	err := db.WithTenant(r.Context(), a.Pool, c.TenantID, func(tx pgx.Tx) error {
		// 先让 rbac 判角色组合（三权分立），再判自授：
		// 反过来会把"给自己加审计角色"报成笼统的自操作，掩盖真正的冲突原因。
		// 自授判定返回错误，整个事务回滚，授权不会生效。
		if err := rbac.Grant(r.Context(), tx, c.TenantID, userID, req.Code, c.Subject); err != nil {
			return err
		}
		if userID == c.Subject {
			return errSelfGrant
		}
		rs, e := rbac.RolesOf(r.Context(), tx, c.TenantID, userID)
		roles = rs
		return e
	})
	switch {
	case errors.Is(err, errSelfGrant):
		_ = a.emit(r, c.TenantID, AuditEntry{
			ActorID: c.Subject, Action: "admin.role.grant", ObjectID: userID, Result: "denied",
			Detail: map[string]any{"code": req.Code, "reason": "self_grant"},
		})
		writeErr(w, r, http.StatusBadRequest, "SELF_OPERATION", "不能给自己授予角色")
		return
	case errors.Is(err, rbac.ErrRoleConflict):
		_ = a.emit(r, c.TenantID, AuditEntry{
			ActorID: c.Subject, Action: "admin.role.grant", ObjectID: userID, Result: "denied",
			Detail: map[string]any{"code": req.Code, "reason": "separation"},
		})
		writeErr(w, r, http.StatusConflict, "SEPARATION_VIOLATION", err.Error())
		return
	case errors.Is(err, rbac.ErrUnknownRole):
		writeErr(w, r, http.StatusBadRequest, "INVALID_ARGUMENT", "未知内置角色")
		return
	case err != nil:
		writeErr(w, r, http.StatusNotFound, "NOT_FOUND", "用户不存在")
		return
	}

	if err := a.emit(r, c.TenantID, AuditEntry{
		ActorID: c.Subject, Action: "admin.role.grant", ObjectID: userID, Result: "ok",
		Detail: map[string]any{"code": req.Code, "roles": roles},
	}); err != nil {
		writeErr(w, r, http.StatusInternalServerError, "AUDIT_FAILED", "审计写入失败，操作已拒绝")
		return
	}
	writeOK(w, r, map[string]any{"userId": userID, "roles": roles})
}

func (a *API) handleRevokeRole(w http.ResponseWriter, r *http.Request) {
	c, _ := claimsFrom(r.Context())
	userID := r.PathValue("id")
	code := r.PathValue("code")

	var roles []string
	err := db.WithTenant(r.Context(), a.Pool, c.TenantID, func(tx pgx.Tx) error {
		if err := rbac.Revoke(r.Context(), tx, c.TenantID, userID, code); err != nil {
			return err
		}
		rs, e := rbac.RolesOf(r.Context(), tx, c.TenantID, userID)
		roles = rs
		return e
	})
	switch {
	case errors.Is(err, rbac.ErrLastAdmin):
		_ = a.emit(r, c.TenantID, AuditEntry{
			ActorID: c.Subject, Action: "admin.role.revoke", ObjectID: userID, Result: "denied",
			Detail: map[string]any{"code": code, "reason": "last_admin"},
		})
		writeErr(w, r, http.StatusConflict, "LAST_ADMIN", "不能移除最后一个系统管理员")
		return
	case errors.Is(err, rbac.ErrUnknownRole):
		writeErr(w, r, http.StatusBadRequest, "INVALID_ARGUMENT", "未知内置角色")
		return
	case err != nil:
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "撤销角色失败")
		return
	}

	if err := a.emit(r, c.TenantID, AuditEntry{
		ActorID: c.Subject, Action: "admin.role.revoke", ObjectID: userID, Result: "ok",
		Detail: map[string]any{"code": code, "roles": roles},
	}); err != nil {
		writeErr(w, r, http.StatusInternalServerError, "AUDIT_FAILED", "审计写入失败，操作已拒绝")
		return
	}
	writeOK(w, r, map[string]any{"userId": userID, "roles": roles})
}

// handleAdminSummary 返回租户级概览：租户基本盘、用户数、空间数、存储用量。
//
// 只要计数，不返回明细：概览页被高频刷新，返回明细会让一次误操作
// （比如折叠面板忘记分页）变成全表扫描。
func (a *API) handleAdminSummary(w http.ResponseWriter, r *http.Request) {
	c, _ := claimsFrom(r.Context())

	var (
		users, spaces, nodes, files int
		bytes                       int64
	)
	err := db.WithTenant(r.Context(), a.Pool, c.TenantID, func(tx pgx.Tx) error {
		if err := tx.QueryRow(r.Context(), `
			SELECT
			  (SELECT count(*) FROM app_user WHERE deleted_at IS NULL),
			  (SELECT count(*) FROM space WHERE deleted_at IS NULL),
			  (SELECT count(*) FROM node WHERE deleted_at IS NULL),
			  (SELECT count(*) FROM node WHERE deleted_at IS NULL AND kind = 'file'),
			  (SELECT COALESCE(sum(size_bytes),0) FROM node WHERE deleted_at IS NULL AND kind = 'file')`,
		).Scan(&users, &spaces, &nodes, &files, &bytes); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "读取概览失败")
		return
	}

	writeOK(w, r, map[string]any{
		"users": users, "spaces": spaces, "nodes": nodes, "files": files,
		"usedBytes": bytes, "generatedAt": time.Now().UTC().Format(time.RFC3339),
	})
}

// handleAuditEvents 审计查询（只读）。
func (a *API) handleAuditEvents(w http.ResponseWriter, r *http.Request) {
	c, _ := claimsFrom(r.Context())
	q := r.URL.Query()

	f := audit.QueryFilter{
		Action:  q.Get("action"),
		ActorID: q.Get("actorId"),
		Result:  q.Get("result"),
	}
	if v := q.Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			f.Limit = n
		}
	}
	if v := q.Get("offset"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			f.Offset = n
		}
	}
	if v := q.Get("from"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			f.From = &t
		}
	}
	if v := q.Get("to"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			f.To = &t
		}
	}

	rows, err := audit.Query(r.Context(), a.Pool, c.TenantID, f)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "查询审计失败")
		return
	}
	items := make([]map[string]any, 0, len(rows))
	for _, x := range rows {
		item := map[string]any{
			"seq": x.Seq, "actorId": x.ActorID, "actorType": x.ActorType,
			"action": x.Action, "objectId": x.ObjectID, "result": x.Result,
			"ip": x.IP, "requestId": x.RequestID,
			"createdAt": x.CreatedAt.UTC().Format(time.RFC3339),
		}
		if len(x.Detail) > 0 {
			var d map[string]any
			if json.Unmarshal(x.Detail, &d) == nil {
				item["detail"] = d
			}
		}
		items = append(items, item)
	}
	writeOK(w, r, map[string]any{"items": items, "count": len(items)})
}

// handleAuditVerify 校验哈希链完整性。
func (a *API) handleAuditVerify(w http.ResponseWriter, r *http.Request) {
	c, _ := claimsFrom(r.Context())
	n, err := audit.Verify(r.Context(), a.Pool, c.TenantID)
	if err != nil {
		writeOK(w, r, map[string]any{"ok": false, "checked": n, "error": err.Error()})
		return
	}
	writeOK(w, r, map[string]any{"ok": true, "checked": n})
}

// handleSetUserExpiry 设置账号有效期（外用户到期即失效）。
//
// 到期判定发生在登录时（auth.Service.Login 检查 expires_at），
// 已签发的会话由 status/epoch 吊销路径处理：
// 到期只是"不能再登录"，要让在线的立刻断开必须同时 suspended 或删号。
// 这里在到期时间早于当前时直接吊销一次，避免"设了过期但人还在用"。
func (a *API) handleSetUserExpiry(w http.ResponseWriter, r *http.Request) {
	c, _ := claimsFrom(r.Context())
	userID := r.PathValue("id")

	var req struct {
		ExpiresAt string `json:"expiresAt"` // RFC3339，空表示永不过期
	}
	if !decode(w, r, &req) {
		return
	}
	var expires *time.Time
	if req.ExpiresAt != "" {
		t, err := time.Parse(time.RFC3339, req.ExpiresAt)
		if err != nil {
			writeErr(w, r, http.StatusBadRequest, "INVALID_ARGUMENT", "expiresAt 需为 RFC3339 时间")
			return
		}
		expires = &t
	}

	err := db.WithTenant(r.Context(), a.Pool, c.TenantID, func(tx pgx.Tx) error {
		ct, e := tx.Exec(r.Context(), `
			UPDATE app_user SET expires_at = $2, updated_at = now()
			 WHERE id = $1 AND deleted_at IS NULL`, userID, expires)
		if e != nil {
			return e
		}
		if ct.RowsAffected() == 0 {
			return pgx.ErrNoRows
		}
		// 已过期 → 立刻吊销现有会话
		if expires != nil && expires.Before(time.Now()) {
			_, e = tx.Exec(r.Context(),
				`UPDATE app_user SET session_epoch = session_epoch + 1 WHERE id = $1`, userID)
		}
		return e
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeErr(w, r, http.StatusNotFound, "NOT_FOUND", "用户不存在")
			return
		}
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "设置有效期失败")
		return
	}

	_ = a.emit(r, c.TenantID, AuditEntry{
		ActorID: c.Subject, Action: "admin.user.expiry", ObjectID: userID, Result: "ok",
		Detail: map[string]any{"expiresAt": req.ExpiresAt},
	})
	writeOK(w, r, map[string]any{"userId": userID, "expiresAt": req.ExpiresAt})
}

// handleDeleteUser 删除账号（软删 + 立即吊销会话）。
//
// AC-64 的关键点：删除必须让**已签发的令牌立刻失效**。
// 只置 deleted_at 而不动 session_epoch，用户手上的 refresh token 还能换新，
// 表现为"账号已删但人还能用"。
//
// 因此这里刻意复用 auth.Service.SetUserStatus（它同时做 epoch++、吊销会话、
// 清本实例的吊销缓存），而不是自己写一条 UPDATE——自己写最容易漏掉"清缓存"，
// 而那一漏就等价于"删了还能用 10 秒"。
func (a *API) handleDeleteUser(w http.ResponseWriter, r *http.Request) {
	c, _ := claimsFrom(r.Context())
	userID := r.PathValue("id")

	if userID == c.Subject {
		writeErr(w, r, http.StatusBadRequest, "INVALID_ARGUMENT", "不能删除自己的账号（请由另一名管理员操作）")
		return
	}

	// 最后一个系统管理员不能删（否则租户永久失去管理入口）
	var admins, isAdmin int
	err := db.WithTenant(r.Context(), a.Pool, c.TenantID, func(tx pgx.Tx) error {
		if e := tx.QueryRow(r.Context(), `
			SELECT count(*) FROM user_role ur JOIN role ro ON ro.id = ur.role_id
			 WHERE ur.user_id = $1 AND ro.code = $2 AND ro.deleted_at IS NULL`,
			userID, rbac.SysAdmin).Scan(&isAdmin); e != nil {
			return e
		}
		return tx.QueryRow(r.Context(), `
			SELECT count(*) FROM user_role ur JOIN role ro ON ro.id = ur.role_id
			 WHERE ro.tenant_id = $1 AND ro.code = $2 AND ro.deleted_at IS NULL`,
			c.TenantID, rbac.SysAdmin).Scan(&admins)
	})
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "读取角色失败")
		return
	}
	if isAdmin > 0 && admins <= 1 {
		writeErr(w, r, http.StatusConflict, "LAST_ADMIN", "不能删除最后一个系统管理员")
		return
	}

	if err := a.Auth.SetUserStatus(r.Context(), c.TenantID, userID, "deleted"); err != nil {
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "删除账号失败")
		return
	}
	// 软删标记（保留审计与追溯能力；真正的内容回收由后台任务负责）
	err = db.WithTenant(r.Context(), a.Pool, c.TenantID, func(tx pgx.Tx) error {
		ct, e := tx.Exec(r.Context(), `
			UPDATE app_user SET deleted_at = now() WHERE id = $1 AND deleted_at IS NULL`, userID)
		if e != nil {
			return e
		}
		if ct.RowsAffected() == 0 {
			return pgx.ErrNoRows
		}
		return nil
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeErr(w, r, http.StatusNotFound, "NOT_FOUND", "用户不存在")
			return
		}
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "删除账号失败")
		return
	}

	_ = a.emit(r, c.TenantID, AuditEntry{
		ActorID: c.Subject, Action: "admin.user.delete", ObjectID: userID, Result: "ok",
	})
	writeOK(w, r, map[string]any{"userId": userID, "deleted": true})
}
