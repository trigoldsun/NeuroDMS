package httpapi

import (
	"context"
	"errors"
	"net/http"
	"time"

	"docvault/internal/ace"
	"docvault/internal/auth"
	"docvault/internal/authz"
	"docvault/internal/content"
	"docvault/internal/db"

	"github.com/jackc/pgx/v5"
)

// registerACL 注册授权管理路由。
func (a *API) registerACL(mux *http.ServeMux) {
	mux.HandleFunc("POST /v1/acl", a.requireAuth(a.handleGrant))
	mux.HandleFunc("GET /v1/acl", a.requireAuth(a.handleListACL))
	// 摘要接口：给详情面板用。只回计数与前几条主体名，不回 allow/deny 位图，
	// 避免"能用摘要接口还原出完整 ACL"。
	mux.HandleFunc("GET /v1/acl/summary", a.requireAuth(a.handleACLSummary))
	mux.HandleFunc("DELETE /v1/acl/{id}", a.requireAuth(a.handleRevokeACL))
}

// aclTarget 解析对象并返回 (spaceID, nodeID)，供权限判定使用。
func (a *API) aclTarget(ctx context.Context, c auth.Claims, objectType, objectID string) (spaceID, nodeID string, err error) {
	switch objectType {
	case "space":
		return objectID, objectID, nil
	case "node":
		n, e := a.Content.GetNode(ctx, c.TenantID, objectID)
		if e != nil {
			return "", "", e
		}
		return n.SpaceID, objectID, nil
	default:
		return "", "", content.ErrBadInput
	}
}

func (a *API) handleGrant(w http.ResponseWriter, r *http.Request) {
	c, _ := claimsFrom(r.Context())
	var req struct {
		ObjectType     string `json:"objectType"`
		ObjectID       string `json:"objectId"`
		SubjectType    string `json:"subjectType"`
		SubjectID      string `json:"subjectId"`
		Preset         string `json:"preset"`
		ExpiresInHours int    `json:"expiresInHours"`
	}
	if !decode(w, r, &req) {
		return
	}
	preset := authz.Preset(req.Preset)
	if !preset.Valid() {
		writeErr(w, r, http.StatusBadRequest, "INVALID_ARGUMENT", "未知权限档位")
		return
	}
	switch req.SubjectType {
	case "user", "dept", "role", "group", "external":
	case "anonymous":
		// 匿名授权只能由分享生成：手工授一条 anonymous ACE 等于"任何人可访问"，
		// 会把分享的口令、有效期、审批全部绕过。
		writeErr(w, r, http.StatusBadRequest, "INVALID_ARGUMENT", "匿名主体不能手工授权，请通过分享生成")
		return
	default:
		writeErr(w, r, http.StatusBadRequest, "INVALID_ARGUMENT", "未知主体类型")
		return
	}

	spaceID, nodeID, err := a.aclTarget(r.Context(), c, req.ObjectType, req.ObjectID)
	if err != nil {
		writeErr(w, r, http.StatusNotFound, "NOT_FOUND", "对象不存在")
		return
	}

	// 授权方必须对该对象有 manage_acl
	d, err := a.check(r.Context(), c, spaceID, nodeID, authz.ManageACL)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "权限判定失败")
		return
	}
	if a.denyUnless(w, r, d) {
		return
	}

	var expires *time.Time
	if req.ExpiresInHours > 0 {
		t := time.Now().Add(time.Duration(req.ExpiresInHours) * time.Hour)
		expires = &t
	}

	var newID string
	err = db.WithTenant(r.Context(), a.Pool, c.TenantID, func(tx pgx.Tx) error {
		id, e := ace.Grant(r.Context(), tx, c.TenantID, req.ObjectType, req.ObjectID,
			req.SubjectType, req.SubjectID, preset, c.Subject, expires)
		newID = id
		return e
	})
	if err != nil {
		if errors.Is(err, ace.ErrCeilingExceeded) {
			// 越权授出必须留痕：这是内部提权的典型尝试路径
			_ = a.emit(r, c.TenantID, AuditEntry{
				ActorID: c.Subject, Action: "acl.grant", ObjectID: req.ObjectID, Result: "denied",
				Detail: map[string]any{"reason": "ceiling", "preset": req.Preset, "subjectId": req.SubjectID},
			})
			writeErr(w, r, http.StatusForbidden, "CEILING_EXCEEDED", "不能授出高于自身档位的权限")
			return
		}
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "授权失败")
		return
	}

	if err := a.emit(r, c.TenantID, AuditEntry{
		ActorID: c.Subject, Action: "acl.grant", ObjectID: req.ObjectID, Result: "ok",
		Detail: map[string]any{
			"objectType": req.ObjectType, "subjectType": req.SubjectType,
			"subjectId": req.SubjectID, "preset": req.Preset, "aceId": newID,
		},
	}); err != nil {
		writeErr(w, r, http.StatusInternalServerError, "AUDIT_FAILED", "审计写入失败，操作已拒绝")
		return
	}
	writeOK(w, r, map[string]any{"aceId": newID, "preset": req.Preset,
		"allow": preset.Bits().Names()})
}

func (a *API) handleListACL(w http.ResponseWriter, r *http.Request) {
	c, _ := claimsFrom(r.Context())
	objectType := r.URL.Query().Get("objectType")
	objectID := r.URL.Query().Get("objectId")

	if objectType == "" || objectID == "" {
		writeErr(w, r, http.StatusBadRequest, "INVALID_ARGUMENT", "objectType 与 objectId 必填")
		return
	}
	spaceID, nodeID, err := a.aclTarget(r.Context(), c, objectType, objectID)
	if err != nil {
		writeErr(w, r, http.StatusNotFound, "NOT_FOUND", "对象不存在")
		return
	}
	d, err := a.check(r.Context(), c, spaceID, nodeID, authz.ManageACL)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "权限判定失败")
		return
	}
	if a.denyUnless(w, r, d) {
		return
	}

	var rows []ace.ACERow
	err = db.WithTenant(r.Context(), a.Pool, c.TenantID, func(tx pgx.Tx) error {
		list, e := ace.List(r.Context(), tx, objectType, objectID)
		rows = list
		return e
	})
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "读取权限失败")
		return
	}

	items := make([]map[string]any, 0, len(rows))
	for _, x := range rows {
		item := map[string]any{
			"aceId": x.ID, "subjectType": x.SubjectType, "subjectId": x.SubjectID,
			"preset": x.Preset, "allow": x.Allow,
		}
		if x.ExpiresAt != nil {
			item["expiresAt"] = x.ExpiresAt.UTC().Format(time.RFC3339)
		}
		items = append(items, item)
	}
	writeOK(w, r, map[string]any{"items": items, "count": len(items)})
}

// handleACLSummary 返回某对象的授权摘要，供详情面板展示"谁被授权过"。
//
// 可见性：调用方必须对该对象有 manage_acl。没有权限时返回 200 + visible=false，
// 而不是 403/404 —— 这是给界面的"可选块"，用错误码会让面板每次打开都弹一次失败提示，
// 并且 404 会让用户误以为对象不存在。不返回任何条目，也就不泄露谁能访问。
func (a *API) handleACLSummary(w http.ResponseWriter, r *http.Request) {
	c, _ := claimsFrom(r.Context())
	objectType := r.URL.Query().Get("objectType")
	objectID := r.URL.Query().Get("objectId")
	if objectType == "" || objectID == "" {
		writeErr(w, r, http.StatusBadRequest, "INVALID_ARGUMENT", "objectType 与 objectId 必填")
		return
	}
	spaceID, nodeID, err := a.aclTarget(r.Context(), c, objectType, objectID)
	if err != nil {
		writeErr(w, r, http.StatusNotFound, "NOT_FOUND", "对象不存在")
		return
	}
	d, err := a.check(r.Context(), c, spaceID, nodeID, authz.ManageACL)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "权限判定失败")
		return
	}
	if !d.allowed {
		writeOK(w, r, map[string]any{"visible": false})
		return
	}

	var rows []ace.ACERow
	inheritedBroken := false
	err = db.WithTenant(r.Context(), a.Pool, c.TenantID, func(tx pgx.Tx) error {
		list, e := ace.List(r.Context(), tx, objectType, objectID)
		if e != nil {
			return e
		}
		rows = list
		// 继承是否被断开：决定界面要不要提示"这里的条目是快照"
		table := "node"
		if objectType == "space" {
			table = "space"
		}
		return tx.QueryRow(r.Context(),
			`SELECT inherit_broken FROM `+table+` WHERE id = $1`, objectID).Scan(&inheritedBroken)
	})
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "读取权限摘要失败")
		return
	}

	bySubject := map[string]int{}
	denyCount, ownerCount, expired := 0, 0, 0
	now := time.Now()
	for _, x := range rows {
		bySubject[x.SubjectType]++
		if len(x.Deny) > 0 {
			denyCount++
		}
		if x.Preset == "owner" {
			ownerCount++
		}
		if x.ExpiresAt != nil && x.ExpiresAt.Before(now) {
			expired++
		}
	}

	// 只取前 6 条：面板是摘要，不是权限管理页。排序：所有者 > 其他人 > 到期条目。
	order := map[string]int{"owner": 0, "manager": 1, "editor": 2, "contributor": 3, "viewer": 4}
	sorted := make([]ace.ACERow, len(rows))
	copy(sorted, rows)
	for i := 0; i < len(sorted); i++ {
		for j := i + 1; j < len(sorted); j++ {
			if order[sorted[j].Preset] < order[sorted[i].Preset] {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			}
		}
	}
	if len(sorted) > 6 {
		sorted = sorted[:6]
	}

	names := a.aclSubjectNames(r.Context(), c.TenantID, sorted)
	entries := make([]map[string]any, 0, len(sorted))
	for _, x := range sorted {
		item := map[string]any{
			"subjectType": x.SubjectType,
			"subjectName": names[x.SubjectType+":"+x.SubjectID],
			"preset":      x.Preset,
			"deny":        len(x.Deny) > 0,
		}
		if x.ExpiresAt != nil {
			item["expiresAt"] = x.ExpiresAt.UTC().Format(time.RFC3339)
		}
		entries = append(entries, item)
	}

	writeOK(w, r, map[string]any{
		"visible":         true,
		"total":           len(rows),
		"bySubject":       bySubject,
		"denyCount":       denyCount,
		"ownerCount":      ownerCount,
		"expiredCount":    expired,
		"inheritedBroken": inheritedBroken,
		"entries":         entries,
	})
}

// aclSubjectNames 批量解析授权主体名称（用户/部门/角色/组）。
//
// 主体 id 在不同表里可能重复，所以键是 "类型:id"，不能只用 id。
func (a *API) aclSubjectNames(ctx context.Context, tenantID string, rows []ace.ACERow) map[string]string {
	byType := map[string][]string{}
	for _, x := range rows {
		if x.SubjectID != "" {
			byType[x.SubjectType] = append(byType[x.SubjectType], x.SubjectID)
		}
	}
	out := map[string]string{}
	if len(byType) == 0 {
		return out
	}
	// 名称解析失败只影响显示（面板会退回"用户/部门"这类类型名），
	// 但必须留一条日志：上一次就是这里静默失败，把"参数占位写错"藏了半小时。
	err := db.WithTenant(ctx, a.Pool, tenantID, func(tx pgx.Tx) error {
		rs, err := tx.Query(ctx, `
			SELECT 'user', id::text, COALESCE(NULLIF(display_name,''), username)
			  FROM app_user WHERE id = ANY($1::uuid[])
			UNION ALL
			SELECT 'dept', id::text, name FROM dept WHERE id = ANY($2::uuid[])
			UNION ALL
			SELECT 'role', id::text, name FROM role WHERE id = ANY($3::uuid[])
			UNION ALL
			SELECT 'group', id::text, name FROM user_group WHERE id = ANY($4::uuid[])`,
			byType["user"], byType["dept"], byType["role"], byType["group"])
		if err != nil {
			return err
		}
		defer rs.Close()
		for rs.Next() {
			var t, id, name string
			if e := rs.Scan(&t, &id, &name); e != nil {
				return e
			}
			out[t+":"+id] = name
		}
		return rs.Err()
	})
	if err != nil {
		a.logErr("解析授权主体名称失败", "err", err)
	}
	return out
}

func (a *API) handleRevokeACL(w http.ResponseWriter, r *http.Request) {
	c, _ := claimsFrom(r.Context())
	aceID := r.PathValue("id")

	// 先确认这条 ACE 所属对象，再校验 manage_acl
	var objectType, objectID string
	err := db.WithTenant(r.Context(), a.Pool, c.TenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(r.Context(),
			`SELECT object_type, object_id::text FROM ace WHERE id = $1`, aceID).
			Scan(&objectType, &objectID)
	})
	if err != nil {
		writeErr(w, r, http.StatusNotFound, "NOT_FOUND", "权限条目不存在")
		return
	}

	spaceID, nodeID, err := a.aclTarget(r.Context(), c, objectType, objectID)
	if err != nil {
		// 对象已删除/解析失败时必须停在这里。
		//
		// 这里原先是 `if err == nil { ...判定... }` 的写法：一旦解析失败就
		// **跳过 manage_acl 判定直接执行删除**。也就是说，任何能登录的用户
		// 只要拿到一条 ACE 的 id（审计导出、截图、前端缓存里都可能出现），
		// 就能删掉对象已被删除的那些授权条目——把别人的授权清掉，
		// 或删掉一条 deny 给自己开口子。判定失败必须中止，不能"降级继续"。
		writeErr(w, r, http.StatusNotFound, "NOT_FOUND", "权限条目所属对象不存在")
		return
	}
	d, err := a.check(r.Context(), c, spaceID, nodeID, authz.ManageACL)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "权限判定失败")
		return
	}
	if a.denyUnless(w, r, d) {
		return
	}

	err = db.WithTenant(r.Context(), a.Pool, c.TenantID, func(tx pgx.Tx) error {
		return ace.Revoke(r.Context(), tx, aceID)
	})
	if err != nil {
		if errors.Is(err, ace.ErrLastOwner) {
			writeErr(w, r, http.StatusBadRequest, "LAST_OWNER", "不能移除对象的最后一个所有者")
			return
		}
		if errors.Is(err, ace.ErrInheritedACE) {
			// 继承快照是"上层 deny 的副本"，允许单删等于给了绕过上层的口子
			writeErr(w, r, http.StatusConflict, "INHERITED_ACE", "继承而来的权限不能单独删除，请先恢复继承")
			return
		}
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "撤销失败")
		return
	}

	_ = a.emit(r, c.TenantID, AuditEntry{
		ActorID: c.Subject, Action: "acl.revoke", ObjectID: objectID, Result: "ok",
		Detail: map[string]any{"aceId": aceID},
	})
	writeOK(w, r, map[string]any{"revoked": true})
}
