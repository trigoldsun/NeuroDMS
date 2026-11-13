package httpapi

import (
	"errors"
	"net/http"
	"strconv"

	"docvault/internal/db"
	"docvault/internal/iam"
	"docvault/internal/platform/httpmw"
	"docvault/internal/rbac"

	"github.com/jackc/pgx/v5"
)

// registerMembers 注册成员（账号）管理端点。
//
// 全部要求系统管理员：账号与角色是管理面的核心，安全管理员与审计管理员
// 都不应该能建号或改角色——否则"三权分立"只剩一个名头。
func (a *API) registerMembers(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/admin/members", a.requireRole(rbac.SysAdmin)(a.handleMemberList))
	mux.HandleFunc("POST /v1/admin/members", a.requireRole(rbac.SysAdmin)(a.handleMemberCreate))
	mux.HandleFunc("GET /v1/admin/members/{id}", a.requireRole(rbac.SysAdmin)(a.handleMemberGet))
	mux.HandleFunc("PATCH /v1/admin/members/{id}", a.requireRole(rbac.SysAdmin)(a.handleMemberUpdate))
	mux.HandleFunc("POST /v1/admin/members/{id}/status", a.requireRole(rbac.SysAdmin)(a.handleMemberStatus))
	mux.HandleFunc("POST /v1/admin/members/{id}/password", a.requireRole(rbac.SysAdmin)(a.handleMemberPassword))
	mux.HandleFunc("DELETE /v1/admin/members/{id}", a.requireRole(rbac.SysAdmin)(a.handleMemberDelete))
	// 角色授予/撤销复用既有路径（前端与既有测试都在用）
	mux.HandleFunc("POST /v1/admin/members/{id}/roles", a.requireRole(rbac.SysAdmin)(a.handleMemberGrantRole))
	mux.HandleFunc("DELETE /v1/admin/members/{id}/roles/{code}", a.requireRole(rbac.SysAdmin)(a.handleMemberRevokeRole))

	// 部门下拉：建号时要选部门
	mux.HandleFunc("GET /v1/admin/depts", a.requireRole(rbac.SysAdmin)(a.handleDeptList))
}

// iamErr 把 iam 的业务错误映射成稳定的状态码与错误码。
//
// 集中映射的理由：同一个错误在 6 个端点里出现，散着写必然出现
// "创建返回 400、修改返回 500"这种不一致，前端没法统一处理。
func (a *API) iamErr(w http.ResponseWriter, r *http.Request, tenantID, action, target string, err error) {
	code, status, msg := "INTERNAL", http.StatusInternalServerError, "操作失败"
	switch {
	case errors.Is(err, iam.ErrNotFound):
		code, status, msg = "NOT_FOUND", http.StatusNotFound, "成员不存在"
	case errors.Is(err, iam.ErrForbidden):
		code, status, msg = "FORBIDDEN", http.StatusForbidden, "需要系统管理员角色"
	case errors.Is(err, iam.ErrInvalidInput):
		code, status, msg = "INVALID_ARGUMENT", http.StatusBadRequest, err.Error()
	case errors.Is(err, iam.ErrDuplicate):
		code, status, msg = "USER_EXISTS", http.StatusConflict, "用户名或邮箱已被占用"
	case errors.Is(err, iam.ErrLastAdmin):
		code, status, msg = "LAST_ADMIN", http.StatusConflict, "不能移除最后一个可登录的系统管理员"
	case errors.Is(err, iam.ErrSeparation):
		code, status, msg = "SEPARATION_VIOLATION", http.StatusConflict, err.Error()
	case errors.Is(err, iam.ErrUnknownRole):
		code, status, msg = "UNKNOWN_ROLE", http.StatusBadRequest, "未知内置角色"
	case errors.Is(err, iam.ErrSelfTarget):
		code, status, msg = "SELF_OPERATION", http.StatusBadRequest, err.Error()
	case errors.Is(err, iam.ErrEscalation):
		code, status, msg = "CEILING_EXCEEDED", http.StatusForbidden, err.Error()
	case errors.Is(err, iam.ErrOwnsSpaces):
		code, status, msg = "OWNS_SPACES", http.StatusConflict, err.Error()
	}
	// 拒绝类结果一律留痕：管理面"谁试图做什么但被拦了"是高价值安全信号
	if status >= 400 {
		_ = a.emit(r, tenantID, AuditEntry{
			ActorID: actorIDOf(r), Action: action, ObjectID: target, Result: "denied",
			Detail: map[string]any{"code": code, "err": err.Error()},
		})
	}
	writeErr(w, r, status, code, msg)
}

// memberID 取出并校验路径里的成员 id。
//
// 为什么要显式校验：空串或非 UUID 会被当成"查不到"送进 SQL，
// PostgreSQL 对非法 uuid 直接报错，最终变成 500——而正确答案是 404。
// 这种 500 在排障时最误导人（看起来像服务坏了）。
func memberID(w http.ResponseWriter, r *http.Request) (string, bool) {
	id := r.PathValue("id")
	if !isUUID(id) {
		writeErr(w, r, http.StatusNotFound, "NOT_FOUND", "成员不存在")
		return "", false
	}
	return id, true
}

// isUUID 只做形状校验（36 位、4 个连字符、十六进制），不追求严格语义。
// 目的只有一个：别把明显不可能是 uuid 的串送进数据库。
func isUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i := 0; i < 36; i++ {
		c := s[i]
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return false
			}
			continue
		}
		isHex := (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
		if !isHex {
			return false
		}
	}
	return true
}

func actorIDOf(r *http.Request) string {
	c, _ := claimsFrom(r.Context())
	return c.Subject
}

// ---------------- 列表与详情 ----------------

func (a *API) handleMemberList(w http.ResponseWriter, r *http.Request) {
	c, _ := claimsFrom(r.Context())
	q := r.URL.Query()

	limit, _ := strconv.Atoi(q.Get("limit"))
	offset, _ := strconv.Atoi(q.Get("offset"))
	// 角色筛选只接受内置角色：否则会变成"按任意字符串扫全表"
	role := q.Get("role")
	if role != "" && !rbac.Known(role) {
		writeErr(w, r, http.StatusBadRequest, "INVALID_ARGUMENT", "未知角色")
		return
	}
	// 状态筛选同样白名单化
	status := q.Get("status")
	switch status {
	case "", iam.StatusActive, iam.StatusSuspended, iam.StatusInvited:
	default:
		writeErr(w, r, http.StatusBadRequest, "INVALID_ARGUMENT", "status 仅支持 active/suspended/invited")
		return
	}
	typ := q.Get("type")
	switch typ {
	case "", iam.TypeInternal, iam.TypeExternal:
	default:
		writeErr(w, r, http.StatusBadRequest, "INVALID_ARGUMENT", "type 仅支持 internal/external")
		return
	}

	items, total, err := a.IAM.List(r.Context(), c.TenantID, iam.ListFilter{
		Query: q.Get("q"), Status: status, Role: role, Type: typ,
		Limit: limit, Offset: offset,
	})
	if err != nil {
		a.logErr("读取成员列表失败", "err", err)
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "读取成员失败")
		return
	}
	writeOK(w, r, map[string]any{"items": items, "total": total, "count": len(items)})
}

func (a *API) handleMemberGet(w http.ResponseWriter, r *http.Request) {
	c, _ := claimsFrom(r.Context())
	id, ok := memberID(w, r)
	if !ok {
		return
	}
	m, err := a.IAM.Get(r.Context(), c.TenantID, id)
	if err != nil {
		a.iamErr(w, r, c.TenantID, "admin.member.get", id, err)
		return
	}
	writeOK(w, r, m)
}

// ---------------- 创建与修改 ----------------

func (a *API) handleMemberCreate(w http.ResponseWriter, r *http.Request) {
	c, _ := claimsFrom(r.Context())
	var in iam.CreateInput
	if !decode(w, r, &in) {
		return
	}
	m, err := a.IAM.Create(r.Context(), c.TenantID, c.Subject, in)
	if err != nil {
		a.iamErr(w, r, c.TenantID, "admin.member.create", in.Username, err)
		return
	}
	// 审计里绝不记口令，只记"谁建了谁、给了什么角色"
	if err := a.emit(r, c.TenantID, AuditEntry{
		ActorID: c.Subject, Action: "admin.member.create", ObjectID: m.ID, Result: "ok",
		Detail: map[string]any{"username": m.Username, "role": in.Role,
			"principalType": m.PrincipalType, "ceiling": m.Ceiling},
	}); err != nil {
		writeErr(w, r, http.StatusInternalServerError, "AUDIT_FAILED", "审计写入失败，创建已回滚")
		return
	}
	writeOK(w, r, m)
}

func (a *API) handleMemberUpdate(w http.ResponseWriter, r *http.Request) {
	c, _ := claimsFrom(r.Context())
	id, ok := memberID(w, r)
	if !ok {
		return
	}
	var in iam.UpdateInput
	if !decode(w, r, &in) {
		return
	}
	m, err := a.IAM.Update(r.Context(), c.TenantID, c.Subject, id, in)
	if err != nil {
		a.iamErr(w, r, c.TenantID, "admin.member.update", id, err)
		return
	}
	_ = a.emit(r, c.TenantID, AuditEntry{
		ActorID: c.Subject, Action: "admin.member.update", ObjectID: id, Result: "ok",
		Detail: map[string]any{"classification": m.Classification, "ceiling": m.Ceiling,
			"deptId": m.DeptID, "mfaRequired": m.MFARequired},
	})
	writeOK(w, r, m)
}

func (a *API) handleMemberStatus(w http.ResponseWriter, r *http.Request) {
	c, _ := claimsFrom(r.Context())
	id, ok := memberID(w, r)
	if !ok {
		return
	}
	var req struct {
		Status string `json:"status"`
	}
	if !decode(w, r, &req) {
		return
	}
	m, err := a.IAM.SetStatus(r.Context(), c.TenantID, c.Subject, id, req.Status)
	if err != nil {
		// 名下还有空间：不能只回一句"失败"，要把清单交回去，
		// 让操作者当场知道"该移交哪几个"。
		var oe *iam.OwnsSpacesError
		if errors.As(err, &oe) {
			_ = a.emit(r, c.TenantID, AuditEntry{
				ActorID: c.Subject, Action: "admin.member.status", ObjectID: id, Result: "denied",
				Detail: map[string]any{"code": "OWNS_SPACES", "status": req.Status, "spaces": len(oe.Spaces)},
			})
			writeOwnsSpaces(w, r, oe)
			return
		}
		a.iamErr(w, r, c.TenantID, "admin.member.status", id, err)
		return
	}
	// 停用会吊销会话，这个事实必须留痕：否则事后无法解释"某人为什么突然掉线"
	if err := a.emit(r, c.TenantID, AuditEntry{
		ActorID: c.Subject, Action: "admin.member.status", ObjectID: id, Result: "ok",
		Detail: map[string]any{"status": m.Status, "sessionsRevoked": m.Status != iam.StatusActive},
	}); err != nil {
		writeErr(w, r, http.StatusInternalServerError, "AUDIT_FAILED", "审计写入失败")
		return
	}
	if a.Auth != nil {
		// 本实例立即收敛（其它实例 ≤10s）
		a.Auth.InvalidateRevocationCache()
	}
	writeOK(w, r, m)
}

func (a *API) handleMemberPassword(w http.ResponseWriter, r *http.Request) {
	c, _ := claimsFrom(r.Context())
	id, ok := memberID(w, r)
	if !ok {
		return
	}
	var req struct {
		Password string `json:"password"`
	}
	if !decode(w, r, &req) {
		return
	}
	if err := a.IAM.ResetPassword(r.Context(), c.TenantID, c.Subject, id, req.Password); err != nil {
		a.iamErr(w, r, c.TenantID, "admin.member.password", id, err)
		return
	}
	// 只记"重置了"，不记任何口令内容
	if err := a.emit(r, c.TenantID, AuditEntry{
		ActorID: c.Subject, Action: "admin.member.password", ObjectID: id, Result: "ok",
		Detail: map[string]any{"sessionsRevoked": true},
	}); err != nil {
		writeErr(w, r, http.StatusInternalServerError, "AUDIT_FAILED", "审计写入失败")
		return
	}
	if a.Auth != nil {
		a.Auth.InvalidateRevocationCache()
	}
	writeOK(w, r, map[string]any{"userId": id, "reset": true})
}

func (a *API) handleMemberDelete(w http.ResponseWriter, r *http.Request) {
	c, _ := claimsFrom(r.Context())
	id, ok := memberID(w, r)
	if !ok {
		return
	}
	if err := a.IAM.Delete(r.Context(), c.TenantID, c.Subject, id); err != nil {
		var oe *iam.OwnsSpacesError
		if errors.As(err, &oe) {
			_ = a.emit(r, c.TenantID, AuditEntry{
				ActorID: c.Subject, Action: "admin.member.delete", ObjectID: id, Result: "denied",
				Detail: map[string]any{"code": "OWNS_SPACES", "spaces": len(oe.Spaces)},
			})
			writeOwnsSpaces(w, r, oe)
			return
		}
		a.iamErr(w, r, c.TenantID, "admin.member.delete", id, err)
		return
	}
	if err := a.emit(r, c.TenantID, AuditEntry{
		ActorID: c.Subject, Action: "admin.member.delete", ObjectID: id, Result: "ok",
	}); err != nil {
		writeErr(w, r, http.StatusInternalServerError, "AUDIT_FAILED", "审计写入失败")
		return
	}
	if a.Auth != nil {
		a.Auth.InvalidateRevocationCache()
	}
	writeOK(w, r, map[string]any{"userId": id, "deleted": true})
}

// ---------------- 角色 ----------------

func (a *API) handleMemberGrantRole(w http.ResponseWriter, r *http.Request) {
	c, _ := claimsFrom(r.Context())
	id, ok := memberID(w, r)
	if !ok {
		return
	}
	var req struct {
		Code string `json:"code"`
	}
	if !decode(w, r, &req) {
		return
	}
	roles, err := a.IAM.GrantRole(r.Context(), c.TenantID, c.Subject, id, req.Code)
	if err != nil {
		a.iamErr(w, r, c.TenantID, "admin.role.grant", id, err)
		return
	}
	_ = a.emit(r, c.TenantID, AuditEntry{
		ActorID: c.Subject, Action: "admin.role.grant", ObjectID: id, Result: "ok",
		Detail: map[string]any{"code": req.Code, "roles": roles},
	})
	writeOK(w, r, map[string]any{"roles": roles})
}

func (a *API) handleMemberRevokeRole(w http.ResponseWriter, r *http.Request) {
	c, _ := claimsFrom(r.Context())
	id, ok := memberID(w, r)
	if !ok {
		return
	}
	code := r.PathValue("code")
	roles, err := a.IAM.RevokeRole(r.Context(), c.TenantID, c.Subject, id, code)
	if err != nil {
		a.iamErr(w, r, c.TenantID, "admin.role.revoke", id, err)
		return
	}
	_ = a.emit(r, c.TenantID, AuditEntry{
		ActorID: c.Subject, Action: "admin.role.revoke", ObjectID: id, Result: "ok",
		Detail: map[string]any{"code": code, "roles": roles},
	})
	writeOK(w, r, map[string]any{"roles": roles})
}

// ---------------- 部门 ----------------

func (a *API) handleDeptList(w http.ResponseWriter, r *http.Request) {
	c, _ := claimsFrom(r.Context())

	type dept struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	items := []dept{}

	err := db.WithTenant(r.Context(), a.Pool, c.TenantID, func(tx pgx.Tx) error {
		rows, e := tx.Query(r.Context(),
			`SELECT id::text, name FROM dept WHERE deleted_at IS NULL ORDER BY path`)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var d dept
			if e := rows.Scan(&d.ID, &d.Name); e != nil {
				return e
			}
			items = append(items, d)
		}
		return rows.Err()
	})
	if err != nil {
		a.logErr("读取部门失败", "err", err)
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "读取部门失败")
		return
	}
	writeOK(w, r, map[string]any{"items": items, "count": len(items)})
}

// writeOwnsSpaces 返回 409 + 名下空间清单。
//
// 用 data 而不是 message 承载清单：前端要渲染成可点击的列表，
// 塞进一句话里只会变成"3 个空间…"这种没法操作的信息。
func writeOwnsSpaces(w http.ResponseWriter, r *http.Request, oe *iam.OwnsSpacesError) {
	writeJSON(w, r, http.StatusConflict, map[string]any{
		"code":      "OWNS_SPACES",
		"message":   oe.Error(),
		"requestId": httpmw.RequestIDFrom(r.Context()),
		"data":      map[string]any{"spaces": oe.Spaces, "count": len(oe.Spaces)},
	})
}
