package httpapi

import (
	"errors"
	"net/http"
	"strconv"

	"docvault/internal/classification"
	"docvault/internal/iam"
	"docvault/internal/platform/httpmw"
	"docvault/internal/rbac"
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

	// 手机号的事后验证：录入不强制当场验证，但必须能补验（docs/44 §4）。
	// 三个端点都只作用于"库里已登记的那个号"，不接受新号码——
	// 换号走 PATCH（会重置验证状态），两条路分开就不会出现"验 A 存 B"。
	mux.HandleFunc("POST /v1/admin/members/{id}/phone/request", a.requireRole(rbac.SysAdmin)(a.handleMemberPhoneRequest))
	mux.HandleFunc("POST /v1/admin/members/{id}/phone/confirm", a.requireRole(rbac.SysAdmin)(a.handleMemberPhoneConfirm))
	mux.HandleFunc("DELETE /v1/admin/members/{id}/phone", a.requireRole(rbac.SysAdmin)(a.handleMemberPhoneClear))

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
	case errors.Is(err, iam.ErrPhoneTaken):
		code, status, msg = "PHONE_TAKEN", http.StatusConflict, "该手机号已被其他账号使用"
	case errors.Is(err, iam.ErrLastAdmin):
		code, status, msg = "LAST_ADMIN", http.StatusConflict, "不能移除最后一个可登录的系统管理员"
	case errors.Is(err, iam.ErrSeparation):
		code, status, msg = "SEPARATION_VIOLATION", http.StatusConflict, err.Error()
	case errors.Is(err, iam.ErrUnknownRole):
		code, status, msg = "UNKNOWN_ROLE", http.StatusBadRequest, "未知内置角色"
	case errors.Is(err, iam.ErrSelfTarget):
		code, status, msg = "SELF_OPERATION", http.StatusBadRequest, err.Error()
	case errors.Is(err, iam.ErrEscalation):
		// 把"找谁办"写进消息：只报"不能授予高于自己"会让人反复重试同一个下拉框。
		code, status = "CEILING_EXCEEDED", http.StatusForbidden
		msg = err.Error() + "。管理员不能提升自己的密级；这类操作需要由同级或更高密级的管理员完成"
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

// guardMemberClass 按"档位 + 授权"判定成员密级是否可写。
//
// 为什么在 HTTP 层而不是 iam：判定要读 edition 与 entitlement（产品能力面），
// iam 是人员域，不该反向依赖档位包。成员写入只有这一个入口，拦在这里是完整的
// （与上传、改对象密级用的是同一个 classLevels/levelAllowed）。
//
// 三件事一起做：
//  1. 显式传入的密级必须落在"该租户此刻允许写入的集合"内（基础版为空集 → 只准 0）；
//  2. 没有密级能力时，**未传**的密级强制落 0，避免 iam 的默认值写出一个不存在的档位；
//  3. 拒绝时用 FEATURE_NOT_ENABLED，与上传入口同码，前端只需认一处。
//
// ceiling（封顶）不在这里限：它是"能授出的上限"，不产生对象数据；
// 对象密级本身已被上传/改密级入口拦住，封顶超出档位不会造成越权。
func (a *API) guardMemberClass(w http.ResponseWriter, r *http.Request, tenantID string, class **int, forceZero bool) bool {
	c, _ := claimsFrom(r.Context())
	levels, st, err := a.classLevels(r.Context(), tenantID)
	if err != nil {
		writeErr(w, r, http.StatusServiceUnavailable, "ENTITLEMENT_UNAVAILABLE",
			"无法读取租户档位，请稍后重试")
		return true
	}
	if len(levels) == 0 {
		if class != nil && *class != nil && **class > 0 {
			_ = a.emit(r, tenantID, AuditEntry{
				ActorID: c.Subject, Action: "admin.member.classification", Result: "denied",
				Detail: map[string]any{"reason": "edition_classification",
					"requested": **class, "edition": string(st.Edition)},
			})
			writeErr(w, r, http.StatusForbidden, "FEATURE_NOT_ENABLED",
				"当前档位或授权不含密级功能（"+st.Spec.Name+"），成员密级只能为 0")
			return true
		}
		// 只在"新建"时补 0：编辑成员时未传密级表示"不改"，
		// 强行置 0 会让"改个显示名"顺手把密级清掉。
		if class != nil && forceZero && *class == nil {
			zero := 0
			*class = &zero
		}
		return false
	}
	if class == nil || *class == nil {
		return false
	}
	v := **class
	if v < 0 || v > classification.MaxLevel {
		writeErr(w, r, http.StatusBadRequest, "INVALID_ARGUMENT", "密级必须在 0..6 之间")
		return true
	}
	if !levelAllowed(levels, v) {
		_ = a.emit(r, tenantID, AuditEntry{
			ActorID: c.Subject, Action: "admin.member.classification", Result: "denied",
			Detail: map[string]any{"reason": "edition_classification",
				"requested": v, "edition": string(st.Edition), "allowed": levels},
		})
		writeErr(w, r, http.StatusForbidden, "FEATURE_NOT_ENABLED",
			"当前档位或授权不支持该密级（"+st.Spec.Name+"）")
		return true
	}
	return false
}

func (a *API) handleMemberCreate(w http.ResponseWriter, r *http.Request) {
	c, _ := claimsFrom(r.Context())
	var in iam.CreateInput
	if !decode(w, r, &in) {
		return
	}
	if a.guardMemberClass(w, r, c.TenantID, &in.Classification, true) {
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
	if a.guardMemberClass(w, r, c.TenantID, &in.Classification, false) {
		return
	}
	// 改前值：成员的密级/档位决定他能看到什么，改错一次就是一次越权，
	// 所以必须能回答"从几级调到几级"。
	// 读失败就给 nil：审计会显示"— → 新值"，而不是编一个 0 级当作旧值
	prev, perr := a.IAM.Get(r.Context(), c.TenantID, id)
	var beforeSnap map[string]any
	if perr == nil {
		beforeSnap = memberSnapshot(prev)
	}
	m, err := a.IAM.Update(r.Context(), c.TenantID, c.Subject, id, in)
	if err != nil {
		a.iamErr(w, r, c.TenantID, "admin.member.update", id, err)
		return
	}
	_ = a.emit(r, c.TenantID, AuditEntry{
		ActorID: c.Subject, Action: "admin.member.update", ObjectID: id, Result: "ok",
		Detail: auditDiff(beforeSnap, memberSnapshot(m)),
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
	prev, perr := a.IAM.Get(r.Context(), c.TenantID, id)
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
	var beforeStatus map[string]any
	if perr == nil {
		beforeStatus = map[string]any{"status": prev.Status}
	}
	statusDetail := auditDiff(beforeStatus, map[string]any{"status": m.Status})
	// 停用会吊销会话，这个事实必须留痕：否则事后无法解释"某人为什么突然掉线"
	statusDetail["sessionsRevoked"] = m.Status != iam.StatusActive
	if err := a.emit(r, c.TenantID, AuditEntry{
		ActorID: c.Subject, Action: "admin.member.status", ObjectID: id, Result: "ok",
		Detail: statusDetail,
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

// memberSnapshot 取成员配置里"会改变可见范围"的字段。
//
// 用户名、邮箱不进来：它们不决定权限，且频繁变更时会淹没真正的越权改动。
func memberSnapshot(m iam.Member) map[string]any {
	return map[string]any{
		"classification": m.Classification,
		"ceiling":        m.Ceiling,
		"deptId":         m.DeptID,
		"mfaRequired":    m.MFARequired,
		// 手机号只记掩码：审计里放完整号码，等于把通讯录写进一个
		// 审计管理员能读的表。掩码足够回答"换没换、换成哪个尾号"。
		"phone":         m.PhoneMasked,
		"phoneVerified": m.PhoneVerified,
		"title":         m.Title,
	}
}
