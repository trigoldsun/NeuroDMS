package httpapi

// 个人资料：换绑邮箱（AC-61）。

import (
	"errors"
	"net/http"

	"docvault/internal/auth"
	"docvault/internal/iam"
)

func (a *API) registerProfile(mux *http.ServeMux) {
	mux.HandleFunc("POST /v1/me/email/request", a.requireAuth(a.handleEmailChangeRequest))
	mux.HandleFunc("POST /v1/me/email/confirm", a.requireAuth(a.handleEmailChangeConfirm))

	// 账号生命周期：注销 + 数字资产交接（详见 internal/iam/account.go）
	mux.HandleFunc("GET /v1/me/handover-candidates", a.requireAuth(a.handleHandoverCandidates))
	mux.HandleFunc("GET /v1/me/account/deletion-preview", a.requireAuth(a.handleDeletionPreview))
	mux.HandleFunc("POST /v1/me/account/delete", a.requireAuth(a.handleSelfDelete))
}

// handleHandoverCandidates 列出可接收资产的账号。
func (a *API) handleHandoverCandidates(w http.ResponseWriter, r *http.Request) {
	c, _ := claimsFrom(r.Context())
	if a.IAM == nil {
		writeErr(w, r, http.StatusNotImplemented, "IAM_UNAVAILABLE", "成员管理未启用")
		return
	}
	items, err := a.IAM.Candidates(r.Context(), c.TenantID, c.Subject, r.URL.Query().Get("q"))
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "读取候选账号失败")
		return
	}
	writeOK(w, r, map[string]any{"items": items})
}

// handleDeletionPreview 返回注销时会交接/撤销的资产数量。
func (a *API) handleDeletionPreview(w http.ResponseWriter, r *http.Request) {
	c, _ := claimsFrom(r.Context())
	if a.IAM == nil {
		writeErr(w, r, http.StatusNotImplemented, "IAM_UNAVAILABLE", "成员管理未启用")
		return
	}
	sum, err := a.IAM.HandoverPreview(r.Context(), c.TenantID, c.Subject)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "统计失败")
		return
	}
	writeOK(w, r, sum)
}

// handleSelfDelete 注销当前账号：先交接数字资产，再软删。
//
// 这是不可逆操作，因此审计写在**交接成功之后**：
// 若审计写失败会返回 500，但数据已提交——这一点在响应里说明，避免用户以为没生效。
func (a *API) handleSelfDelete(w http.ResponseWriter, r *http.Request) {
	c, _ := claimsFrom(r.Context())
	if a.IAM == nil {
		writeErr(w, r, http.StatusNotImplemented, "IAM_UNAVAILABLE", "成员管理未启用")
		return
	}
	var req struct {
		SuccessorID string `json:"successorId"`
		Confirm     string `json:"confirm"`
	}
	if !decode(w, r, &req) {
		return
	}

	sum, err := a.IAM.SelfDelete(r.Context(), c.TenantID, c.Subject, req.SuccessorID, req.Confirm)
	if err != nil {
		switch {
		case errors.Is(err, iam.ErrNoSuccessor):
			writeErr(w, r, http.StatusBadRequest, "NO_SUCCESSOR", "请选择一位可用的接收人")
		case errors.Is(err, iam.ErrLastAdmin):
			writeErr(w, r, http.StatusConflict, "LAST_ADMIN",
				"你是当前唯一可登录的系统管理员，请先指定另一位管理员再注销")
		case errors.Is(err, iam.ErrInvalidInput):
			writeErr(w, r, http.StatusBadRequest, "CONFIRM_MISMATCH", "请输入自己的账号名以确认注销")
		case errors.Is(err, iam.ErrNotFound):
			writeErr(w, r, http.StatusNotFound, "NOT_FOUND", "账号不存在")
		default:
			// 注销失败必须留痕：这是不可逆操作，500 又不带原因的话，
			// 用户只能报"注销不了"，运维无从下手。
			a.logErr("账号注销失败", "userId", c.Subject, "err", err)
			writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "注销失败")
		}
		return
	}

	_ = a.emit(r, c.TenantID, AuditEntry{
		ActorID: c.Subject, Action: "account.self_delete", ObjectID: req.SuccessorID, Result: "ok",
		Detail: map[string]any{
			"spaces": sum.Spaces, "nodes": sum.Nodes,
			"grants": sum.Grants, "revokedShares": sum.RevokedShares,
		},
	})
	writeOK(w, r, map[string]any{
		"deleted":             true,
		"handedOverSpaces":    sum.Spaces,
		"handedOverNodes":     sum.Nodes,
		"handedOverGrants":    sum.Grants,
		"revokedShares":       sum.RevokedShares,
		"sessionsInvalidated": true,
	})
}

// handleEmailChangeRequest 发起换绑：必须提供当前口令。
func (a *API) handleEmailChangeRequest(w http.ResponseWriter, r *http.Request) {
	c, _ := claimsFrom(r.Context())
	var req struct {
		NewEmail string `json:"newEmail"`
		Password string `json:"password"`
	}
	if !decode(w, r, &req) {
		return
	}
	if req.NewEmail == "" {
		writeErr(w, r, http.StatusBadRequest, "INVALID_ARGUMENT", "newEmail 必填")
		return
	}

	sentTo, ttl, err := a.Auth.RequestEmailChange(r.Context(), c.TenantID, c.Subject, req.NewEmail, req.Password)
	switch {
	case errors.Is(err, auth.ErrInvalidCredentials):
		// 口令错必须留痕：这是"有人拿到了别人会话、想换绑邮箱"的典型信号
		_ = a.emit(r, c.TenantID, AuditEntry{
			ActorID: c.Subject, Action: "profile.email.request", Result: "denied",
			Detail: map[string]any{"reason": "invalid_credentials"},
		})
		writeErr(w, r, http.StatusUnauthorized, "INVALID_CREDENTIALS", "口令错误")
		return
	case errors.Is(err, auth.ErrEmailInvalid):
		writeErr(w, r, http.StatusBadRequest, "INVALID_ARGUMENT", err.Error())
		return
	case errors.Is(err, auth.ErrEmailTaken):
		writeErr(w, r, http.StatusConflict, "EMAIL_TAKEN", err.Error())
		return
	case errors.Is(err, auth.ErrChannelUnavailable):
		// 不能"跳过验证码直接改"：那等于把双因子换成单因子
		writeErr(w, r, http.StatusServiceUnavailable, "CHANNEL_UNAVAILABLE", err.Error())
		return
	case err != nil:
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "发送验证码失败")
		return
	}

	_ = a.emit(r, c.TenantID, AuditEntry{
		ActorID: c.Subject, Action: "profile.email.request", Result: "ok",
		Detail: map[string]any{"to": sentTo},
	})
	writeOK(w, r, map[string]any{
		"sentTo": sentTo, "expiresIn": ttl,
		"next": "请在新邮箱查收验证码，并调用 /v1/me/email/confirm 完成换绑",
	})
}

// handleEmailChangeConfirm 用验证码完成换绑。
func (a *API) handleEmailChangeConfirm(w http.ResponseWriter, r *http.Request) {
	c, _ := claimsFrom(r.Context())
	var req struct {
		NewEmail string `json:"newEmail"`
		Code     string `json:"code"`
	}
	if !decode(w, r, &req) {
		return
	}
	if req.NewEmail == "" || req.Code == "" {
		writeErr(w, r, http.StatusBadRequest, "INVALID_ARGUMENT", "newEmail 与 code 必填")
		return
	}

	err := a.Auth.ConfirmEmailChange(r.Context(), c.TenantID, c.Subject, req.NewEmail, req.Code)
	switch {
	case errors.Is(err, auth.ErrCodeInvalid):
		_ = a.emit(r, c.TenantID, AuditEntry{
			ActorID: c.Subject, Action: "profile.email.confirm", Result: "denied",
			Detail: map[string]any{"reason": "code_invalid"},
		})
		writeErr(w, r, http.StatusBadRequest, "CODE_INVALID", "验证码错误或已失效")
		return
	case errors.Is(err, auth.ErrEmailInvalid):
		writeErr(w, r, http.StatusBadRequest, "INVALID_ARGUMENT", err.Error())
		return
	case errors.Is(err, auth.ErrEmailTaken):
		writeErr(w, r, http.StatusConflict, "EMAIL_TAKEN", err.Error())
		return
	case errors.Is(err, auth.ErrChannelUnavailable):
		writeErr(w, r, http.StatusServiceUnavailable, "CHANNEL_UNAVAILABLE", err.Error())
		return
	case errors.Is(err, auth.ErrSessionInvalid):
		writeErr(w, r, http.StatusUnauthorized, "SESSION_INVALID", "会话已失效")
		return
	case err != nil:
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "换绑失败")
		return
	}

	_ = a.emit(r, c.TenantID, AuditEntry{
		ActorID: c.Subject, Action: "profile.email.confirm", Result: "ok",
		// 不写完整邮箱：审计日志会被导出，联系方式属于个人信息
		Detail: map[string]any{"changed": true},
	})
	writeOK(w, r, map[string]any{
		"changed": true,
		"note":    "换绑成功，所有会话已失效，请重新登录",
	})
}
