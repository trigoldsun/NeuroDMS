package httpapi

import (
	"errors"
	"net/http"

	"docvault/internal/auth"
)

// 管理端手机号验证（docs/44 §4）。
//
// 三个动作都只作用于"已经登记在库里的号码"：换号走 PATCH member，
// 会重置验证状态；验证接口不接受新号码，因此不会出现"验的是 A 号、存的是 B 号"。

// handleMemberPhoneRequest 给成员已登记的号码发一条验证码。
func (a *API) handleMemberPhoneRequest(w http.ResponseWriter, r *http.Request) {
	id, ok := memberID(w, r)
	if !ok {
		return
	}
	c, _ := claimsFrom(r.Context())
	sentTo, err := a.Auth.RequestPhoneVerifyFor(r.Context(), c.TenantID, id, clientIP(r))
	if err != nil {
		a.memberPhoneErr(w, r, c.TenantID, "admin.member.phone.request", id, err)
		return
	}
	_ = a.emit(r, c.TenantID, AuditEntry{
		ActorID: c.Subject, Action: "admin.member.phone.request", ObjectID: id, Result: "ok",
		Detail: map[string]any{"phone": sentTo},
	})
	writeOK(w, r, map[string]any{
		"sentTo": sentTo,
		"next":   "请向本人索取验证码，填入后点「确认验证」",
	})
}

// handleMemberPhoneConfirm 校验验证码并把号码置为已验证。
func (a *API) handleMemberPhoneConfirm(w http.ResponseWriter, r *http.Request) {
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
	c, _ := claimsFrom(r.Context())
	masked, err := a.Auth.ConfirmPhoneVerifyFor(r.Context(), c.TenantID, id, req.Code)
	if err != nil {
		a.memberPhoneErr(w, r, c.TenantID, "admin.member.phone.confirm", id, err)
		return
	}
	// 验证状态是"能否用小程序的凭据开关"，必须留痕：
	// 这条记录回答的是"谁在什么时候把哪个号码变成了可用凭据"。
	_ = a.emit(r, c.TenantID, AuditEntry{
		ActorID: c.Subject, Action: "admin.member.phone.confirm", ObjectID: id, Result: "ok",
		Detail: auditDiff(
			map[string]any{"phoneVerified": false},
			map[string]any{"phoneVerified": true, "phone": masked},
		),
	})
	writeOK(w, r, map[string]any{"phoneMasked": masked, "phoneVerified": true})
}

// handleMemberPhoneClear 清除号码与验证状态。
func (a *API) handleMemberPhoneClear(w http.ResponseWriter, r *http.Request) {
	id, ok := memberID(w, r)
	if !ok {
		return
	}
	c, _ := claimsFrom(r.Context())
	// 改前值必须在清除之前读，否则审计只能记"清空过"，
	// 回答不了"清掉的是哪个号"——而号被清错时，这一条正是找回的线索。
	before := ""
	if m, e := a.IAM.Get(r.Context(), c.TenantID, id); e == nil {
		before = m.PhoneMasked
	}
	if err := a.Auth.ClearPhone(r.Context(), c.TenantID, id); err != nil {
		a.memberPhoneErr(w, r, c.TenantID, "admin.member.phone.clear", id, err)
		return
	}
	_ = a.emit(r, c.TenantID, AuditEntry{
		ActorID: c.Subject, Action: "admin.member.phone.clear", ObjectID: id, Result: "ok",
		Detail: auditDiff(
			map[string]any{"phone": before, "phoneVerified": true},
			map[string]any{"phone": "", "phoneVerified": false},
		),
	})
	writeOK(w, r, map[string]any{"phoneMasked": "", "phoneVerified": false})
}

// memberPhoneErr 把手机号相关错误映射成稳定的状态码。
//
// 不复用 writeAuthErr：那是"登录失败"的语义（401 为主），
// 而这里是管理操作失败——把 503 配置缺失报成 401，会让人以为令牌过期了。
func (a *API) memberPhoneErr(w http.ResponseWriter, r *http.Request, tenantID, action, target string, err error) {
	code, status, msg := "INTERNAL", http.StatusInternalServerError, "操作失败"

	var rl *auth.RateLimitError
	switch {
	case errors.As(err, &rl):
		writeRetryAfter(w, rl.RetryAfter)
		code, status, msg = "SMS_RATE_LIMITED", http.StatusTooManyRequests, rl.Reason
	case errors.Is(err, auth.ErrTargetNotFound):
		code, status, msg = "NOT_FOUND", http.StatusNotFound, "成员不存在"
	case errors.Is(err, auth.ErrPhoneRequired):
		code, status, msg = "PHONE_REQUIRED", http.StatusBadRequest, "该成员还没有登记手机号，请先在编辑里填写"
	case errors.Is(err, auth.ErrCodeInvalid):
		code, status, msg = "SMS_CODE_INVALID", http.StatusUnauthorized, "验证码不正确或已失效"
	case errors.Is(err, auth.ErrSMSNotConfigured):
		code, status, msg = "SMS_NOT_CONFIGURED", http.StatusServiceUnavailable, "短信认证服务未配置，暂时无法验证手机号"
	case errors.Is(err, auth.ErrSMSUnavailable):
		code, status, msg = "SMS_UNAVAILABLE", http.StatusServiceUnavailable, "短信服务暂不可用，请稍后重试"
	}

	if status >= 400 {
		_ = a.emit(r, tenantID, AuditEntry{
			ActorID: actorIDOf(r), Action: action, ObjectID: target, Result: "denied",
			Detail: map[string]any{"code": code, "err": msg},
		})
	}
	writeErr(w, r, status, code, msg)
}
