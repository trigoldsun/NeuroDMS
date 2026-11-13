package httpapi

// 分享链接的邮箱验证（AC-50 / AC-51）。
//
// 三条硬要求：
//   1. 只有白名单内的邮箱能申请验证码（AC-50），不在白名单时**不发码**；
//   2. 验证码连错 6 次后即使正确的码也失效（AC-51，由 OTPStore 的次数上限保证）；
//   3. 验证通过是一次性的：兑换时必须消费验证记录，否则"跳过验证直接兑换"依然可行。

import (
	"errors"
	"net/http"
	"time"

	"docvault/internal/auth"
	"docvault/internal/share"
)

func (a *API) registerShareVerify(mux *http.ServeMux) {
	mux.HandleFunc("POST /v1/public/shares/{token}/verify/request", a.handleShareVerifyRequest)
	mux.HandleFunc("POST /v1/public/shares/{token}/verify/confirm", a.handleShareVerifyConfirm)
}

func (a *API) handleShareVerifyRequest(w http.ResponseWriter, r *http.Request) {
	token := r.PathValue("token")

	var req struct {
		Email string `json:"email"`
	}
	if !decode(w, r, &req) {
		return
	}
	if req.Email == "" {
		writeErr(w, r, http.StatusBadRequest, "INVALID_ARGUMENT", "email 必填")
		return
	}

	p, err := share.LookupVerifyPolicy(r.Context(), a.Pool, token)
	if err != nil {
		// 与兑换保持一致的统一失效表现：不存在/过期/撤销都是 410，避免枚举
		writeErr(w, r, http.StatusGone, "SHARE_UNAVAILABLE", "链接不可用")
		return
	}
	if !p.RequireVerify {
		writeErr(w, r, http.StatusBadRequest, "VERIFY_NOT_REQUIRED", "该链接无需邮箱验证")
		return
	}

	// 白名单判定必须在发码之前：先发码再拒，等于给攻击者当免费的邮件发送器
	if !share.EmailAllowed(req.Email, p.Whitelist) {
		_ = a.emitPublic(r, p.TenantID, p.ShareID, "share.verify.request", "denied",
			map[string]any{"reason": "email_not_allowed"})
		writeErr(w, r, http.StatusForbidden, "EMAIL_NOT_ALLOWED", "该邮箱不在允许访问的范围内")
		return
	}

	sentTo, ttl, err := a.Auth.RequestShareCode(r.Context(), p.TenantID, p.ShareID, req.Email)
	switch {
	case errors.Is(err, auth.ErrChannelUnavailable):
		writeErr(w, r, http.StatusServiceUnavailable, "CHANNEL_UNAVAILABLE", "邮件通道未配置，无法完成验证")
		return
	case errors.Is(err, auth.ErrEmailInvalid):
		writeErr(w, r, http.StatusBadRequest, "INVALID_ARGUMENT", err.Error())
		return
	case errors.Is(err, auth.ErrTooManyCodes):
		writeErr(w, r, http.StatusTooManyRequests, "TOO_MANY_CODES", "验证码请求过于频繁，请稍后再试")
		return
	case err != nil:
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "发送验证码失败")
		return
	}

	_ = a.emitPublic(r, p.TenantID, p.ShareID, "share.verify.request", "ok",
		map[string]any{"to": sentTo})
	writeOK(w, r, map[string]any{"sentTo": sentTo, "expiresIn": ttl})
}

func (a *API) handleShareVerifyConfirm(w http.ResponseWriter, r *http.Request) {
	token := r.PathValue("token")
	password := r.Header.Get("X-Share-Password")

	var req struct {
		Email string `json:"email"`
		Code  string `json:"code"`
	}
	if !decode(w, r, &req) {
		return
	}
	if req.Email == "" || req.Code == "" {
		writeErr(w, r, http.StatusBadRequest, "INVALID_ARGUMENT", "email 与 code 必填")
		return
	}

	p, err := share.LookupVerifyPolicy(r.Context(), a.Pool, token)
	if err != nil {
		writeErr(w, r, http.StatusGone, "SHARE_UNAVAILABLE", "链接不可用")
		return
	}
	if !p.RequireVerify {
		writeErr(w, r, http.StatusBadRequest, "VERIFY_NOT_REQUIRED", "该链接无需邮箱验证")
		return
	}
	if !share.EmailAllowed(req.Email, p.Whitelist) {
		writeErr(w, r, http.StatusForbidden, "EMAIL_NOT_ALLOWED", "该邮箱不在允许访问的范围内")
		return
	}

	if err := a.Auth.VerifyShareCode(r.Context(), p.TenantID, p.ShareID, req.Email, req.Code); err != nil {
		_ = a.emitPublic(r, p.TenantID, p.ShareID, "share.verify.confirm", "denied",
			map[string]any{"reason": "code_invalid"})
		writeErr(w, r, http.StatusBadRequest, "CODE_INVALID", "验证码不正确或已失效（连续错误将临时锁定）")
		return
	}

	if _, _, err := share.RecordVerify(r.Context(), a.Pool, p, req.Email,
		clientIP(r), share.DefaultVerifyTTL); err != nil {
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "记录验证状态失败")
		return
	}

	// 验证通过 → 直接兑换并签发票据，省掉一次多余往返
	res, err := share.RedeemWithVerify(r.Context(), a.Pool, token, password, req.Email,
		clientIP(r), r.UserAgent())
	if err != nil {
		a.redeemError(w, r, err)
		return
	}
	ticket, expires, err := share.IssueTicket(r.Context(), a.Pool, res, clientIP(r), share.DefaultTicketTTL)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "签发访问票据失败")
		return
	}

	_ = a.emitPublic(r, p.TenantID, p.ShareID, "share.verify.confirm", "ok",
		map[string]any{"verified": true})
	writeOK(w, r, map[string]any{
		"shareId": res.ShareID, "objectType": res.ObjectType, "objectId": res.ObjectID,
		"allowDownload": res.AllowDownload, "watermark": res.Watermark,
		"ticket": ticket, "expiresIn": int(time.Until(expires).Seconds()),
	})
}

// emitPublic 记录匿名访问者的审计（actor 类型固定 anonymous，不写邮箱明文）。
func (a *API) emitPublic(r *http.Request, tenantID, shareID, action, result string, detail map[string]any) error {
	if detail == nil {
		detail = map[string]any{}
	}
	detail["shareId"] = shareID
	return a.emit(r, tenantID, AuditEntry{
		ActorType: "anonymous", Action: action, ObjectID: shareID, Result: result, Detail: detail,
	})
}
