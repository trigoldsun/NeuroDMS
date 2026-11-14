package httpapi

// 短信验证码登录（公开端点，靠频控而不是身份保护）。

import (
	"net/http"
	"strconv"
	"time"

	"docvault/internal/auth"
)

func (a *API) registerSMSAuth(mux *http.ServeMux) {
	mux.HandleFunc("POST /v1/auth/sms/send", a.handleSMSSend)
	mux.HandleFunc("POST /v1/auth/sms/login", a.handleSMSLogin)
}

// handleSMSSend 发送登录验证码。
//
// 账号不存在时同样回 200 + "若该号码已登记，验证码已发送"：
// 这个接口不允许变成"查手机号是否注册"的工具。
func (a *API) handleSMSSend(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Account string `json:"account"`
	}
	if !decode(w, r, &req) {
		return
	}
	if req.Account == "" {
		writeErr(w, r, http.StatusBadRequest, "INVALID_ARGUMENT", "请填写手机号")
		return
	}
	if a.Auth == nil {
		writeErr(w, r, http.StatusNotImplemented, "NOT_AVAILABLE", "认证服务未启用")
		return
	}

	res, err := a.Auth.SendLoginCode(r.Context(), req.Account, clientIP(r))
	if err != nil {
		writeAuthErr(w, r, err)
		return
	}
	// 只有解析到租户（号码确实属于某账号）才落审计；未登记的号码没有租户可归属。
	if res.TenantID != "" {
		_ = a.emit(r, res.TenantID, AuditEntry{
			ActorID: "", Action: "auth.sms.send", Result: "ok",
			Detail: map[string]any{"phone": res.SentTo},
		})
	}
	writeOK(w, r, map[string]any{
		"sentTo":     res.SentTo,
		"retryAfter": res.RetryAfter,
		// 文案刻意不承诺"已发送"：号码未登记时也确实不会发
		"message": "若该号码已登记，验证码已发送",
	})
}

// handleSMSLogin 校验验证码并签发会话。
func (a *API) handleSMSLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Account string `json:"account"`
		Code    string `json:"code"`
	}
	if !decode(w, r, &req) {
		return
	}
	if req.Account == "" || req.Code == "" {
		writeErr(w, r, http.StatusBadRequest, "INVALID_ARGUMENT", "手机号与验证码均为必填")
		return
	}
	tk, err := a.Auth.LoginWithSMS(r.Context(), req.Account, req.Code, clientIP(r), r.UserAgent())
	if err != nil {
		// 失败也要留痕：先解析账号拿到租户，否则审计表没有归属可写
		// （audit_login 在 tenantID 为空时会直接跳过）。
		// 解析失败（号码未登记）时只剩 sms_send_log 里的哈希记录，这是有意的：
		// 不能为了记审计而把"该号码存在"写进一个可被读到的位置。
		tenantID := ""
		if ref, e := a.Auth.ResolveAccount(r.Context(), req.Account); e == nil {
			tenantID = ref.TenantID
		}
		a.auditLogin(r, tenantID, auth.MaskPhone(normalizeLoosePhone(req.Account)), err)
		writeAuthErr(w, r, err)
		return
	}
	if err := a.emit(r, tk.TenantID, AuditEntry{
		ActorID: tk.UserID, Action: "auth.login", Result: "ok",
		Detail: map[string]any{"method": "sms", "phone": auth.MaskPhone(normalizeLoosePhone(req.Account))},
	}); err != nil {
		writeErr(w, r, http.StatusInternalServerError, "AUDIT_FAILED", "审计写入失败，登录已拒绝")
		return
	}
	writeOK(w, r, map[string]any{
		"accessToken":   tk.Access,
		"refreshToken":  tk.Refresh,
		"accessExpires": tk.AccessExpires.UTC().Format(time.RFC3339),
		"userId":        tk.UserID,
		"tenantId":      tk.TenantID,
		"sessionId":     tk.SessionID,
	})
}

// normalizeLoosePhone 只用于"把用户输入转成可掩码的样子"，失败则原样返回。
func normalizeLoosePhone(raw string) string {
	if p, err := auth.NormalizePhone(raw); err == nil {
		return p
	}
	return raw
}

// writeRetryAfter 给 429 响应补一个 Retry-After 头（前端倒计时用它）。
func writeRetryAfter(w http.ResponseWriter, seconds int) {
	if seconds > 0 {
		w.Header().Set("Retry-After", strconv.Itoa(seconds))
	}
}
