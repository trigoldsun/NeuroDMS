package httpapi

// 租户侧能力查询（docs/17 §4）。
//
// 为什么前端需要这个接口：没有它，界面只能"先把按钮都显示出来，点了再 403"。
// 客户看到的是"功能有但不能用"，客服也无法区分"没买"和"没权限"。
//
// 注意：这个接口只服务展示，**不是安全边界**。真正的判定在每个写入口，
// 前端隐藏按钮只是让体验合理。

import (
	"net/http"
	"time"

	"docvault/internal/tenant"
)

// registerEdition 注册租户侧能力查询。
func (a *API) registerEdition(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/me/capabilities", a.requireAuth(a.handleMyCapabilities))
}

func (a *API) handleMyCapabilities(w http.ResponseWriter, r *http.Request) {
	c, _ := claimsFrom(r.Context())

	st, err := a.editionState(r.Context(), c.TenantID)
	if err != nil {
		writeErr(w, r, http.StatusServiceUnavailable, "ENTITLEMENT_UNAVAILABLE",
			"无法读取租户档位，请稍后重试")
		return
	}

	// 租户策略可能是调用方自己调小的，展示时用"实际生效值"，
	// 避免界面写 50、实际只保留 10 这种对不上的情况。
	policyKeep, policyMB := 0, 0
	timeoutSec := tenant.DefaultUploadTimeoutSeconds
	var allowedExts []string
	if pol, perr := a.tenantPolicy(r.Context(), c.TenantID); perr == nil {
		policyKeep, policyMB = pol.VersionKeep, pol.MaxUploadMB
		if pol.UploadTimeoutSeconds > 0 {
			timeoutSec = pol.UploadTimeoutSeconds
		}
		allowedExts = pol.AllowedExts
	}

	var expires any
	if st.ExpiresAt != nil {
		expires = st.ExpiresAt.UTC().Format(time.RFC3339)
	}

	writeOK(w, r, map[string]any{
		"edition":         string(st.Edition),
		"declaredEdition": string(st.Declared),
		"editionName":     st.Spec.Name,
		"expiresAt":       expires,
		// grace = 已到期但仍在 30 天宽限内；expired = 已降为基础版
		"grace":   st.InGrace,
		"expired": st.Expired,
		"capabilities": map[string]any{
			"classification": st.Spec.Classification,
			"ad":             st.Spec.AD,
			"shareMail":      st.Spec.ShareMail,
			"customDomain":   st.Spec.CustomDomain,
		},
		"classificationLevels": st.SelectableClasses(),
		"limits": map[string]any{
			"versionKeep": st.EffectiveVersionKeep(policyKeep),
			"maxUploadMB": st.EffectiveMaxUploadMB(policyMB),
			// 上传超时按租户可配（默认 300 秒）：前端用它决定本地等待上限，
			// 后端用它设置本次请求的读取截止时间。两边必须同源，否则
			// 前端还在等、后端已经断开，用户看到的是"莫名其妙的失败"。
			"uploadTimeoutSeconds": timeoutSec,
			// allowedExts 为 null 表示不限制；空数组会被前端理解成"一个都不许传"。
			"allowedExts": allowedExts,
		},
	})
}
