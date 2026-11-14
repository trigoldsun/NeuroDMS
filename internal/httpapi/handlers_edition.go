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
	// folderUpload 是"档位允许 **且** 租户已开启"的结果；
	// folderUploadAllowed 只表示档位允许，用来决定设置页的开关是否可点。
	folderUpload := false
	// smsLogin：档位允许 + 租户开启 + 通道就绪，三者缺一不可
	smsLogin := false
	if pol, perr := a.tenantPolicy(r.Context(), c.TenantID); perr == nil {
		policyKeep, policyMB = pol.VersionKeep, pol.MaxUploadMB
		if pol.UploadTimeoutSeconds > 0 {
			timeoutSec = pol.UploadTimeoutSeconds
		}
		allowedExts = pol.AllowedExts
		folderUpload = st.Spec.FolderUpload && pol.FolderUpload
		smsLogin = st.Spec.SmsLogin && pol.SmsLogin && a.SMSConfigured
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
			// folderUpload：整目录上传此刻是否可用（档位允许 + 租户已开启）
			"folderUpload": folderUpload,
			"smsLogin":     smsLogin,
		},
		// 档位层面是否允许（租户关掉时它仍为 true，便于设置页提示"可开启"）
		"folderUploadAllowed": st.Spec.FolderUpload,
		// 短信登录是否具备开通条件（档位 + 通道）。必须与"当前生效值"分开：
		// 只用有效值判断，设置页在关闭状态下永远是灰的，点了也没法开通。
		"smsLoginAllowed":      st.Spec.SmsLogin && a.SMSConfigured,
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
