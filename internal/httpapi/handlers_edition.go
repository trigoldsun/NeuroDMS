package httpapi

// 租户侧能力查询（docs/17 §4、docs/47 §4.1）。
//
// 为什么前端需要这个接口：没有它，界面只能"先把按钮都显示出来，点了再 403"。
// 客户看到的是"功能有但不能用"，客服也无法区分"没买"和"没权限"。
//
// 注意：这个接口只服务展示，**不是安全边界**。真正的判定在每个写入口，
// 前端隐藏按钮只是让体验合理。
//
// 兼容策略：`capabilities` 下的旧布尔值保留一个版本（含义与之前完全一致：
// "档位/授权允许"或"生效值"），新字段 `capabilityDetail` 给出五态。
// 直接改旧字段含义会让前端在灰度期出现"按钮时有时无"。

import (
	"net/http"
	"time"

	"docvault/internal/entitlement"
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
	caps, err := a.capabilitiesOf(r.Context(), c.TenantID)
	if err != nil {
		// 授权读不到一律 503：不能让"读失败"退化成"没有该能力"，
		// 否则前端会显示"可升级"，而实际原因是我们这边挂了。
		writeErr(w, r, http.StatusServiceUnavailable, "ENTITLEMENT_UNAVAILABLE",
			"无法读取能力授权，请稍后重试")
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

	folder := caps[entitlement.UploadFolder]
	sms := caps[entitlement.SMSLogin]

	writeOK(w, r, map[string]any{
		"edition":         string(st.Edition),
		"declaredEdition": string(st.Declared),
		"editionName":     st.Spec.Name,
		"expiresAt":       expires,
		// grace = 已到期但仍在 30 天宽限内；expired = 已到期
		"grace":   st.InGrace,
		"expired": st.Expired,
		// 旧字段：含义与改动前一致，便于前端平滑切换
		"capabilities": map[string]any{
			"classification": caps[entitlement.Classification].Entitled,
			"ad":             caps[entitlement.DirAuth].Entitled,
			"shareMail":      caps[entitlement.MailOutbound].Entitled,
			"customDomain":   caps[entitlement.CustomDomain].Entitled,
			// folderUpload：授权 + 租户已开启（资源无需配置）
			"folderUpload": folder.Entitled && folder.Enabled,
			// smsLogin：授权 + 租户已开启 + 通道就绪，三者缺一不可
			"smsLogin": sms.Usable,
		},
		// 新字段：五态，带来源与原因码
		"capabilityDetail": caps,
		// 授权层：租户关掉时它仍为 true，便于设置页提示"可开启"
		"folderUploadAllowed": folder.Entitled,
		// 开通条件（授权 + 通道）。必须与"当前生效值"分开：
		// 只给有效值，设置页在关闭状态下永远是灰的，点了也没法开通。
		"smsLoginAllowed":      sms.Entitled && sms.Configured,
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
