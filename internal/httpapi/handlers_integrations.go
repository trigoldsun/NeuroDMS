package httpapi

// 凭证中心（docs/47 §4.4）。
//
// 五个端点都只做"取参 → 调 store → 组装响应"：
// 校验（必填、未知字段、密钥通道）在 integrations 包内，
// 这样命令行与后台任务用同一套规则，不会出现"界面能存、脚本存不了"。

import (
	"errors"
	"net/http"
	"strings"

	"docvault/internal/integrations"
	"docvault/internal/rbac"
)

func (a *API) registerIntegrations(mux *http.ServeMux) {
	// 能力域目录：哪些能在这里配、哪些有专用页、哪些还没接入
	mux.HandleFunc("GET /v1/admin/integrations/kinds",
		a.requireRole(rbac.SysAdmin)(a.handleIntegrationKinds))
	// 能力域与 provider 描述：前端据此渲染表单（字段级 schema）
	mux.HandleFunc("GET /v1/admin/integrations/{kind}/providers",
		a.requireRole(rbac.SysAdmin)(a.handleIntegrationProviders))
	// 已保存的配置列表（不含密钥）
	mux.HandleFunc("GET /v1/admin/integrations",
		a.requireRole(rbac.SysAdmin)(a.handleIntegrationList))
	mux.HandleFunc("PUT /v1/admin/integrations/{kind}/{provider}",
		a.requireRole(rbac.SysAdmin)(a.handleIntegrationSave))
	mux.HandleFunc("POST /v1/admin/integrations/{kind}/{provider}/test",
		a.requireRole(rbac.SysAdmin)(a.handleIntegrationTest))
	mux.HandleFunc("POST /v1/admin/integrations/{kind}/{provider}/activate",
		a.requireRole(rbac.SysAdmin)(a.handleIntegrationActivate))
	mux.HandleFunc("DELETE /v1/admin/integrations/{kind}/{provider}",
		a.requireRole(rbac.SysAdmin)(a.handleIntegrationDelete))
}

func (a *API) integrationStore(w http.ResponseWriter, r *http.Request) (*integrations.Store, bool) {
	if a.Integrations == nil {
		writeErr(w, r, http.StatusServiceUnavailable, "INTEGRATIONS_UNAVAILABLE",
			"凭证中心未启用（服务未装配）")
		return nil, false
	}
	return a.Integrations, true
}

func (a *API) handleIntegrationKinds(w http.ResponseWriter, r *http.Request) {
	items := integrations.Catalog()
	writeOK(w, r, map[string]any{"items": items, "count": len(items)})
}

func (a *API) handleIntegrationProviders(w http.ResponseWriter, r *http.Request) {
	st, ok := a.integrationStore(w, r)
	if !ok {
		return
	}
	kind := strings.TrimSpace(r.PathValue("kind"))
	items := st.Registry().ByKind(kind)
	writeOK(w, r, map[string]any{
		"kind":   kind,
		"status": integrations.KindStatus(kind),
		"items":  items,
		"count":  len(items),
		// 没有加密密钥时前端要提前提示"密钥字段无法保存"，
		// 而不是让管理员填完一屏再报错。
		"secretAvailable": st.Available(),
	})
}

func (a *API) handleIntegrationList(w http.ResponseWriter, r *http.Request) {
	st, ok := a.integrationStore(w, r)
	if !ok {
		return
	}
	c, _ := claimsFrom(r.Context())
	kind := strings.TrimSpace(r.URL.Query().Get("kind"))
	if kind == "" {
		writeErr(w, r, http.StatusBadRequest, "INVALID_ARGUMENT", "kind 必填")
		return
	}
	items, err := st.List(r.Context(), c.TenantID, kind)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "读取凭证失败")
		return
	}
	// platformFallback 只对 sms 有意义：租户没配通道时系统会走平台默认通道，
	// 只显示租户配置会让人误判"短信不可用"（实测发生过：四家全"未配置"但能发）。
	out := map[string]any{
		"kind": kind, "items": items, "count": len(items),
		"secretAvailable": st.Available(),
		"providers":       st.Registry().ByKind(kind),
	}
	if kind == "sms" && a.SMS != nil {
		out["platformFallback"] = a.SMS.PlatformReady()
	}
	writeOK(w, r, out)
}

func (a *API) handleIntegrationSave(w http.ResponseWriter, r *http.Request) {
	st, ok := a.integrationStore(w, r)
	if !ok {
		return
	}
	c, _ := claimsFrom(r.Context())
	kind, provider := strings.TrimSpace(r.PathValue("kind")), strings.TrimSpace(r.PathValue("provider"))

	// 只有 available 的能力域能在这里写：external 有专用页面（两处事实会打架），
	// planned 后端没接管（存了也不生效，属于假开关）。
	if st := integrations.KindStatus(kind); st != integrations.KindAvailable {
		writeErr(w, r, http.StatusBadRequest, "KIND_NOT_CONFIGURABLE",
			"该能力域不在凭证中心配置（邮件/目录请用专用页面，SSO/存储等尚未接入）")
		return
	}

	var req struct {
		Config  map[string]string `json:"config"`
		Secrets map[string]string `json:"secrets"`
		Active  bool              `json:"active"`
	}
	if !decode(w, r, &req) {
		return
	}

	// 先读旧值：审计要记"改前/改后"，密钥只记是否更换。
	before, berr := st.Get(r.Context(), c.TenantID, kind, provider)
	hadBefore := berr == nil
	if berr != nil && !errors.Is(berr, integrations.ErrNotFound) {
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "读取原配置失败")
		return
	}

	saved, err := st.Save(r.Context(), c.TenantID, c.Subject, integrations.Settings{
		Kind: kind, Provider: provider, Config: req.Config, Secrets: req.Secrets, Active: req.Active,
	})
	if err != nil {
		switch {
		case errors.Is(err, integrations.ErrUnknownProvider):
			writeErr(w, r, http.StatusBadRequest, "UNKNOWN_PROVIDER", "未知的通道")
		case errors.Is(err, integrations.ErrNoSecretKey):
			writeErr(w, r, http.StatusServiceUnavailable, "SECRET_KEY_MISSING",
				"服务端未配置 DOCVAULT_SECRET_KEY，无法加密保存密钥")
		case errors.Is(err, integrations.ErrInvalidInput):
			writeErr(w, r, http.StatusBadRequest, "INVALID_ARGUMENT", err.Error())
		default:
			writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "保存凭证失败")
		}
		return
	}

	// 审计：非密字段记改前/改后；密钥只记"是否更换"，绝不记值。
	diff := auditDiff(anyMap(before.Config), anyMap(saved.Config))
	secretChanged := map[string]bool{}
	for k := range req.Secrets {
		if req.Secrets[k] != "" {
			secretChanged[k] = true
		}
	}
	detail := map[string]any{
		"kind": kind, "provider": provider, "active": saved.Active,
		"secretChanged": secretChanged,
	}
	for k, v := range diff {
		detail[k] = v
	}
	if !hadBefore {
		detail["created"] = true
	}
	// provider 编码不是 uuid（审计表 object_id 是 uuid 列）：
	// 传进去会让 INSERT 失败，而调用方忽略错误 → 凭证变更**没有审计**。
	a.emitLogged(r, c.TenantID, AuditEntry{
		ActorID: c.Subject, Action: "admin.integration.save",
		ObjectType: kind, Result: "ok", Detail: detail,
	})

	writeOK(w, r, map[string]any{"settings": saved, "changed": len(diff) > 0 || len(secretChanged) > 0})
}

func (a *API) handleIntegrationTest(w http.ResponseWriter, r *http.Request) {
	st, ok := a.integrationStore(w, r)
	if !ok {
		return
	}
	c, _ := claimsFrom(r.Context())
	kind, provider := strings.TrimSpace(r.PathValue("kind")), strings.TrimSpace(r.PathValue("provider"))

	res, err := st.Test(r.Context(), c.TenantID, kind, provider)
	if err != nil {
		if errors.Is(err, integrations.ErrNotFound) {
			writeErr(w, r, http.StatusNotFound, "NOT_FOUND", "请先保存配置再测试")
			return
		}
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "测试失败")
		return
	}
	// 自检结果进审计：换通道时"当时测没测、通没通"是排障的第一手证据。
	a.emitLogged(r, c.TenantID, AuditEntry{
		ActorID: c.Subject, Action: "admin.integration.test",
		ObjectType: kind, Result: boolResult(res.OK),
		Detail: map[string]any{"provider": provider, "code": res.Code, "message": res.Message},
	})
	writeOK(w, r, map[string]any{
		"ok": res.OK, "code": res.Code, "message": res.Message,
		"at": res.At,
		// 分类码给前端做"下一步做什么"的提示，不要按 message 匹配
		"hint": integrationHint(res.Code),
	})
}

func (a *API) handleIntegrationActivate(w http.ResponseWriter, r *http.Request) {
	st, ok := a.integrationStore(w, r)
	if !ok {
		return
	}
	c, _ := claimsFrom(r.Context())
	kind, provider := strings.TrimSpace(r.PathValue("kind")), strings.TrimSpace(r.PathValue("provider"))
	if err := st.Activate(r.Context(), c.TenantID, kind, provider); err != nil {
		if errors.Is(err, integrations.ErrNotFound) {
			writeErr(w, r, http.StatusNotFound, "NOT_FOUND", "配置不存在")
			return
		}
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "切换失败")
		return
	}
	a.emitLogged(r, c.TenantID, AuditEntry{
		ActorID: c.Subject, Action: "admin.integration.activate",
		ObjectType: kind, Result: "ok", Detail: map[string]any{"kind": kind, "provider": provider},
	})
	writeOK(w, r, map[string]any{"kind": kind, "provider": provider, "active": true})
}

func (a *API) handleIntegrationDelete(w http.ResponseWriter, r *http.Request) {
	st, ok := a.integrationStore(w, r)
	if !ok {
		return
	}
	c, _ := claimsFrom(r.Context())
	kind, provider := strings.TrimSpace(r.PathValue("kind")), strings.TrimSpace(r.PathValue("provider"))
	if err := st.Delete(r.Context(), c.TenantID, kind, provider); err != nil {
		if errors.Is(err, integrations.ErrNotFound) {
			writeErr(w, r, http.StatusNotFound, "NOT_FOUND", "配置不存在")
			return
		}
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "删除失败")
		return
	}
	a.emitLogged(r, c.TenantID, AuditEntry{
		ActorID: c.Subject, Action: "admin.integration.delete",
		ObjectType: kind, Result: "ok", Detail: map[string]any{"provider": provider},
	})
	writeOK(w, r, map[string]any{"kind": kind, "provider": provider, "removed": true})
}

// integrationHint 把分类码翻译成"下一步做什么"。
func integrationHint(code string) string {
	switch code {
	case integrations.CodeOK:
		return ""
	case integrations.CodeAuthFailed:
		return "密钥无效或已禁用：请核对 AccessKey/SecretKey，并确认该账号已开通短信服务。"
	case integrations.CodeTemplateMissing:
		return "模板不存在或未审核：请确认模板 ID，且模板中第 1 个变量用于验证码。"
	case integrations.CodeSignMissing:
		return "签名未报备或不匹配：请确认签名名称与模板类型一致。"
	case integrations.CodeQuota:
		return "余量不足或被限流：请检查套餐余额与频控设置。"
	case integrations.CodeNetwork:
		return "网络不可达：本地部署请确认服务器能出网，或检查厂商 IP 白名单。"
	case integrations.CodeNotConfigured:
		return "配置不完整：请补齐必填项后重试。"
	default:
		return "自检未通过，详细原因已写入服务端日志（含诊断信息，不含密钥）。"
	}
}

// boolResult 把自检结果转成审计的 result 字段（ok / denied）。
func boolResult(ok bool) string {
	if ok {
		return "ok"
	}
	return "denied"
}

// anyMap 把 map[string]string 转成 auditDiff 需要的 map[string]any。
func anyMap(m map[string]string) map[string]any {
	if len(m) == 0 {
		return nil
	}
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}
