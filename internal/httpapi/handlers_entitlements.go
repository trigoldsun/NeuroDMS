package httpapi

// 能力授权（docs/47 §4.1–4.7）。
//
// 这一层只做两件事：
//  1. 把"授权 / 自管 / 资源就绪"三层合成一个可解释的结论（五态）；
//  2. 给运营台提供按租户改单项授权的接口。
//
// 五个状态必须分开返回，因为它们是**不同的故障**：
//   没买（entitled=false）   → 销售能答"升级或加购"
//   平台关了（source=locked）→ 客服能答"合规下线，不是你的问题"
//   自己关了（enabled=false）→ 管理员能自己开
//   没配资源（configured=false）→ 实施能去配通道
// 只给一个布尔值时，这四种情况在界面上长得一模一样。

import (
	"context"
	"errors"
	"net/http"
	"time"

	"docvault/internal/edition"
	"docvault/internal/entitlement"
	"docvault/internal/platformauth"
)

// capability 是 /v1/me/capabilities 里的一项。
type capability struct {
	// Entitled 授权层：这个租户买没买。
	Entitled bool `json:"entitled"`
	// Enabled 自管层：买了之后租户自己开没开。
	Enabled bool `json:"enabled"`
	// Configured 资源层：通道/证书/IdP 是否就绪。
	Configured bool `json:"configured"`
	// Usable 三者相与：此刻能不能用。前端只应据此显示入口。
	Usable bool `json:"usable"`
	// Source: plan | grant | locked | expired
	Source string `json:"source"`
	// Reason 是可直接展示的原因码（见下方常量）。
	Reason    string `json:"reason,omitempty"`
	ExpiresAt string `json:"expiresAt,omitempty"`
}

// 原因码。前端按码给文案，不要按中文串匹配。
const (
	reasonPlanExcluded    = "plan_excluded"    // 档位不含，可升级/加购
	reasonPlatformLocked  = "platform_locked"  // 平台强制关闭
	reasonGrantExpired    = "grant_expired"    // 特批到期
	reasonTenantDisabled  = "tenant_disabled"  // 本组织未启用
	reasonResourceMissing = "resource_missing" // 通道/证书未配置
)

// capabilitiesOf 解算某租户的全部能力。
func (a *API) capabilitiesOf(ctx context.Context, tenantID string) (map[string]capability, error) {
	st, err := a.editionState(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	if a.Entitlements == nil {
		return nil, errors.New("授权服务未装配")
	}
	vals, err := a.Entitlements.Resolve(ctx, tenantID, st.Edition)
	if err != nil {
		return nil, err
	}
	pol, perr := a.tenantPolicy(ctx, tenantID)
	if perr != nil {
		return nil, perr
	}

	self := map[string]bool{
		entitlement.UploadFolder: pol.FolderUpload,
		entitlement.SMSLogin:     pol.SmsLogin,
	}
	ready := a.resourceReady(ctx, tenantID)

	out := make(map[string]capability, len(vals))
	for code, v := range vals {
		c := capability{
			Entitled:   v.Entitled,
			Enabled:    true,
			Configured: true,
			Source:     v.Source,
		}
		if on, ok := self[code]; ok {
			c.Enabled = on
		}
		if rd, ok := ready[code]; ok {
			c.Configured = rd
		}
		c.Usable = c.Entitled && c.Enabled && c.Configured

		switch {
		case !c.Entitled && v.Source == entitlement.SourceLocked:
			c.Reason = reasonPlatformLocked
		case !c.Entitled && v.Source == entitlement.SourceExpired:
			c.Reason = reasonGrantExpired
		case !c.Entitled:
			c.Reason = reasonPlanExcluded
		case !c.Enabled:
			c.Reason = reasonTenantDisabled
		case !c.Configured:
			c.Reason = reasonResourceMissing
		}
		if v.ExpiresAt != nil {
			c.ExpiresAt = v.ExpiresAt.UTC().Format(time.RFC3339)
		}
		out[code] = c
	}
	return out, nil
}

// resourceReady 汇总"这个部署的通道就绪状态"。
//
// 这是 capabilities 的第三层，之前只有 SMSConfigured 一个布尔到处用，
// 于是"档位允许但通道没配"与"能正常用"在界面上无法区分。
func (a *API) resourceReady(ctx context.Context, tenantID string) map[string]bool {
	return map[string]bool{
		// 短信：租户自带通道优先，否则平台通道；两者都读不到算未就绪
		entitlement.SMSLogin: a.smsReady(ctx, tenantID),
		// 邮件：平台默认通道或租户自有通道，任一存在即可
		entitlement.MailOutbound:     a.Outbox != nil || a.Mail != nil,
		entitlement.ShareEmailVerify: a.Outbox != nil || a.Mail != nil,
		// 目录：装配了 Store 才能配
		entitlement.DirAuth: a.Directory != nil,
		// 在线编辑：OnlyOffice 未装配时不可用
		entitlement.EditOnline: a.Office != nil,
		// SSO：部署前提
		entitlement.SSO: a.SSO != nil && a.SSO.Enabled,
		// 转码：未启用时不提示"已就绪"
		entitlement.MediaTranscode: a.Media != nil,
		// 域名：绑定本身不需要密钥；证书那一步会单独提示
		entitlement.CustomDomain: true,
	}
}

// smsReady 判断该租户此刻是否有可用的短信通道。
//
// 装配了 Service（生产）就以它为准：先看租户自己的集成配置，再看平台环境变量。
// 没装配（单测）时才回落到静态布尔。
func (a *API) smsReady(ctx context.Context, tenantID string) bool {
	if a.SMS != nil {
		return a.SMS.Configured(ctx, tenantID)
	}
	return a.SMSConfigured
}

// entitled 只回答授权层，读失败返回 error。
//
// 调用方必须把 error 映射成 503 而不是"没有该能力"：读不到授权与"没买"
// 是两件事，前端要显示的文案也不同。
func (a *API) entitled(ctx context.Context, tenantID, code string) (bool, error) {
	if a.Entitlements == nil {
		return false, errors.New("授权服务未装配")
	}
	st, err := a.editionState(ctx, tenantID)
	if err != nil {
		return false, err
	}
	return a.Entitlements.Entitled(ctx, tenantID, code, st.Edition)
}

// entitlementDenyMessage 给出拒绝时的中文说明，运营/客服可直接转述。
func entitlementDenyMessage(v entitlement.Value, name string) string {
	switch v.Source {
	case entitlement.SourceLocked:
		if v.Reason != "" {
			return "平台已关闭「" + name + "」：" + v.Reason
		}
		return "平台已关闭「" + name + "」"
	case entitlement.SourceExpired:
		return "「" + name + "」的加购授权已到期，请联系运营续订"
	default:
		return "当前档位不含「" + name + "」，可升级或单独加购"
	}
}

// entitlementValue 读取单条授权结论（含原因），供拒绝文案使用。
func (a *API) entitlementValue(ctx context.Context, tenantID, code string) (entitlement.Value, error) {
	if a.Entitlements == nil {
		return entitlement.Value{}, errors.New("授权服务未装配")
	}
	st, err := a.editionState(ctx, tenantID)
	if err != nil {
		return entitlement.Value{}, err
	}
	all, err := a.Entitlements.Resolve(ctx, tenantID, st.Edition)
	if err != nil {
		return entitlement.Value{}, err
	}
	v, ok := all[code]
	if !ok {
		return entitlement.Value{}, entitlement.ErrUnknownCode
	}
	return v, nil
}

// ---------------- 平台运营台 ----------------

func (a *API) registerPlatformEntitlements(mux *http.ServeMux) {
	// 能力定义（三档默认，只读）：给运营台渲染表头与说明
	mux.HandleFunc("GET /v1/platform/entitlements", a.requirePlatform(a.handlePlatformEntitlementDefs))
	// 单租户能力矩阵
	mux.HandleFunc("GET /v1/platform/tenants/{slug}/entitlements",
		a.requirePlatform(a.handlePlatformEntitlementList))
	// 单项授权（inherit / on / off）
	mux.HandleFunc("PUT /v1/platform/tenants/{slug}/entitlements/{code}",
		a.requirePlatformWrite(a.handlePlatformEntitlementPut))
	// 全局强制关（合规下线）
	mux.HandleFunc("POST /v1/platform/entitlements/{code}/lock",
		a.requirePlatformWrite(a.handlePlatformEntitlementLock))
}

func (a *API) handlePlatformEntitlementDefs(w http.ResponseWriter, r *http.Request) {
	if a.Entitlements == nil {
		writeErr(w, r, http.StatusServiceUnavailable, "ENTITLEMENT_UNAVAILABLE", "授权服务未启用")
		return
	}
	// 用一个必然存在的租户也能读到定义，但更干净的是直接读表。
	// 这里复用 List 会引入租户依赖，故定义单独走一张全局表。
	items, err := a.Entitlements.Defs(r.Context())
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "读取能力定义失败")
		return
	}
	writeOK(w, r, map[string]any{"items": items, "count": len(items)})
}

func (a *API) handlePlatformEntitlementList(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("slug")
	if a.Entitlements == nil {
		writeErr(w, r, http.StatusServiceUnavailable, "ENTITLEMENT_UNAVAILABLE", "授权服务未启用")
		return
	}
	items, err := a.Entitlements.List(r.Context(), slug)
	if err != nil {
		if errors.Is(err, entitlement.ErrNotFound) {
			writeErr(w, r, http.StatusNotFound, "NOT_FOUND", "租户不存在")
			return
		}
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "读取能力授权失败")
		return
	}
	// 生效档位一起返回：运营要看到"这行是档位给的，还是特批给的"
	var ed string
	if st, eerr := a.platformEditionState(r.Context(), slug); eerr == nil {
		ed = string(st.Edition)
	}
	writeOK(w, r, map[string]any{"items": items, "count": len(items), "edition": ed})
}

func (a *API) handlePlatformEntitlementPut(w http.ResponseWriter, r *http.Request) {
	slug, code := r.PathValue("slug"), r.PathValue("code")
	var req struct {
		State  string `json:"state"`
		Reason string `json:"reason"`
		// 省略/null → on 默认 90 天、off 默认长期；
		// "never" → 显式长期（合同内买断）；RFC3339 → 指定到期。
		ExpiresAt *string `json:"expiresAt"`
	}
	if !decode(w, r, &req) {
		return
	}
	if a.Entitlements == nil {
		writeErr(w, r, http.StatusServiceUnavailable, "ENTITLEMENT_UNAVAILABLE", "授权服务未启用")
		return
	}

	// 归一化三态：`default` 是历史别名，等同于 inherit（见 entitlement.NormalizeState）。
	// GET 与 PUT 现在都用 "inherit"，读写两侧同一个词。
	state := entitlement.NormalizeState(req.State)
	var expires *time.Time
	switch state {
	case entitlement.StateInherit:
		// 删行，回到档位默认；带到期没有意义，忽略
	case "on", "off":
		if req.ExpiresAt != nil {
			if *req.ExpiresAt == "never" {
				expires = nil
			} else if *req.ExpiresAt != "" {
				t, err := time.Parse(time.RFC3339, *req.ExpiresAt)
				if err != nil {
					writeErr(w, r, http.StatusBadRequest, "INVALID_ARGUMENT",
						"到期时间需为 RFC3339 或 never")
					return
				}
				expires = &t
			}
		}
		// 开通型特批默认 90 天：不给"忘了设到期"留下永久白送的入口。
		if state == "on" && req.ExpiresAt == nil {
			t := time.Now().AddDate(0, 0, 90)
			expires = &t
		}
	default:
		// 把合法值直接写在错误里：对接方不该靠读代码猜枚举。
		writeErr(w, r, http.StatusBadRequest, "INVALID_ARGUMENT",
			`state 只能是 inherit（跟随档位，兼容别名 default）/ on / off，收到 "`+req.State+`"`)
		return
	}

	p, _ := platformFrom(r.Context())
	ch, err := a.Entitlements.Set(r.Context(), slug, code, state, req.Reason, expires, actorOf(p))
	if err != nil {
		switch {
		case errors.Is(err, entitlement.ErrNotFound):
			writeErr(w, r, http.StatusNotFound, "NOT_FOUND", "租户不存在")
		case errors.Is(err, entitlement.ErrInvalidState):
			writeErr(w, r, http.StatusBadRequest, "INVALID_ARGUMENT", err.Error())
		case errors.Is(err, entitlement.ErrUnknownCode):
			writeErr(w, r, http.StatusBadRequest, "INVALID_ARGUMENT", "未知能力编码")
		default:
			writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "保存授权失败")
		}
		return
	}

	// 审计记改前/改后，只留变化字段（docs/31 §9.1 的统一口径）。
	before := map[string]any{"state": ch.PrevState, "reason": ch.PrevReason}
	after := map[string]any{"state": ch.CurState, "reason": ch.CurReason}
	if ch.PrevExpires != nil {
		before["expiresAt"] = ch.PrevExpires.UTC().Format(time.RFC3339)
	}
	if ch.CurExpires != nil {
		after["expiresAt"] = ch.CurExpires.UTC().Format(time.RFC3339)
	}
	a.auditPlatform(r, p, "platform.entitlement.set", slug, "ok", map[string]any{
		"code":   code,
		"before": before,
		"after":  after,
	})

	writeOK(w, r, map[string]any{"code": code, "state": ch.CurState, "change": ch})
}

func (a *API) handlePlatformEntitlementLock(w http.ResponseWriter, r *http.Request) {
	code := r.PathValue("code")
	var req struct {
		Locked bool   `json:"locked"`
		Reason string `json:"reason"`
	}
	if !decode(w, r, &req) {
		return
	}
	if a.Entitlements == nil {
		writeErr(w, r, http.StatusServiceUnavailable, "ENTITLEMENT_UNAVAILABLE", "授权服务未启用")
		return
	}
	prev, cur, err := a.Entitlements.Lock(r.Context(), code, req.Locked, req.Reason)
	if err != nil {
		if errors.Is(err, entitlement.ErrUnknownCode) {
			writeErr(w, r, http.StatusBadRequest, "INVALID_ARGUMENT", "未知能力编码")
			return
		}
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "保存全局开关失败")
		return
	}
	p, _ := platformFrom(r.Context())
	a.auditPlatform(r, p, "platform.entitlement.lock", code, "ok", map[string]any{
		"before": map[string]any{"locked": prev},
		"after":  map[string]any{"locked": cur, "reason": req.Reason},
	})
	writeOK(w, r, map[string]any{"code": code, "locked": cur})
}

// classLevels 返回"该租户此刻允许写入的密级集合"。
//
// 与 edition.SelectableClasses 的差别只在一种情况：基础版客户**单项加购**了
// 密级能力。此时档位里没有可选集合，但他确实买了这个能力——给旗舰版全集，
// 否则会出现"买了密级功能，却只能写 0 级"，比没买更让人困惑。
//
// 第二个返回值是档位状态，调用方拿它拼提示文案（"当前档位（X）不支持"）。
func (a *API) classLevels(ctx context.Context, tenantID string) ([]int, edition.State, error) {
	st, err := a.editionState(ctx, tenantID)
	if err != nil {
		return nil, st, err
	}
	ok, err := a.entitled(ctx, tenantID, entitlement.Classification)
	if err != nil {
		return nil, st, err
	}
	if !ok {
		return nil, st, nil
	}
	levels := st.SelectableClasses()
	if len(levels) == 0 {
		levels = edition.SelectableFor(edition.Business)
	}
	return levels, st, nil
}

// levelAllowed 判断某密级是否可写。0 级永远可写：
// 上传不带密级时就是 0，若连 0 都拦，基础版连文件都传不上去。
func levelAllowed(levels []int, v int) bool {
	if v == 0 {
		return true
	}
	for _, x := range levels {
		if x == v {
			return true
		}
	}
	return false
}

// actorOf 取平台操作者标识（静态令牌也要留痕，不能写成空）。
func actorOf(p platformauth.Principal) string {
	if p.Static {
		return "static-token"
	}
	if p.Email != "" {
		return p.Email
	}
	return "unknown"
}

// platformEditionState 读某租户的**生效**档位（平台视角）。
//
// 必须走 edition.Resolve：库里声明的档位可能已过期，
// 运营台显示"旗舰版"而实际能力已按基础版算，是最容易吵架的一处不一致。
func (a *API) platformEditionState(ctx context.Context, slug string) (edition.State, error) {
	if a.Tenants == nil {
		return edition.State{}, errors.New("租户服务未装配")
	}
	info, err := a.Tenants.GetEdition(ctx, slug)
	if err != nil {
		return edition.State{}, err
	}
	return edition.Resolve(info.Edition, info.ExpiresAt, time.Now()), nil
}
