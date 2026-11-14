package httpapi

import (
	"context"
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"docvault/internal/rbac"
	"docvault/internal/tenant"
)

// registerBranding 注册租户级配置（品牌/策略）、租户自查用量与开关读取。
func (a *API) registerBranding(mux *http.ServeMux) {
	// 租户管理台（需要系统管理员）
	mux.HandleFunc("GET /v1/admin/branding", a.requireRole(rbac.SysAdmin)(a.handleGetBranding))
	mux.HandleFunc("PUT /v1/admin/branding", a.requireRole(rbac.SysAdmin)(a.handlePutBranding))
	mux.HandleFunc("GET /v1/admin/policy", a.requireRole(rbac.SysAdmin)(a.handleGetPolicy))
	mux.HandleFunc("PUT /v1/admin/policy", a.requireRole(rbac.SysAdmin)(a.handlePutPolicy))
	mux.HandleFunc("GET /v1/admin/usage", a.requireRole(rbac.SysAdmin)(a.handleSelfUsage))

	// 登录用户都能读自己的开关（界面据此决定显示什么）。
	// 必须包 requireAuth：漏了它会拿不到租户上下文，开关求值直接失败，
	// 表现为"接口 200 但永远是空列表"——比报错更难发现。
	mux.HandleFunc("GET /v1/features", a.requireAuth(a.handleFeatures))

	// 公开：登录页与分享页在**未登录**状态就要拿到品牌
	mux.HandleFunc("GET /v1/tenant/branding", a.handlePublicBranding)
	mux.HandleFunc("GET /v1/tenant/branding/logo", a.handlePublicLogo)
}

// ---------------- 品牌（租户侧） ----------------

func (a *API) handleGetBranding(w http.ResponseWriter, r *http.Request) {
	c, _ := claimsFrom(r.Context())
	slug, err := a.Tenants.SlugOf(r.Context(), c.TenantID)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "读取租户标识失败")
		return
	}
	b, err := a.Tenants.BrandingBySlug(r.Context(), slug)
	if err != nil {
		if errors.Is(err, tenant.ErrNotFound) {
			writeErr(w, r, http.StatusNotFound, "NOT_FOUND", "租户不存在")
			return
		}
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "读取品牌失败")
		return
	}
	writeOK(w, r, brandingView(b, slug))
}

func (a *API) handlePutBranding(w http.ResponseWriter, r *http.Request) {
	c, _ := claimsFrom(r.Context())
	var req struct {
		tenant.BrandingInput
		// LogoBase64 用字符串接收（浏览器端用 FileReader 拿到的就是 base64）
		LogoBase64 string `json:"logoBase64"`
	}
	if !decode(w, r, &req) {
		return
	}
	if req.LogoBase64 != "" {
		raw, err := base64.StdEncoding.DecodeString(stripDataURL(req.LogoBase64))
		if err != nil {
			writeErr(w, r, http.StatusBadRequest, "INVALID_ARGUMENT", "Logo 不是合法 base64")
			return
		}
		req.Logo = raw
	}
	// 改前值必须在 Update 之前读：Update 之后库里已经是新值，
	// 再"读旧值"只会读到新值，审计就变成两侧相同的假对照。
	beforeBrand := a.brandingSnapshot(r.Context(), c.TenantID)
	if err := a.Tenants.UpdateBranding(r.Context(), c.TenantID, req.BrandingInput); err != nil {
		if errors.Is(err, tenant.ErrInvalidInput) {
			writeErr(w, r, http.StatusBadRequest, "INVALID_ARGUMENT", err.Error())
			return
		}
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "保存品牌失败")
		return
	}

	// 品牌是"所有分享页都会变"的配置，必须留痕且能追到人。
	// 记改动前后：只记"改过"回答不了"改成什么了"，而品牌名会印在
	// 邮件主题与分享页页眉上，事后追查时需要精确值。
	detail := auditDiff(beforeBrand, map[string]any{
		"productName":  req.ProductName,
		"primaryColor": req.PrimaryColor,
		"accentColor":  req.AccentColor,
		"footerText":   req.FooterText,
		"privacyUrl":   req.PrivacyURL,
	})
	if len(req.Logo) > 0 {
		// Logo 是二进制，不放进 before/after（会撑爆审计行），只记"换了"
		detail["logoChanged"] = true
	}
	if err := a.emit(r, c.TenantID, AuditEntry{
		ActorID: c.Subject, Action: "tenant.branding.update", Result: "ok",
		Detail: detail,
	}); err != nil {
		writeErr(w, r, http.StatusInternalServerError, "AUDIT_FAILED", "审计写入失败，配置未生效")
		return
	}

	slug, _ := a.Tenants.SlugOf(r.Context(), c.TenantID)
	b, _ := a.Tenants.BrandingBySlug(r.Context(), slug)
	writeOK(w, r, brandingView(b, slug))
}

// stripDataURL 去掉 "data:image/png;base64," 前缀。
// 前端图省事直接给 dataURL 是常态，后端不该因此报 400。
func stripDataURL(s string) string {
	if i := strings.Index(s, ","); strings.HasPrefix(s, "data:") && i > 0 {
		return s[i+1:]
	}
	return s
}

// brandingSnapshot 取品牌里"可修改且会被展示"的几个字段，用于审计前后对照。
//
// 读失败返回 nil：审计会退化成"只有新值"，但配置保存本身不受影响——
// 不能因为审计取不到旧值就把一次正常的配置变更拒掉。
func (a *API) brandingSnapshot(ctx context.Context, tenantID string) map[string]any {
	if a.Tenants == nil {
		return nil
	}
	slug, err := a.Tenants.SlugOf(ctx, tenantID)
	if err != nil {
		return nil
	}
	b, err := a.Tenants.BrandingBySlug(ctx, slug)
	if err != nil {
		return nil
	}
	return map[string]any{
		"productName":  b.ProductName,
		"primaryColor": b.PrimaryColor,
		"accentColor":  b.AccentColor,
		"footerText":   b.FooterText,
		"privacyUrl":   b.PrivacyURL,
	}
}

// ---------------- 策略 ----------------

func (a *API) handleGetPolicy(w http.ResponseWriter, r *http.Request) {
	c, _ := claimsFrom(r.Context())
	p, err := a.Tenants.GetPolicy(r.Context(), c.TenantID)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "读取策略失败")
		return
	}
	writeOK(w, r, p)
}

func (a *API) handlePutPolicy(w http.ResponseWriter, r *http.Request) {
	c, _ := claimsFrom(r.Context())
	var p tenant.Policy
	if !decode(w, r, &p) {
		return
	}
	before, _ := a.Tenants.GetPolicy(r.Context(), c.TenantID)
	effective, err := a.Tenants.SetPolicy(r.Context(), c.TenantID, p)
	if err != nil {
		if errors.Is(err, tenant.ErrInvalidInput) {
			writeErr(w, r, http.StatusBadRequest, "INVALID_ARGUMENT", err.Error())
			return
		}
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "保存策略失败")
		return
	}
	p = effective
	// 策略是"最容易在事后被质疑"的一组参数（上传上限、日志保留期），
	// 必须能回答"谁在几号把它从多少改成了多少"。
	// 两侧都换成生效值：SetPolicy 会把 0 落成默认值，
	// 直接比 0 与 10 会把"原样保存"记成一次变更。
	oldMap, newMap := jsonMap(before.WithDefaults()), jsonMap(p.WithDefaults())
	// allowedExts 带 omitempty：清空白名单时键会消失，两侧都补成 [] 才能比对出变化
	for _, m := range []map[string]any{oldMap, newMap} {
		if m != nil {
			if _, ok := m["allowedExts"]; !ok {
				m["allowedExts"] = []string{}
			}
		}
	}
	_ = a.emit(r, c.TenantID, AuditEntry{
		ActorID: c.Subject, Action: "tenant.policy.update", Result: "ok",
		Detail: auditDiff(oldMap, newMap),
	})
	writeOK(w, r, p)
}

// ---------------- 租户自查用量 ----------------

func (a *API) handleSelfUsage(w http.ResponseWriter, r *http.Request) {
	c, _ := claimsFrom(r.Context())
	st, err := a.Metering.LoadState(r.Context(), c.TenantID)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "读取用量失败")
		return
	}
	month := r.URL.Query().Get("month")
	totals := map[string]int64{}
	if month != "" {
		totals, _ = a.Metering.MonthTotals(r.Context(), c.TenantID, month)
	}
	writeOK(w, r, map[string]any{
		"state": st, "month": month, "monthTotals": totals,
		"exceeded": st.Exceeded(),
	})
}

// ---------------- 灰度开关（租户侧读取） ----------------

func (a *API) handleFeatures(w http.ResponseWriter, r *http.Request) {
	c, _ := claimsFrom(r.Context())
	eff, err := a.Features.Effective(r.Context(), c.TenantID)
	if err != nil {
		// 开关读不到时返回全空：前端会按"未开启"处理，功能少一块但不会误显示
		writeOK(w, r, map[string]any{"items": []any{}})
		return
	}
	writeOK(w, r, map[string]any{"items": eff})
}

// ---------------- 公开品牌 ----------------

func brandingView(b tenant.Branding, slug string) map[string]any {
	v := map[string]any{
		"slug": b.Slug, "tenantName": b.TenantName, "status": b.Status,
		"productName": b.ProductName, "primaryColor": b.PrimaryColor,
		"accentColor": b.AccentColor, "footerText": b.FooterText,
		"privacyUrl": b.PrivacyURL,
		"updatedAt":  b.UpdatedAt.UTC().Format(time.RFC3339),
	}
	if slug == "" {
		slug = b.Slug
	}
	if len(b.Logo) > 0 {
		v["logoUrl"] = "/v1/tenant/branding/logo?slug=" + slug + "&v=" + b.LogoSHA()
		v["logoMime"] = b.LogoMime
	}
	return v
}

// handlePublicBranding 按 slug 或 Host 返回品牌。
//
// 先后顺序：显式 slug 优先于 Host。
// 理由：分享链接里带的是 slug，而 Host 可能只是"某个反代域名"，
// 用 Host 覆盖显式参数会让分享页显示错误的品牌。
func (a *API) handlePublicBranding(w http.ResponseWriter, r *http.Request) {
	slug := r.URL.Query().Get("slug")
	var (
		b   tenant.Branding
		err error
	)
	if slug != "" {
		b, err = a.Tenants.BrandingBySlug(r.Context(), slug)
	} else {
		b, err = a.Tenants.BrandingByHost(r.Context(), r.Host)
	}
	if err != nil {
		if errors.Is(err, tenant.ErrNotFound) {
			writeErr(w, r, http.StatusNotFound, "NOT_FOUND", "租户不存在")
			return
		}
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "读取品牌失败")
		return
	}
	// 停用/删除的租户不展示品牌：否则分享页看起来"还在正常服务"
	if b.Status == tenant.StatusSuspended || b.Status == tenant.StatusDeleted {
		writeErr(w, r, http.StatusNotFound, "NOT_FOUND", "租户不可用")
		return
	}
	w.Header().Set("Cache-Control", "public, max-age=60")
	writeOK(w, r, brandingView(b, slug))
}

func (a *API) handlePublicLogo(w http.ResponseWriter, r *http.Request) {
	slug := r.URL.Query().Get("slug")
	var (
		b   tenant.Branding
		err error
	)
	if slug != "" {
		b, err = a.Tenants.BrandingBySlug(r.Context(), slug)
	} else {
		b, err = a.Tenants.BrandingByHost(r.Context(), r.Host)
	}
	if err != nil || len(b.Logo) == 0 {
		http.NotFound(w, r)
		return
	}
	mime := b.LogoMime
	if mime == "" {
		mime = "image/png"
	}
	w.Header().Set("Content-Type", mime)
	w.Header().Set("Content-Length", strconv.Itoa(len(b.Logo)))
	// 品牌 Logo 会出现在未登录的登录页：不允许被当成脚本执行
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; sandbox")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "public, max-age=300")
	_, _ = w.Write(b.Logo)
}

// ---------------- DNS ----------------

// lookupTXT 是 net.LookupTXT 的可替换包装（测试里注入假结果）。
func (a *API) lookupTXT(ctx context.Context, name string) ([]string, error) {
	if a.LookupTXT != nil {
		return a.LookupTXT(ctx, name)
	}
	res := &net.Resolver{}
	c, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return res.LookupTXT(c, name)
}
