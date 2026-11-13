package httpapi

import (
	"context"
	"encoding/csv"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"docvault/internal/feature"
	"docvault/internal/platformauth"
	"docvault/internal/tenant"

	"github.com/jackc/pgx/v5"
)

// registerPlatformTenants 注册平台运营端点（租户生命周期、配额、用量、域名、开关）。
//
// 全部走 requirePlatform：静态令牌（应急）与平台账号会话都行，
// 但租户账号的令牌在这里一定不通过——两套令牌结构不同，无法互认。
func (a *API) registerPlatformTenants(mux *http.ServeMux) {
	// 认证
	mux.HandleFunc("POST /v1/platform/auth/login", a.handlePlatformLogin)
	mux.HandleFunc("POST /v1/platform/auth/logout", a.requirePlatform(a.handlePlatformLogout))
	mux.HandleFunc("GET /v1/platform/me", a.requirePlatform(a.handlePlatformMe))

	// 租户生命周期
	mux.HandleFunc("GET /v1/platform/tenants", a.requirePlatform(a.handlePlatformTenantList))
	mux.HandleFunc("POST /v1/platform/tenants", a.requirePlatformWrite(a.handlePlatformTenantCreate))
	mux.HandleFunc("GET /v1/platform/tenants/{slug}", a.requirePlatform(a.handlePlatformTenantGet))
	mux.HandleFunc("PATCH /v1/platform/tenants/{slug}", a.requirePlatformWrite(a.handlePlatformTenantPatch))
	mux.HandleFunc("DELETE /v1/platform/tenants/{slug}", a.requirePlatformWrite(a.handlePlatformTenantDelete))

	// 档位
	mux.HandleFunc("GET /v1/platform/tenants/{slug}/edition", a.requirePlatform(a.handlePlatformEditionGet))
	mux.HandleFunc("PUT /v1/platform/tenants/{slug}/edition", a.requirePlatformWrite(a.handlePlatformEditionPut))

	// 配额与用量
	mux.HandleFunc("GET /v1/platform/tenants/{slug}/quota", a.requirePlatform(a.handlePlatformQuotaGet))
	mux.HandleFunc("PUT /v1/platform/tenants/{slug}/quota", a.requirePlatformWrite(a.handlePlatformQuotaPut))
	mux.HandleFunc("GET /v1/platform/tenants/{slug}/usage", a.requirePlatform(a.handlePlatformUsage))
	mux.HandleFunc("GET /v1/platform/tenants/{slug}/invoice.csv", a.requirePlatform(a.handlePlatformInvoice))
	mux.HandleFunc("GET /v1/platform/usage/reconcile", a.requirePlatform(a.handlePlatformReconcile))

	// 域名与证书
	mux.HandleFunc("GET /v1/platform/tenants/{slug}/domains", a.requirePlatform(a.handlePlatformDomainList))
	mux.HandleFunc("POST /v1/platform/tenants/{slug}/domains", a.requirePlatformWrite(a.handlePlatformDomainAdd))
	mux.HandleFunc("DELETE /v1/platform/tenants/{slug}/domains/{host}", a.requirePlatformWrite(a.handlePlatformDomainDelete))
	mux.HandleFunc("POST /v1/platform/tenants/{slug}/domains/{host}/verify", a.requirePlatformWrite(a.handlePlatformDomainVerify))
	mux.HandleFunc("PUT /v1/platform/tenants/{slug}/domains/{host}/certificate", a.requirePlatformWrite(a.handlePlatformDomainCert))

	// 灰度开关
	mux.HandleFunc("GET /v1/platform/flags", a.requirePlatform(a.handlePlatformFlags))
	mux.HandleFunc("PUT /v1/platform/flags/{code}", a.requirePlatformWrite(a.handlePlatformFlagPut))
	mux.HandleFunc("GET /v1/platform/tenants/{slug}/flags", a.requirePlatform(a.handlePlatformTenantFlags))
	mux.HandleFunc("PUT /v1/platform/tenants/{slug}/flags/{code}", a.requirePlatformWrite(a.handlePlatformTenantFlagPut))
	mux.HandleFunc("DELETE /v1/platform/tenants/{slug}/flags/{code}", a.requirePlatformWrite(a.handlePlatformTenantFlagDelete))

	// 平台审计
	mux.HandleFunc("GET /v1/platform/audit", a.requirePlatform(a.handlePlatformAuditLog))
}

// requirePlatform 校验平台身份，把 Principal 放进请求上下文。
func (a *API) requirePlatform(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if a.PlatformAuth == nil {
			writeErr(w, r, http.StatusUnauthorized, "UNAUTHORIZED", "平台端点未启用")
			return
		}
		token := bearer(r)
		p, err := a.PlatformAuth.Authenticate(r.Context(), token, a.PlatformToken)
		if err != nil {
			writeErr(w, r, http.StatusUnauthorized, "UNAUTHORIZED", "平台令牌无效或已过期")
			return
		}
		next(w, r.WithContext(withPlatform(r.Context(), p)))
	}
}

// requirePlatformWrite 在 requirePlatform 之上要求可写角色。
//
// 只读角色（合规/支持人员）能看全部数据但不能改任何东西：
// 这是"能排查问题"与"能造成影响"之间最有用的一条分界线。
func (a *API) requirePlatformWrite(next http.HandlerFunc) http.HandlerFunc {
	return a.requirePlatform(func(w http.ResponseWriter, r *http.Request) {
		p, _ := platformFrom(r.Context())
		if !p.CanWrite() {
			a.auditPlatform(r, p, "platform.write_denied", r.URL.Path, "denied", nil)
			writeErr(w, r, http.StatusForbidden, "READONLY_ROLE", "当前平台账号为只读角色，不能执行变更")
			return
		}
		next(w, r)
	})
}

func bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if strings.HasPrefix(h, "Bearer ") {
		return strings.TrimSpace(h[len("Bearer "):])
	}
	return ""
}

type platformCtxKey struct{}

func withPlatform(ctx context.Context, p platformauth.Principal) context.Context {
	return context.WithValue(ctx, platformCtxKey{}, p)
}

func platformFrom(ctx context.Context) (platformauth.Principal, bool) {
	p, ok := ctx.Value(platformCtxKey{}).(platformauth.Principal)
	return p, ok
}

// auditPlatform 写平台审计。失败只记录到日志：平台操作"不做"比"记不上"更糟，
// 但调用方必须能知道审计没写成功（日志里能看到）。
func (a *API) auditPlatform(r *http.Request, p platformauth.Principal, action, target, result string, detail map[string]any) {
	if a.PlatformAuth == nil {
		return
	}
	actor := p.Email
	if actor == "" {
		actor = "unknown"
	}
	if p.Static {
		actor = "static-token"
	}
	if err := a.PlatformAuth.Audit(r.Context(), actor, action, target, result, detail, clientIP(r)); err != nil {
		a.logErr("平台审计写入失败", "action", action, "target", target, "err", err)
	}
}

// ---------------- 平台认证 ----------------

func (a *API) handlePlatformLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if !decode(w, r, &req) {
		return
	}
	token, p, expires, err := a.PlatformAuth.Login(r.Context(), req.Email, req.Password,
		clientIP(r), r.UserAgent())
	if err != nil {
		switch {
		case errors.Is(err, platformauth.ErrAccountDisabled):
			writeErr(w, r, http.StatusForbidden, "ACCOUNT_DISABLED", "平台账号已停用")
		case errors.Is(err, platformauth.ErrInvalidCredentials):
			writeErr(w, r, http.StatusUnauthorized, "INVALID_CREDENTIALS", "账号或口令不正确")
		default:
			writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "登录失败")
		}
		// 登录失败也留痕：平台面的暴力破解必须先在这里看得见
		a.auditPlatform(r, platformauth.Principal{Email: req.Email}, "platform.login", "", "denied",
			map[string]any{"reason": err.Error()})
		return
	}
	a.auditPlatform(r, p, "platform.login", "", "ok", nil)
	writeOK(w, r, map[string]any{
		"accessToken": token,
		"expiresAt":   expires.UTC().Format(time.RFC3339),
		"email":       p.Email,
		"role":        p.Role,
	})
}

func (a *API) handlePlatformLogout(w http.ResponseWriter, r *http.Request) {
	p, _ := platformFrom(r.Context())
	_ = a.PlatformAuth.Logout(r.Context(), bearer(r))
	a.auditPlatform(r, p, "platform.logout", "", "ok", nil)
	writeOK(w, r, map[string]any{"ok": true})
}

func (a *API) handlePlatformMe(w http.ResponseWriter, r *http.Request) {
	p, _ := platformFrom(r.Context())
	writeOK(w, r, map[string]any{
		"email": p.Email, "role": p.Role, "static": p.Static,
		"canWrite": p.CanWrite(),
	})
}

// ---------------- 租户生命周期 ----------------

func (a *API) handlePlatformTenantList(w http.ResponseWriter, r *http.Request) {
	list, err := a.Tenants.List(r.Context())
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "读取租户列表失败")
		return
	}
	writeOK(w, r, map[string]any{"items": list, "count": len(list)})
}

func (a *API) handlePlatformTenantCreate(w http.ResponseWriter, r *http.Request) {
	var in tenant.CreateInput
	if !decode(w, r, &in) {
		return
	}
	created, err := a.Tenants.Create(r.Context(), in)
	p, _ := platformFrom(r.Context())
	if err != nil {
		switch {
		case errors.Is(err, tenant.ErrSlugTaken):
			writeErr(w, r, http.StatusConflict, "SLUG_TAKEN", "租户标识已被占用")
		case errors.Is(err, tenant.ErrInvalidInput):
			writeErr(w, r, http.StatusBadRequest, "INVALID_ARGUMENT", err.Error())
		default:
			a.logErr("开通租户失败", "slug", in.Slug, "err", err)
			writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "开通租户失败")
		}
		a.auditPlatform(r, p, "platform.tenant.create", in.Slug, "error",
			map[string]any{"err": err.Error()})
		return
	}
	ed := in.Edition
	if strings.TrimSpace(ed) == "" {
		ed = "basic"
	}
	a.auditPlatform(r, p, "platform.tenant.create", created.Slug, "ok",
		map[string]any{"edition": ed, "editionExpiresAt": in.EditionExpiresAt,
			"trialDays": in.TrialDays, "admin": in.AdminUsername})
	writeOK(w, r, created)
}

func (a *API) handlePlatformTenantGet(w http.ResponseWriter, r *http.Request) {
	t, err := a.Tenants.Get(r.Context(), r.PathValue("slug"))
	if err != nil {
		if errors.Is(err, tenant.ErrNotFound) {
			writeErr(w, r, http.StatusNotFound, "NOT_FOUND", "租户不存在")
			return
		}
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "读取租户失败")
		return
	}
	writeOK(w, r, t)
}

func (a *API) handlePlatformTenantPatch(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("slug")
	var req struct {
		Status *string `json:"status"`
	}
	if !decode(w, r, &req) {
		return
	}
	p, _ := platformFrom(r.Context())
	if req.Status == nil {
		writeErr(w, r, http.StatusBadRequest, "INVALID_ARGUMENT", "未提供需要变更的字段")
		return
	}

	chg, err := a.Tenants.SetStatus(r.Context(), slug, *req.Status)
	if err != nil {
		switch {
		case errors.Is(err, tenant.ErrNotFound):
			writeErr(w, r, http.StatusNotFound, "NOT_FOUND", "租户不存在")
		case errors.Is(err, tenant.ErrInvalidStatus):
			writeErr(w, r, http.StatusBadRequest, "INVALID_ARGUMENT",
				"状态仅支持 active/trial/readonly/suspended/deleted")
		default:
			a.logErr("变更租户状态失败", "slug", slug, "err", err)
			writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "变更状态失败")
		}
		return
	}

	// 本实例立即失效两处缓存：只读闸门（15s）与吊销检查（10s）。
	//
	// 数据库已经在同一事务里吊销了会话，但**吊销检查有进程内缓存**——
	// 不清缓存的话，运营点了"停用"，本实例上已登录的人还能继续用最多 10 秒，
	// 现场看到的是"停用了但人还在用"。其它实例仍受 TTL 约束（PRD 允许 30s 内收敛）。
	a.invalidateGate(chg.TenantID)
	if chg.CurStatus == tenant.StatusSuspended || chg.CurStatus == tenant.StatusDeleted {
		if a.Auth != nil {
			a.Auth.Guard().InvalidateAll()
		}
	}

	// 停用/删除会吊销会话，这个事实必须写进审计——否则事后无法解释
	// "为什么某个用户突然被踢下线"。
	a.auditPlatform(r, p, "platform.tenant.status", slug, "ok", map[string]any{
		"prev": chg.PrevStatus, "cur": chg.CurStatus,
		"sessionsRevoked": chg.CurStatus == tenant.StatusSuspended || chg.CurStatus == tenant.StatusDeleted,
	})
	writeOK(w, r, chg)
}

func (a *API) handlePlatformTenantDelete(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("slug")
	chg, err := a.Tenants.SetStatus(r.Context(), slug, tenant.StatusDeleted)
	if err != nil {
		if errors.Is(err, tenant.ErrNotFound) {
			writeErr(w, r, http.StatusNotFound, "NOT_FOUND", "租户不存在")
			return
		}
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "删除租户失败")
		return
	}
	a.invalidateGate(chg.TenantID)
	if a.Auth != nil {
		a.Auth.Guard().InvalidateAll()
	}
	p, _ := platformFrom(r.Context())
	a.auditPlatform(r, p, "platform.tenant.delete", slug, "ok",
		map[string]any{"prev": chg.PrevStatus, "retention": "30d"})
	writeOK(w, r, map[string]any{"slug": slug, "deleted": true,
		"retentionNote": "逻辑删除，数据保留 30 天后可物理清理"})
}

// ---------------- 配额与用量 ----------------

func (a *API) handlePlatformQuotaGet(w http.ResponseWriter, r *http.Request) {
	q, err := a.Tenants.GetQuota(r.Context(), r.PathValue("slug"))
	if err != nil {
		if errors.Is(err, tenant.ErrNotFound) {
			writeErr(w, r, http.StatusNotFound, "NOT_FOUND", "租户不存在")
			return
		}
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "读取配额失败")
		return
	}
	writeOK(w, r, q)
}

func (a *API) handlePlatformQuotaPut(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("slug")
	var q tenant.Quota
	if !decode(w, r, &q) {
		return
	}
	if err := a.Tenants.SetQuota(r.Context(), slug, q); err != nil {
		switch {
		case errors.Is(err, tenant.ErrNotFound):
			writeErr(w, r, http.StatusNotFound, "NOT_FOUND", "租户不存在")
		case errors.Is(err, tenant.ErrInvalidInput):
			writeErr(w, r, http.StatusBadRequest, "INVALID_ARGUMENT", err.Error())
		default:
			writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "设置配额失败")
		}
		return
	}
	if tid, terr := a.Tenants.ResolveID(r.Context(), slug); terr == nil {
		a.invalidateGate(tid)
	}
	p, _ := platformFrom(r.Context())
	a.auditPlatform(r, p, "platform.quota.set", slug, "ok", map[string]any{
		"maxUsers": q.MaxUsers, "maxStorageBytes": q.MaxStorageBytes,
		"maxTranscodeSeconds": q.MaxTranscodeSeconds, "maxApiCallsDay": q.MaxAPICallsDay,
		"onExceed": q.OnExceed,
	})
	writeOK(w, r, map[string]any{"slug": slug, "quota": q})
}

func (a *API) handlePlatformUsage(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("slug")
	now := time.Now().UTC()
	from := parseDate(r.URL.Query().Get("from"), now.AddDate(0, 0, -29))
	to := parseDate(r.URL.Query().Get("to"), now)

	points, err := a.Metering.Series(r.Context(), slug, from, to)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "读取用量失败")
		return
	}
	t, err := a.Tenants.Get(r.Context(), slug)
	if err != nil {
		if errors.Is(err, tenant.ErrNotFound) {
			writeErr(w, r, http.StatusNotFound, "NOT_FOUND", "租户不存在")
			return
		}
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "读取租户失败")
		return
	}
	q, _ := a.Tenants.GetQuota(r.Context(), slug)

	writeOK(w, r, map[string]any{
		"slug": slug, "from": from.Format("2006-01-02"), "to": to.Format("2006-01-02"),
		"points": points,
		// 瞬时量单独给：它不是"某天发生了多少"，按日累加会重复计算
		"snapshot": map[string]any{
			"storageBytes": t.StorageBytes, "activeUsers": t.Users, "files": t.Files,
		},
		"quota": q,
	})
}

// handlePlatformInvoice 导出账单 CSV（PRD-TEN-06 的"一期可导出账单"）。
//
// CSV 而不是 JSON：对账是财务的动作，Excel 是他们的工具。
func (a *API) handlePlatformInvoice(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("slug")
	month := r.URL.Query().Get("month")
	if month == "" {
		month = time.Now().UTC().Format("2006-01")
	}
	id, err := a.Tenants.ResolveID(r.Context(), slug)
	if err != nil {
		writeErr(w, r, http.StatusNotFound, "NOT_FOUND", "租户不存在")
		return
	}
	totals, err := a.Metering.MonthTotals(r.Context(), id, month)
	if err != nil {
		writeErr(w, r, http.StatusBadRequest, "INVALID_ARGUMENT", err.Error())
		return
	}
	t, _ := a.Tenants.Get(r.Context(), slug)

	units := map[string]string{
		"api_calls": "次", "transcode_seconds": "秒", "share_views": "次",
		"preview_renders": "次", "egress_bytes": "字节",
	}

	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition",
		`attachment; filename="usage-`+slug+`-`+month+`.csv"`)
	// BOM：不加的话 Excel 打开中文列名是乱码（Windows 版默认按 GBK 猜）
	_, _ = w.Write([]byte{0xEF, 0xBB, 0xBF})

	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"租户", "月份", "指标", "数量", "单位", "口径"})
	for _, m := range sortedKeys(totals) {
		_ = cw.Write([]string{slug, month, m, strconv.FormatInt(totals[m], 10), units[m], "当月累计"})
	}
	// 瞬时量单独标注口径：它不是"当月发生"，而是"月末快照"
	_ = cw.Write([]string{slug, month, "storage_bytes", strconv.FormatInt(t.StorageBytes, 10),
		"字节", "月末快照"})
	_ = cw.Write([]string{slug, month, "active_users", strconv.FormatInt(t.Users, 10),
		"人", "月末快照"})
	cw.Flush()

	p, _ := platformFrom(r.Context())
	a.auditPlatform(r, p, "platform.invoice.export", slug, "ok", map[string]any{"month": month})
}

func (a *API) handlePlatformReconcile(w http.ResponseWriter, r *http.Request) {
	repair := r.URL.Query().Get("repair") == "true"
	drifts, err := a.Metering.Reconcile(r.Context(), repair)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "对账失败")
		return
	}
	var dirty int
	for _, d := range drifts {
		if d.StorageDrift != 0 || d.UsersDrift != 0 {
			dirty++
		}
	}
	if repair && dirty > 0 {
		p, _ := platformFrom(r.Context())
		a.auditPlatform(r, p, "platform.usage.reconcile", "", "ok",
			map[string]any{"repaired": dirty, "total": len(drifts)})
	}
	writeOK(w, r, map[string]any{
		"items": drifts, "count": len(drifts), "driftCount": dirty, "repaired": repair,
	})
}

// ---------------- 域名与证书 ----------------

func (a *API) handlePlatformDomainList(w http.ResponseWriter, r *http.Request) {
	list, err := a.Tenants.ListDomains(r.Context(), r.PathValue("slug"))
	if err != nil {
		if errors.Is(err, tenant.ErrNotFound) {
			writeErr(w, r, http.StatusNotFound, "NOT_FOUND", "租户不存在")
			return
		}
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "读取域名失败")
		return
	}
	writeOK(w, r, map[string]any{"items": list, "count": len(list)})
}

func (a *API) handlePlatformDomainAdd(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("slug")
	var req struct {
		Host    string `json:"host"`
		Primary bool   `json:"primary"`
	}
	if !decode(w, r, &req) {
		return
	}
	tenantID, err := a.Tenants.ResolveID(r.Context(), slug)
	if err != nil {
		writeErr(w, r, http.StatusNotFound, "NOT_FOUND", "租户不存在")
		return
	}
	p, _ := platformFrom(r.Context())

	// 自定义域名是灰度开关门控的能力：平台可以先关掉整个功能，
	// 再处理个别租户的例外（用租户级覆盖）。
	// 读不到开关时拒绝，不当成开启。
	fs, ferr := a.featureState(r.Context(), tenantID, feature.CustomDomain)
	if ferr != nil {
		writeErr(w, r, http.StatusServiceUnavailable, "FEATURE_UNAVAILABLE",
			"域名能力暂时不可用，请稍后重试")
		return
	}
	if !fs.Enabled {
		writeErr(w, r, http.StatusForbidden, "FEATURE_DISABLED",
			featureDenyMessage(fs, "自定义域名"))
		return
	}

	token, err := a.Tenants.AddDomain(r.Context(), tenantID, req.Host, req.Primary)
	if err != nil {
		if errors.Is(err, tenant.ErrInvalidInput) {
			writeErr(w, r, http.StatusBadRequest, "INVALID_ARGUMENT", err.Error())
			return
		}
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "绑定域名失败")
		return
	}
	a.auditPlatform(r, p, "platform.domain.add", slug, "ok",
		map[string]any{"host": req.Host, "primary": req.Primary})
	writeOK(w, r, map[string]any{
		"host": strings.ToLower(req.Host), "verified": false,
		// 把"该配什么"直接给出去，避免运维去翻文档猜记录名
		"dns": map[string]string{
			"type": "TXT", "name": "_docvault-challenge." + strings.ToLower(req.Host), "value": token,
		},
	})
}

func (a *API) handlePlatformDomainDelete(w http.ResponseWriter, r *http.Request) {
	slug, host := r.PathValue("slug"), r.PathValue("host")
	tenantID, err := a.Tenants.ResolveID(r.Context(), slug)
	if err != nil {
		writeErr(w, r, http.StatusNotFound, "NOT_FOUND", "租户不存在")
		return
	}
	if err := a.Tenants.RemoveDomain(r.Context(), tenantID, host); err != nil {
		if errors.Is(err, tenant.ErrNotFound) {
			writeErr(w, r, http.StatusNotFound, "NOT_FOUND", "域名不存在")
			return
		}
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "解绑失败")
		return
	}
	p, _ := platformFrom(r.Context())
	a.auditPlatform(r, p, "platform.domain.delete", slug, "ok", map[string]any{"host": host})
	writeOK(w, r, map[string]any{"host": host, "removed": true})
}

// handlePlatformDomainVerify 用 DNS TXT 验证域名归属。
//
// 为什么是 TXT 而不是"访问一个验证文件"：后者要求服务端主动向用户填写的域名
// 发 HTTP 请求，这是 SSRF 的典型入口（内网地址、云元数据端点都走这条路）。
func (a *API) handlePlatformDomainVerify(w http.ResponseWriter, r *http.Request) {
	slug, host := r.PathValue("slug"), strings.ToLower(r.PathValue("host"))
	tenantID, err := a.Tenants.ResolveID(r.Context(), slug)
	if err != nil {
		writeErr(w, r, http.StatusNotFound, "NOT_FOUND", "租户不存在")
		return
	}
	want, err := a.Tenants.VerifyToken(r.Context(), tenantID, host)
	if err != nil {
		writeErr(w, r, http.StatusNotFound, "NOT_FOUND", "域名不存在")
		return
	}

	records, lerr := a.lookupTXT(r.Context(), "_docvault-challenge."+host)
	if lerr != nil {
		writeErr(w, r, http.StatusBadGateway, "DNS_LOOKUP_FAILED",
			"DNS 查询失败："+lerr.Error())
		return
	}
	found := false
	for _, rec := range records {
		if strings.TrimSpace(rec) == want {
			found = true
			break
		}
	}
	if !found {
		writeErr(w, r, http.StatusPreconditionFailed, "DNS_CHALLENGE_MISMATCH",
			"未在 _docvault-challenge."+host+" 找到匹配的 TXT 记录")
		return
	}
	if err := a.Tenants.MarkVerified(r.Context(), tenantID, host); err != nil {
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "标记验证失败")
		return
	}
	p, _ := platformFrom(r.Context())
	a.auditPlatform(r, p, "platform.domain.verify", slug, "ok", map[string]any{"host": host})
	writeOK(w, r, map[string]any{"host": host, "verified": true})
}

func (a *API) handlePlatformDomainCert(w http.ResponseWriter, r *http.Request) {
	slug, host := r.PathValue("slug"), strings.ToLower(r.PathValue("host"))
	var req struct {
		CertPEM string `json:"certPem"`
		KeyPEM  string `json:"keyPem"`
	}
	if !decode(w, r, &req) {
		return
	}
	if req.CertPEM == "" || req.KeyPEM == "" {
		writeErr(w, r, http.StatusBadRequest, "INVALID_ARGUMENT", "certPem 与 keyPem 都必须提供")
		return
	}
	tenantID, err := a.Tenants.ResolveID(r.Context(), slug)
	if err != nil {
		writeErr(w, r, http.StatusNotFound, "NOT_FOUND", "租户不存在")
		return
	}
	info, err := a.Tenants.SetCertificate(r.Context(), a.SecretBox, tenantID, host,
		req.CertPEM, []byte(req.KeyPEM))
	if err != nil {
		switch {
		case errors.Is(err, tenant.ErrCertUnavailable):
			writeErr(w, r, http.StatusServiceUnavailable, "SECRET_KEY_MISSING",
				"未配置 DOCVAULT_SECRET_KEY，拒绝以明文保存私钥")
		case errors.Is(err, tenant.ErrInvalidInput):
			writeErr(w, r, http.StatusBadRequest, "INVALID_ARGUMENT", err.Error())
		case errors.Is(err, tenant.ErrNotFound):
			writeErr(w, r, http.StatusNotFound, "NOT_FOUND", "域名不存在")
		default:
			a.logErr("保存证书失败", "host", host, "err", err)
			writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "保存证书失败")
		}
		return
	}
	p, _ := platformFrom(r.Context())
	a.auditPlatform(r, p, "platform.domain.cert", slug, "ok",
		map[string]any{"host": host, "notAfter": info.NotAfter, "fingerprint": info.Fingerprint})
	writeOK(w, r, info)
}

// ---------------- 灰度开关 ----------------

func (a *API) handlePlatformFlags(w http.ResponseWriter, r *http.Request) {
	list, err := a.Features.List(r.Context())
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "读取开关失败")
		return
	}
	writeOK(w, r, map[string]any{"items": list, "count": len(list)})
}

func (a *API) handlePlatformFlagPut(w http.ResponseWriter, r *http.Request) {
	code := r.PathValue("code")
	var req struct {
		DefaultEnabled bool `json:"defaultEnabled"`
		RolloutPercent int  `json:"rolloutPercent"`
	}
	if !decode(w, r, &req) {
		return
	}
	if err := a.Features.SetFlag(r.Context(), code, req.DefaultEnabled, req.RolloutPercent); err != nil {
		if errors.Is(err, feature.ErrUnknownFlag) {
			writeErr(w, r, http.StatusNotFound, "NOT_FOUND", err.Error())
			return
		}
		writeErr(w, r, http.StatusBadRequest, "INVALID_ARGUMENT", err.Error())
		return
	}
	p, _ := platformFrom(r.Context())
	a.auditPlatform(r, p, "platform.flag.set", code, "ok", map[string]any{
		"defaultEnabled": req.DefaultEnabled, "rolloutPercent": req.RolloutPercent,
	})
	writeOK(w, r, map[string]any{"code": code, "defaultEnabled": req.DefaultEnabled,
		"rolloutPercent": req.RolloutPercent})
}

func (a *API) handlePlatformTenantFlags(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("slug")
	overrides, err := a.Features.TenantOverrides(r.Context(), slug)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "读取租户开关失败")
		return
	}
	tenantID, err := a.Tenants.ResolveID(r.Context(), slug)
	if err != nil {
		writeErr(w, r, http.StatusNotFound, "NOT_FOUND", "租户不存在")
		return
	}
	eff, err := a.Features.Effective(r.Context(), tenantID)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "求值失败")
		return
	}
	writeOK(w, r, map[string]any{"slug": slug, "overrides": overrides, "effective": eff})
}

func (a *API) handlePlatformTenantFlagPut(w http.ResponseWriter, r *http.Request) {
	slug, code := r.PathValue("slug"), r.PathValue("code")
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if !decode(w, r, &req) {
		return
	}
	tenantID, err := a.Tenants.ResolveID(r.Context(), slug)
	if err != nil {
		writeErr(w, r, http.StatusNotFound, "NOT_FOUND", "租户不存在")
		return
	}
	if err := a.Features.SetOverride(r.Context(), tenantID, code, req.Enabled); err != nil {
		if errors.Is(err, feature.ErrUnknownFlag) {
			writeErr(w, r, http.StatusNotFound, "NOT_FOUND", err.Error())
			return
		}
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "设置覆盖失败")
		return
	}
	p, _ := platformFrom(r.Context())
	a.auditPlatform(r, p, "platform.flag.override", slug, "ok",
		map[string]any{"code": code, "enabled": req.Enabled})
	writeOK(w, r, map[string]any{"slug": slug, "code": code, "enabled": req.Enabled})
}

func (a *API) handlePlatformTenantFlagDelete(w http.ResponseWriter, r *http.Request) {
	slug, code := r.PathValue("slug"), r.PathValue("code")
	tenantID, err := a.Tenants.ResolveID(r.Context(), slug)
	if err != nil {
		writeErr(w, r, http.StatusNotFound, "NOT_FOUND", "租户不存在")
		return
	}
	if err := a.Features.ClearOverride(r.Context(), tenantID, code); err != nil {
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "清除覆盖失败")
		return
	}
	p, _ := platformFrom(r.Context())
	a.auditPlatform(r, p, "platform.flag.override.clear", slug, "ok", map[string]any{"code": code})
	writeOK(w, r, map[string]any{"slug": slug, "code": code, "cleared": true})
}

// ---------------- 平台审计 ----------------

func (a *API) handlePlatformAuditLog(w http.ResponseWriter, r *http.Request) {
	events, err := a.PlatformAuth.AuditList(r.Context(), platformauth.AuditFilter{
		Action: r.URL.Query().Get("action"),
		Target: r.URL.Query().Get("target"),
		Limit:  atoiDefault(r.URL.Query().Get("limit"), 100),
	})
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "读取平台审计失败")
		return
	}
	items := make([]map[string]any, 0, len(events))
	for _, e := range events {
		items = append(items, map[string]any{
			"id": e.ID, "actor": e.Actor, "action": e.Action, "target": e.Target,
			"result": e.Result, "ip": e.IP, "createdAt": e.CreatedAt.UTC().Format(time.RFC3339),
		})
	}
	writeOK(w, r, map[string]any{"items": items, "count": len(items)})
}

func parseDate(v string, def time.Time) time.Time {
	if v == "" {
		return def
	}
	t, err := time.Parse("2006-01-02", v)
	if err != nil {
		return def
	}
	return t
}

func atoiDefault(v string, def int) int {
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return def
	}
	return n
}

func sortedKeys(m map[string]int64) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	for i := 0; i < len(out); i++ {
		for j := i + 1; j < len(out); j++ {
			if out[j] < out[i] {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}

// 断言依赖被使用（避免未来重构时静默丢掉 tx 类型导入）
var _ = pgx.ErrNoRows
