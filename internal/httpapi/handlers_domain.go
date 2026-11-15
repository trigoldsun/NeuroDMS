package httpapi

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"docvault/internal/acmecert"
	"docvault/internal/entitlement"
	"docvault/internal/feature"
	"docvault/internal/rbac"
	"docvault/internal/tenant"
)

// 租户自助的域名与证书（docs/47 §4.6）。
//
// 为什么本地版必须是自助：本地部署没有运营台，域名与证书只能由客户的
// 管理员自己绑、自己验、自己签。SaaS 侧同一套接口保留，平台仍可用
// entitlement lock（一票否决）关掉某租户的域名能力，不需要两套代码。

func (a *API) registerDomain(mux *http.ServeMux) {
	// requireRole 内部已经做了 requireAuth：再包一层会重复解析令牌、
	// 重复查一次角色（每次多一次数据库往返），没有额外安全性。
	sys := a.requireRole(rbac.SysAdmin)
	mux.HandleFunc("GET /v1/admin/domains", sys(a.handleDomainList))
	mux.HandleFunc("GET /v1/admin/domains/acme", sys(a.handleDomainACMEStatus))
	mux.HandleFunc("POST /v1/admin/domains", sys(a.handleDomainAdd))
	mux.HandleFunc("DELETE /v1/admin/domains/{host}", sys(a.handleDomainDelete))
	mux.HandleFunc("POST /v1/admin/domains/{host}/verify", sys(a.handleDomainVerify))
	mux.HandleFunc("PUT /v1/admin/domains/{host}/certificate", sys(a.handleDomainCertUpload))
	mux.HandleFunc("DELETE /v1/admin/domains/{host}/certificate", sys(a.handleDomainCertDelete))
	mux.HandleFunc("POST /v1/admin/domains/{host}/acme", sys(a.handleDomainACMEIssue))
	mux.HandleFunc("POST /v1/admin/domains/{host}/acme/begin", sys(a.handleDomainACMEBegin))
	mux.HandleFunc("POST /v1/admin/domains/{host}/acme/finish", sys(a.handleDomainACMEFinish))
}

// domainGate 判定"这个租户此刻能不能配自定义域名"。
//
// 两道锁的顺序有意如此：先看授权（客户有没有买/平台有没有强制关），
// 再看灰度开关（我们放不放这个功能）。反过来的话，平台灰度关闭期间
// 客户会看到"请升级"，那是误导。
func (a *API) domainGate(w http.ResponseWriter, r *http.Request, tenantID string) bool {
	ok, err := a.entitled(r.Context(), tenantID, entitlement.CustomDomain)
	if err != nil {
		writeErr(w, r, http.StatusServiceUnavailable, "ENTITLEMENT_UNAVAILABLE",
			"无法读取能力授权，请稍后重试")
		return false
	}
	if !ok {
		writeErr(w, r, http.StatusForbidden, "FEATURE_NOT_ENABLED",
			"当前档位或授权不含自定义域名，可升级或联系运营单独开通")
		return false
	}
	if a.Features != nil {
		fs, ferr := a.featureState(r.Context(), tenantID, feature.CustomDomain)
		if ferr != nil {
			writeErr(w, r, http.StatusServiceUnavailable, "FEATURE_UNAVAILABLE",
				"域名能力暂时不可用，请稍后重试")
			return false
		}
		if !fs.Enabled {
			writeErr(w, r, http.StatusForbidden, "FEATURE_DISABLED",
				featureDenyMessage(fs, "自定义域名"))
			return false
		}
	}
	return true
}

func (a *API) handleDomainList(w http.ResponseWriter, r *http.Request) {
	c, _ := claimsFrom(r.Context())
	// 列表不做授权拦截：客户升级前绑过的域名，降档后仍要能看见并解绑，
	// 否则会出现"域名占着位、界面里消失、换个租户又绑不上"的死锁。
	list, err := a.Tenants.ListDomainsFor(r.Context(), c.TenantID)
	if err != nil {
		a.logErr("读取域名失败", "err", err)
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "读取域名失败")
		return
	}
	// 空列表回 [] 而不是 null：前端 `items.map` 会在 null 上直接抛错，
	// 而"没有域名"是最常见的初始状态。
	if list == nil {
		list = []tenant.Domain{}
	}
	out := map[string]any{"items": list, "count": len(list)}
	if a.Acme != nil {
		out["acme"] = a.Acme.Status()
	}
	writeOK(w, r, out)
}

func (a *API) handleDomainACMEStatus(w http.ResponseWriter, r *http.Request) {
	if a.Acme == nil {
		writeOK(w, r, acmecert.Status{
			Mode: "off", Available: false,
			Reason: "自动签发未装配：证书需由反向代理或边缘托管",
		})
		return
	}
	writeOK(w, r, a.Acme.Status())
}

func (a *API) handleDomainAdd(w http.ResponseWriter, r *http.Request) {
	c, _ := claimsFrom(r.Context())
	if !a.domainGate(w, r, c.TenantID) {
		return
	}
	var req struct {
		Host    string `json:"host"`
		Primary bool   `json:"primary"`
	}
	if !decode(w, r, &req) {
		return
	}
	token, err := a.Tenants.AddDomain(r.Context(), c.TenantID, req.Host, req.Primary)
	if err != nil {
		if errors.Is(err, tenant.ErrInvalidInput) {
			writeErr(w, r, http.StatusBadRequest, "INVALID_ARGUMENT", err.Error())
			return
		}
		a.logErr("绑定域名失败", "err", err)
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "绑定域名失败")
		return
	}
	host := strings.ToLower(strings.TrimSpace(req.Host))
	// ObjectID 留空：审计表的 object_id 是 uuid 列，域名不是 uuid。
	// 域名标识放 Detail（此前传 host 导致这条审计**静默写不进去**）。
	a.emitLogged(r, c.TenantID, AuditEntry{
		ActorID: c.Subject, Action: "admin.domain.add",
		ObjectType: "tenant_domain", Result: "ok",
		Detail: map[string]any{"host": host, "primary": req.Primary},
	})
	writeOK(w, r, map[string]any{
		"host": host, "verified": false,
		"dns": map[string]string{
			"type": "TXT", "name": "_docvault-challenge." + host, "value": token,
		},
	})
}

func (a *API) handleDomainDelete(w http.ResponseWriter, r *http.Request) {
	c, _ := claimsFrom(r.Context())
	host := strings.ToLower(r.PathValue("host"))
	// 解绑不受授权门控：这是"减少占位"的操作，拦住只会让客户卡死。
	if err := a.Tenants.RemoveDomain(r.Context(), c.TenantID, host); err != nil {
		if errors.Is(err, tenant.ErrNotFound) {
			writeErr(w, r, http.StatusNotFound, "NOT_FOUND", "域名不存在")
			return
		}
		a.logErr("解绑域名失败", "err", err)
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "解绑失败")
		return
	}
	a.emitLogged(r, c.TenantID, AuditEntry{
		ActorID: c.Subject, Action: "admin.domain.delete",
		ObjectType: "tenant_domain", Result: "ok",
		Detail: map[string]any{"host": host},
	})
	writeOK(w, r, map[string]any{"host": host, "removed": true})
}

func (a *API) handleDomainVerify(w http.ResponseWriter, r *http.Request) {
	c, _ := claimsFrom(r.Context())
	host := strings.ToLower(r.PathValue("host"))
	if !a.domainGate(w, r, c.TenantID) {
		return
	}
	want, err := a.Tenants.VerifyToken(r.Context(), c.TenantID, host)
	if err != nil {
		writeErr(w, r, http.StatusNotFound, "NOT_FOUND", "域名不存在")
		return
	}
	records, lerr := a.lookupTXT(r.Context(), "_docvault-challenge."+host)
	if lerr != nil {
		// 用 503 而不是 502：Cloudflare 等边缘会把 **502/504 的响应体整个替换**成
		// "error code: 502"，客户看不到我们写的这句话（实测踩到）。
		// 503 会原样透传，且语义上也对：本机解析不了外网，是暂时性依赖不可用。
		writeErr(w, r, http.StatusServiceUnavailable, "DNS_LOOKUP_FAILED",
			"DNS 查询失败，请检查本服务器能否解析外网域名")
		return
	}
	for _, rec := range records {
		if strings.TrimSpace(rec) == want {
			if err := a.Tenants.MarkVerified(r.Context(), c.TenantID, host); err != nil {
				a.logErr("标记域名验证失败", "err", err)
				writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "标记验证失败")
				return
			}
			a.emitLogged(r, c.TenantID, AuditEntry{
				ActorID: c.Subject, Action: "admin.domain.verify",
				ObjectType: "tenant_domain", Result: "ok",
				Detail: map[string]any{"host": host},
			})
			writeOK(w, r, map[string]any{"host": host, "verified": true})
			return
		}
	}
	writeErr(w, r, http.StatusPreconditionFailed, "DNS_CHALLENGE_MISMATCH",
		"未在 _docvault-challenge."+host+" 找到匹配的 TXT 记录，请确认记录已生效")
}

func (a *API) handleDomainCertUpload(w http.ResponseWriter, r *http.Request) {
	c, _ := claimsFrom(r.Context())
	host := strings.ToLower(r.PathValue("host"))
	if !a.domainGate(w, r, c.TenantID) {
		return
	}
	var req struct {
		CertPEM string `json:"certPem"`
		KeyPEM  string `json:"keyPem"`
	}
	if !decode(w, r, &req) {
		return
	}
	if strings.TrimSpace(req.CertPEM) == "" || strings.TrimSpace(req.KeyPEM) == "" {
		writeErr(w, r, http.StatusBadRequest, "INVALID_ARGUMENT",
			"证书与私钥都必须提供（PEM 格式）")
		return
	}
	info, err := a.Tenants.SetCertificate(r.Context(), a.SecretBox, c.TenantID, host,
		req.CertPEM, []byte(req.KeyPEM))
	if err != nil {
		switch {
		case errors.Is(err, tenant.ErrCertUnavailable):
			writeErr(w, r, http.StatusServiceUnavailable, "SECRET_KEY_MISSING",
				"服务端未配置 DOCVAULT_SECRET_KEY，拒绝以明文保存私钥")
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
	// 手工上传优先：一旦客户自己传了证书，自动续期就不再碰这个域名
	// （见 SetCertificate 的 source=manual）。
	a.emitLogged(r, c.TenantID, AuditEntry{
		ActorID: c.Subject, Action: "admin.domain.cert.upload",
		ObjectType: "tenant_domain", Result: "ok",
		Detail: map[string]any{
			"host": host, "source": "manual",
			"notAfter": info.NotAfter, "fingerprint": info.Fingerprint,
		},
	})
	writeOK(w, r, info)
}

func (a *API) handleDomainCertDelete(w http.ResponseWriter, r *http.Request) {
	c, _ := claimsFrom(r.Context())
	host := strings.ToLower(r.PathValue("host"))
	if err := a.Tenants.ClearCertificate(r.Context(), c.TenantID, host); err != nil {
		if errors.Is(err, tenant.ErrNotFound) {
			writeErr(w, r, http.StatusNotFound, "NOT_FOUND", "域名不存在")
			return
		}
		a.logErr("删除证书失败", "err", err)
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "删除证书失败")
		return
	}
	a.emitLogged(r, c.TenantID, AuditEntry{
		ActorID: c.Subject, Action: "admin.domain.cert.delete",
		ObjectType: "tenant_domain", Result: "ok",
		Detail: map[string]any{"host": host},
	})
	writeOK(w, r, map[string]any{"host": host, "certRemoved": true})
}

// handleDomainACMEIssue 按当前模式发起签发：
// http01 同步完成；dns01 返回 TXT 记录（两阶段的第一步）。
func (a *API) handleDomainACMEIssue(w http.ResponseWriter, r *http.Request) {
	c, _ := claimsFrom(r.Context())
	host := strings.ToLower(r.PathValue("host"))
	if !a.domainGate(w, r, c.TenantID) {
		return
	}
	if !a.acmeReady(w, r) {
		return
	}
	if !a.acmeCooldown(w, r, c.TenantID, host) {
		return
	}
	switch a.Acme.Mode() {
	case acmecert.ModeHTTP01:
		if err := a.Acme.IssueHTTP01(r.Context(), c.TenantID, host); err != nil {
			a.Acme.RecordError(r.Context(), c.TenantID, host, err)
			a.writeACMEErr(w, r, err)
			return
		}
		a.emitLogged(r, c.TenantID, AuditEntry{
			ActorID: c.Subject, Action: "admin.domain.cert.issue",
			ObjectType: "tenant_domain", Result: "ok",
			Detail: map[string]any{"host": host, "mode": "http01"},
		})
		writeOK(w, r, map[string]any{"host": host, "issued": true, "mode": "http01"})
	case acmecert.ModeDNS01:
		ch, err := a.Acme.BeginDNS01(r.Context(), c.TenantID, host)
		if err != nil {
			a.Acme.RecordError(r.Context(), c.TenantID, host, err)
			a.writeACMEErr(w, r, err)
			return
		}
		writeOK(w, r, map[string]any{"host": host, "issued": false, "mode": "dns01", "dns": ch})
	default:
		writeErr(w, r, http.StatusConflict, "ACME_DISABLED",
			"自动签发未启用，请手工上传证书或改由反向代理托管")
	}
}

func (a *API) handleDomainACMEBegin(w http.ResponseWriter, r *http.Request) {
	c, _ := claimsFrom(r.Context())
	host := strings.ToLower(r.PathValue("host"))
	if !a.domainGate(w, r, c.TenantID) {
		return
	}
	if !a.acmeReady(w, r) {
		return
	}
	ch, err := a.Acme.BeginDNS01(r.Context(), c.TenantID, host)
	if err != nil {
		a.Acme.RecordError(r.Context(), c.TenantID, host, err)
		a.writeACMEErr(w, r, err)
		return
	}
	writeOK(w, r, map[string]any{"dns": ch})
}

func (a *API) handleDomainACMEFinish(w http.ResponseWriter, r *http.Request) {
	c, _ := claimsFrom(r.Context())
	host := strings.ToLower(r.PathValue("host"))
	if !a.domainGate(w, r, c.TenantID) {
		return
	}
	if !a.acmeReady(w, r) {
		return
	}
	if !a.acmeCooldown(w, r, c.TenantID, host) {
		return
	}
	if err := a.Acme.FinishDNS01(r.Context(), c.TenantID, host); err != nil {
		a.Acme.RecordError(r.Context(), c.TenantID, host, err)
		a.writeACMEErr(w, r, err)
		return
	}
	a.emitLogged(r, c.TenantID, AuditEntry{
		ActorID: c.Subject, Action: "admin.domain.cert.issue",
		ObjectType: "tenant_domain", Result: "ok",
		Detail: map[string]any{"host": host, "mode": "dns01"},
	})
	writeOK(w, r, map[string]any{"host": host, "issued": true, "mode": "dns01"})
}

// acmeCooldown 拦住"刚失败就再点一次"。
//
// CA 对同一域名每小时 5 次授权失败有硬限制，超了之后一小时内连订单都下不了。
// 界面上连点是最容易烧光额度的方式，所以这里主动挡 60 秒并说明原因。
func (a *API) acmeCooldown(w http.ResponseWriter, r *http.Request, tenantID, host string) bool {
	if a.Acme == nil {
		return true
	}
	left, lastErr := a.Acme.Cooldown(r.Context(), tenantID, host, time.Minute)
	if left <= 0 {
		return true
	}
	secs := int(left.Seconds()) + 1
	writeErr(w, r, http.StatusTooManyRequests, "ACME_COOLDOWN",
		fmt.Sprintf("刚刚失败过（%s），请 %d 秒后再试。"+
			"同一域名每小时失败 5 次会被 CA 临时拒绝一小时——"+
			"建议先用测试目录（DOCVAULT_ACME_DIRECTORY）调通再切生产", lastErr, secs))
	return false
}

// acmeReady 检查 ACME 服务是否可用，不可用时写一条可照做的说明。
func (a *API) acmeReady(w http.ResponseWriter, r *http.Request) bool {
	if a.Acme == nil {
		writeErr(w, r, http.StatusConflict, "ACME_DISABLED",
			"自动签发未装配，请手工上传证书")
		return false
	}
	st := a.Acme.Status()
	if !st.Available {
		writeErr(w, r, http.StatusConflict, "ACME_DISABLED", st.Reason)
		return false
	}
	return true
}

// writeACMEErr 把 ACME 错误映射成状态码 + 一句可读的话。
//
// 上游错误里可能带订单 URL、账户 URL 甚至内部地址，一律不进响应体，
// 只写服务端日志（与短信自检的处理一致）。
func (a *API) writeACMEErr(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, acmecert.ErrDisabled):
		writeErr(w, r, http.StatusConflict, "ACME_DISABLED", "自动签发未启用")
	case errors.Is(err, acmecert.ErrNotVerified):
		writeErr(w, r, http.StatusPreconditionFailed, "DOMAIN_NOT_VERIFIED",
			"域名还没通过归属验证，请先完成 DNS TXT 验证再签发")
	case errors.Is(err, acmecert.ErrDNSNotReady):
		writeErr(w, r, http.StatusPreconditionFailed, "DNS_NOT_READY",
			"TXT 记录尚未生效：请等待几分钟（或降低 TTL）后重试；已生效仍失败请检查是否有同名多条 TXT")
	case errors.Is(err, acmecert.ErrNoAccountKey):
		writeErr(w, r, http.StatusServiceUnavailable, "SECRET_KEY_MISSING",
			"服务端未配置 DOCVAULT_SECRET_KEY，无法保存 ACME 账户与证书私钥")
	default:
		a.logErr("自动签发失败", "err", err)
		writeErr(w, r, http.StatusServiceUnavailable, "ACME_FAILED",
			"自动签发失败，原因已记录到服务端日志（常见原因：域名未解析到本机、80/443 不可达、CA 频控）")
	}
}
