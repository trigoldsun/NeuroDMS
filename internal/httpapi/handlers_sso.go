package httpapi

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/netip"
	"regexp"
	"strings"
	"time"

	"docvault/internal/auth"
	"docvault/internal/platform/httpmw"
)

// SSOSettings 描述"域身份单点登录"的部署前提。
//
// 本服务**不做** Kerberos/NTLM 协商：Go 的 HTTP 栈没有 SSPI，无法参与
// SPNEGO 协商。正确做法是让前置的反向代理完成 Windows 集成认证
// （IIS 的 Windows 身份验证，或 nginx + spnego-http-auth-nginx-module），
// 再由代理把一个"已认证用户名"的请求头传给本服务。
//
// 因此这个功能的全部安全性都压在"谁有权写这个头"上。三道门禁缺一不可：
//   - Enabled：显式开关，默认关闭；
//   - Trusted：请求来源必须落在受信代理网段内；
//   - Secret：可选的共享密钥，防止同网段的其他进程伪造。
//
// 任何一项配置不成立，都按"未启用"处理（fail-closed），
// 绝不允许"配置写错了但功能还在跑"。
type SSOSettings struct {
	Enabled       bool
	Header        string
	Secret        string
	Trusted       []netip.Prefix
	DefaultTenant string
	// Reason 记录"为什么不可用"，供前端与运维排查（不含敏感信息）
	Reason string
}

// 这些头绝不能作为身份断言来源：
// 它们由客户端直接控制，或本身就是代理元数据，接受它们等于开放认证绕过。
var forbiddenSSOHeaders = map[string]bool{
	"authorization":    true,
	"cookie":           true,
	"host":             true,
	"x-forwarded-for":  true,
	"x-forwarded-host": true,
	"x-real-ip":        true,
	"forwarded":        true,
}

var ssoHeaderPattern = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`)

// NewSSOSettings 校验并构造 SSO 配置。返回的对象永远非 nil：
// 未启用时 Enabled=false，调用方不需要到处判空。
func NewSSOSettings(enabled bool, header, secret string, cidrs []string, defaultTenant string, log *slog.Logger) *SSOSettings {
	s := &SSOSettings{
		Header:        strings.TrimSpace(header),
		Secret:        secret,
		DefaultTenant: strings.TrimSpace(defaultTenant),
	}
	if !enabled {
		s.Reason = "未启用"
		return s
	}
	if s.Header == "" {
		s.Header = "X-Remote-User"
	}
	if !ssoHeaderPattern.MatchString(s.Header) {
		s.Reason = "断言头名称不合法（只允许字母、数字与连字符）"
		return s
	}
	if forbiddenSSOHeaders[strings.ToLower(s.Header)] {
		s.Reason = "断言头不能使用客户端可控的头（如 Authorization / Cookie / X-Forwarded-For）"
		log.Error("SSO 配置被拒绝", "reason", s.Reason, "header", s.Header)
		return s
	}

	if sk := strings.TrimSpace(secret); sk == "" {
		// 共享密钥是**必需**的，不是可选项。
		//
		// 只靠"来源网段"不够：同一个 docker 网络里，任何容器都能发请求；
		// 更现实的是，若把网段写成 cloudflared 所在网络，公网请求也会
		// 从那个地址进来——等于把断言头交给全世界。密钥让"谁能写这条头"
		// 收敛到持有密钥的那一个代理进程。
		s.Reason = "未配置共享密钥（DOCVAULT_SSO_SHARED_SECRET），已拒绝启用"
		log.Error("SSO 配置被拒绝", "reason", s.Reason)
		return s
	}

	if len(cidrs) == 0 {
		// 没有可信网段就等于"任何来源都能断言"，比不开还危险。
		s.Reason = "未配置可信代理网段（DOCVAULT_SSO_TRUSTED_CIDRS），已拒绝启用"
		log.Error("SSO 配置被拒绝", "reason", s.Reason)
		return s
	}
	for _, raw := range cidrs {
		p, err := netip.ParsePrefix(strings.TrimSpace(raw))
		if err != nil {
			s.Reason = "可信代理网段无法解析：" + raw
			log.Error("SSO 配置被拒绝", "reason", s.Reason)
			return s
		}
		if p.Bits() == 0 {
			// 0.0.0.0/0 或 ::/0 等于信任全世界，直接拒绝启用。
			s.Reason = "可信代理网段不能是 " + raw + "（会信任所有来源）"
			log.Error("SSO 配置被拒绝", "reason", s.Reason)
			return s
		}
		s.Trusted = append(s.Trusted, p)
	}

	s.Enabled = true
	return s
}

// trusted 判断来源是否在受信代理网段内。
func (s *SSOSettings) trusted(addr netip.Addr) bool {
	if !addr.IsValid() {
		return false
	}
	for _, p := range s.Trusted {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// assert 从请求中取出"代理已认证的用户名"。
//
// 返回空串表示"本次请求没有可信的身份断言"——可能是没开 SSO、
// 来源不可信、缺少共享密钥，或代理没能完成集成认证（例如浏览器
// 不在域内）。这三种情况对外一律表现为"不可用"，不区分细节，
// 避免把内部拓扑暴露给匿名访问者。
func (a *API) ssoAssert(r *http.Request) (string, bool) {
	s := a.SSO
	if s == nil || !s.Enabled {
		return "", false
	}

	// 必须用**直连对端**判断来源可信度。
	// clientIP() 在可信代理后面会被改写成真实客户端地址，
	// 用它判断等于"让客户端自己证明自己是代理"。
	addr := httpmw.DirectPeer(r.Context())
	if !addr.IsValid() {
		a2, err := netip.ParseAddr(clientIP(r))
		if err != nil {
			return "", false
		}
		addr = a2
	}
	if !s.trusted(addr) {
		return "", false
	}

	if s.Secret != "" {
		got := []byte(r.Header.Get("X-SSO-Secret"))
		want := []byte(s.Secret)
		// 常量时间比较：普通 == 会因提前返回而泄漏前缀匹配长度
		if len(got) != len(want) || subtle.ConstantTimeCompare(got, want) != 1 {
			return "", false
		}
	}

	raw := strings.TrimSpace(r.Header.Get(s.Header))
	if raw == "" {
		return "", false
	}
	return normalizeAssertedUser(raw), true
}

// normalizeAssertedUser 把代理可能写出的几种形式统一成登录名。
//
// 代理常见输出：
//
//	NEURONGENE\zhangsan
//	zhangsan@neurongene.cn
//	zhangsan
//
// 统一取短名并小写：本地账号的 username 就是这么存的，
// 大小写不同不应该导致"这个人在系统里但登不上"。
func normalizeAssertedUser(raw string) string {
	if i := strings.LastIndex(raw, `\`); i >= 0 {
		raw = raw[i+1:]
	}
	if i := strings.LastIndex(raw, "@"); i > 0 {
		raw = raw[:i]
	}
	return strings.ToLower(strings.TrimSpace(raw))
}

func (a *API) registerSSO(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/auth/sso", a.handleSSOProbe)
	mux.HandleFunc("POST /v1/auth/sso", a.handleSSOLogin)
}

// handleSSOProbe 告诉前端"现在能不能用域身份自动登录"。
//
// 前端在登录页加载时调用一次：可用就直接尝试登录，不可用就安静地
// 显示账号口令表单——不能因为探测失败就弹错误，那会让每个外部用户
// 都看到一个吓人的提示。
func (a *API) handleSSOProbe(w http.ResponseWriter, r *http.Request) {
	// 探测结果与具体用户绑定，不能被任何中间层缓存
	w.Header().Set("Cache-Control", "no-store")

	user, ok := a.ssoAssert(r)
	if ok && user != "" {
		writeOK(w, r, map[string]any{
			"available": true,
			"tenant":    a.SSO.DefaultTenant,
		})
		return
	}

	// 未启用时**不给理由**：这是绝大多数部署的正常状态，
	// 在登录页常驻一句"未启用域登录"只会让所有人以为哪里配错了。
	// 只有"启用了但没拿到断言"才值得提示——那是运维真正要查的现场。
	if a.SSO == nil || !a.SSO.Enabled {
		writeOK(w, r, map[string]any{"available": false})
		return
	}
	writeOK(w, r, map[string]any{
		"available": false,
		"reason":    "未收到域身份信息（浏览器可能不在域内，或代理未启用集成认证）",
	})
}

// handleSSOLogin 用代理断言的身份直接建立会话。
func (a *API) handleSSOLogin(w http.ResponseWriter, r *http.Request) {
	user, ok := a.ssoAssert(r)
	if !ok || user == "" {
		// 401 而不是 500：这是"没有可信身份"，不是服务故障。
		// 前端据此回退到账号口令表单，不显示为错误。
		writeErr(w, r, http.StatusUnauthorized, "SSO_UNAVAILABLE",
			"未收到可信的域身份信息")
		return
	}

	var req struct {
		TenantSlug string `json:"tenantSlug"`
	}
	// 请求体可以为空（前端可能还没有组织标识），因此解码失败不阻断。
	// 这里不用 decode()：那个辅助函数会直接写 400 响应。
	_ = json.NewDecoder(r.Body).Decode(&req)

	tenant := strings.TrimSpace(req.TenantSlug)
	if tenant == "" && a.SSO != nil {
		tenant = a.SSO.DefaultTenant
	}
	if tenant == "" {
		writeErrHint(w, r, http.StatusBadRequest, "TENANT_REQUIRED",
			"域身份登录需要先确定组织标识",
			"请在登录页填写组织标识后重试，或联系管理员配置默认组织。")
		return
	}

	tk, err := a.Auth.LoginWithAssertion(r.Context(), tenant, user, clientIP(r), r.UserAgent())
	if err != nil {
		var ch *auth.MFAChallenge
		if errors.As(err, &ch) {
			// 与口令登录保持一致：此时不签发任何令牌
			a.auditLogin(r, "", user, nil)
			writeJSON(w, r, http.StatusAccepted, map[string]any{
				"data": map[string]any{
					"mfaRequired": true,
					"challenge":   ch.Challenge,
					"sentTo":      ch.SentTo,
					"expiresIn":   ch.ExpiresIn,
				},
			})
			return
		}
		a.auditLogin(r, "", user, err)
		writeAuthErr(w, r, err)
		return
	}

	// 审计里必须留痕"这次登录没有经过口令"，否则事后无法区分
	// 正常登录与代理断言登录。
	if err := a.emit(r, tk.TenantID, AuditEntry{
		ActorID: tk.UserID, Action: "auth.login", Result: "ok",
		Detail: map[string]any{"username": user, "method": "sso"},
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
		"method":        "sso",
	})
}
