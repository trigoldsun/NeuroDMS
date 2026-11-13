// Package httpapi 组装 HTTP 路由。
//
// 分层纪律：handler 只做"取参 → 调 service → 组装响应"，不写业务规则。
// 每个受保护端点都必须显式声明所需身份，禁止"仅登录即可"的隐式放行。
package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"docvault/internal/auth"
	"docvault/internal/content"
	"docvault/internal/db"
	"docvault/internal/directory"
	"docvault/internal/feature"
	"docvault/internal/iam"
	"docvault/internal/media"
	"docvault/internal/metering"
	"docvault/internal/notify"
	"docvault/internal/onlyoffice"
	"docvault/internal/platform/httpmw"
	"docvault/internal/platformauth"
	"docvault/internal/preview"
	"docvault/internal/rbac"
	"docvault/internal/scan"
	"docvault/internal/secretbox"
	"docvault/internal/tenant"
	"docvault/internal/watermark"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// API 持有全部依赖。
type API struct {
	Pool    *pgxpool.Pool
	Auth    *auth.Service
	Content *content.Store
	// Preview 为 nil 表示未启用在线预览（前端降级为下载）
	Preview *preview.Cache
	// Raw 为 nil 表示未启用 RAW 解码（未装 LibRaw）；此时 RAW 走"不支持预览"
	Raw *preview.RawRenderer
	// Office 为 nil 表示未配置在线编辑
	Office *onlyoffice.Service
	// Media 为 nil 表示未启用音视频转码
	Media *media.Service
	// MetricsToken 为 /metrics 的独立抓取令牌；为空时该端点一律 401
	MetricsToken string
	// PlatformToken 为平台运营跨租户只读的独立令牌；为空时 /v1/platform/* 一律 401
	PlatformToken string
	// Scanner 为 nil 表示未启用病毒扫描（上传不做扫描，但会显式标注）
	Scanner *scan.Client
	// Watermark 为 nil 表示不叠加溯源水印（预览直接返回转换产物）
	Watermark *watermark.Service
	// ---- M3：多租户 SaaS 能力 ----
	// Tenants 租户生命周期与租户级配置
	Tenants *tenant.Service
	// IAM 成员（账号）管理：建号、改资料、启停、重置口令、角色授予
	IAM *iam.Service
	// Metering 用量计量与配额判定
	Metering *metering.Service
	// Features 灰度开关
	Features *feature.Service
	// PlatformAuth 平台运营账号与会话（与租户账号完全分离）
	PlatformAuth *platformauth.Service
	// SecretBox 用于加密落库的证书私钥与目录服务账号口令；nil 表示未配置密钥
	SecretBox *secretbox.Box

	// 目录认证（LDAP/AD）：Store 管配置，Resolver 供登录按租户取连接，
	// Runner 负责触发同步与自动调度。三者都可为 nil（未启用）。
	Directory   *directory.Store
	DirResolver *directory.Resolver
	DirRunner   *directory.Runner

	// SSO 是域身份单点登录的部署前提与门禁（见 handlers_sso.go）。
	// nil 或 Enabled=false 时相关接口一律不可用。
	SSO *SSOSettings
	// Outbox 是通知外发队列；nil 表示未配置邮件通道（"邮件分享"会明确告知不可用）
	Outbox *notify.Outbox
	// PublicBaseURL 是外发链接使用的对外地址（如 https://ndms.neurongene.cn）。
	// 为空时按请求头推导——但反向代理场景下推导容易出错，生产应显式配置。
	PublicBaseURL string
	// LookupTXT 供域名验证使用（测试可注入）
	LookupTXT func(ctx context.Context, name string) ([]string, error)
	// startedAt 用于暴露进程启动时间
	startedAt time.Time
	Log       *slog.Logger
	// OnAudit 写审计失败会影响调用方返回值：这是 fail-closed 的一部分，
	// "业务成功但审计缺失"比"请求失败"更危险。
	OnAudit AuditFn
	// gate 是只读闸门的进程内缓存（见 tenant_gate.go）
	gate gateCache
}

// AuditFn 是审计写入回调。
type AuditFn func(ctx context.Context, tenantID string, ev AuditEntry) error

// AuditEntry 是审计事件的轻量投影，避免 httpapi 直接依赖 audit 包的具体结构。
type AuditEntry struct {
	ActorID    string
	ActorType  string
	Action     string
	ObjectType string
	ObjectID   string
	Result     string
	Detail     map[string]any
	IP         string
	RequestID  string
}

// Register 注册全部路由。
func (a *API) Register(mux *http.ServeMux) {
	if a.startedAt.IsZero() {
		a.startedAt = time.Now()
	}
	mux.HandleFunc("POST /v1/auth/login", a.handleLogin)
	a.registerSSO(mux)
	mux.HandleFunc("POST /v1/auth/mfa/verify", a.handleMFAVerify)
	mux.HandleFunc("POST /v1/auth/refresh", a.handleRefresh)
	mux.HandleFunc("POST /v1/auth/logout", a.handleLogout)
	mux.HandleFunc("POST /v1/auth/password/change", a.requireAuth(a.handleChangePassword))
	mux.HandleFunc("GET /v1/me", a.requireAuth(a.handleMe))

	a.registerShare(mux)
	a.registerShareVerify(mux)

	a.registerContent(mux)
	a.registerTransfer(mux)
	a.registerWorkspace(mux)
	a.registerACL(mux)
	a.registerGovernance(mux)
	a.registerAdmin(mux)
	a.registerPlatform(mux)
	a.registerPlatformTenants(mux)
	a.registerPlatformUsers(mux)
	a.registerBranding(mux)
	// 租户档位能力查询：前端据此隐藏按钮，不承担安全职责
	a.registerEdition(mux)
	// 格式目录：设置页的"允许上传的格式"与预览能力标注。
	// 放这里而不是 preview 里：它描述的是"本实例能做什么"，与预览是否启用无关，
	// 未启用预览时同样要能返回清单（只是能力全为不可预览）。
	mux.HandleFunc("GET /v1/meta/formats", a.requireAuth(a.handleFormatCatalog))
	a.registerMembers(mux)
	a.registerClassification(mux)
	a.registerBatch(mux)
	a.registerUpload(mux)
	a.registerSearch(mux)
	a.registerProfile(mux)
	a.registerActivity(mux)
	a.registerLDAPAdmin(mux)
	a.registerDirectory(mux)
	a.registerPreview(mux)
	a.registerMedia(mux)
	a.registerOps(mux)
	mux.HandleFunc("GET /robots.txt", a.handleRobots)
}

// ---------------- 中间件 ----------------

type claimsKey struct{}

// requireAuth 解析 Bearer 令牌并把 claims 放入上下文。
func (a *API) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		raw := r.Header.Get("Authorization")
		if !strings.HasPrefix(raw, "Bearer ") {
			writeErr(w, r, http.StatusUnauthorized, "UNAUTHENTICATED", "缺少访问令牌")
			return
		}
		claims, err := a.Auth.Verify(r.Context(), strings.TrimPrefix(raw, "Bearer "))
		if err != nil {
			writeErr(w, r, http.StatusUnauthorized, "SESSION_INVALID", "会话已失效")
			return
		}
		// 只读闸门：租户停用/降级/超配额时统一在这里拒绝写请求。
		// 放在 requireAuth 内部，是因为它是所有受保护端点的唯一入口——
		// 放到各 handler 里必然会在新增接口时漏掉。
		if writableMethod(r.Method) && !gateExempt(r.URL.Path) {
			if blocked, reason := a.tenantWriteBlocked(r.Context(), claims.TenantID); blocked {
				writeErr(w, r, http.StatusForbidden, "TENANT_READONLY",
					"当前租户处于只读状态（"+reason+"），暂时不能执行写操作")
				return
			}
		}

		// API 调用计量：只累加内存计数，由后台按分钟落库。
		// 放在这里是为了"不漏"：任何受保护请求都会经过这个包装。
		if a.Metering != nil {
			a.Metering.CountAPICall(claims.TenantID)
		}

		ctx := context.WithValue(r.Context(), claimsKey{}, claims)
		next(w, r.WithContext(ctx))
	}
}

func claimsFrom(ctx context.Context) (auth.Claims, bool) {
	c, ok := ctx.Value(claimsKey{}).(auth.Claims)
	return c, ok
}

// ---------------- 认证 ----------------

type loginReq struct {
	TenantSlug string `json:"tenantSlug"`
	Username   string `json:"username"`
	Password   string `json:"password"`
	// Mode 指定用哪种身份校验：local / domain / 省略（auto）。
	//
	// 同一租户允许本地与域账号同名，所以"用哪个身份"必须由用户决定。
	// 省略时按 auto 处理（本地优先），保证旧客户端与未接入域的组织行为不变。
	Mode string `json:"mode,omitempty"`
}

func (a *API) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req loginReq
	if !decode(w, r, &req) {
		return
	}
	if req.TenantSlug == "" || req.Username == "" || req.Password == "" {
		writeErr(w, r, http.StatusBadRequest, "INVALID_ARGUMENT", "租户、用户名与口令均为必填")
		return
	}

	mode, merr := auth.ParseLoginMode(req.Mode)
	if merr != nil {
		writeAuthErr(w, r, merr)
		return
	}

	tk, err := a.Auth.Login(r.Context(), req.TenantSlug, req.Username, req.Password, mode,
		clientIP(r), r.UserAgent())
	if err != nil {
		var ch *auth.MFAChallenge
		if errors.As(err, &ch) {
			// 注意：此处不签发任何令牌。返回 202 表示"口令已通过，还需一步"。
			a.auditLogin(r, "", req.Username, nil)
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
		a.auditLogin(r, "", req.Username, err)
		writeAuthErr(w, r, err)
		return
	}
	if err := a.emit(r, tk.TenantID, AuditEntry{
		ActorID: tk.UserID, Action: "auth.login", Result: "ok",
		Detail: map[string]any{"username": req.Username},
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

// handleMFAVerify 用验证码完成登录。
func (a *API) handleMFAVerify(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Challenge string `json:"challenge"`
		Code      string `json:"code"`
	}
	if !decode(w, r, &req) {
		return
	}
	if req.Challenge == "" || req.Code == "" {
		writeErr(w, r, http.StatusBadRequest, "INVALID_ARGUMENT", "challenge 与 code 均为必填")
		return
	}

	tk, err := a.Auth.VerifyMFA(r.Context(), req.Challenge, req.Code, clientIP(r), r.UserAgent())
	if err != nil {
		// 失败也写审计：二次验证失败率是账号被盗的早期信号
		_ = a.emit(r, "", AuditEntry{
			ActorType: "user", Action: "auth.mfa", Result: "denied",
			Detail: map[string]any{"reason": err.Error()},
		})
		if errors.Is(err, auth.ErrCodeInvalid) {
			writeErr(w, r, http.StatusUnauthorized, "CODE_INVALID", "验证码不正确或已失效")
			return
		}
		if errors.Is(err, auth.ErrChallengeStale) {
			writeErr(w, r, http.StatusUnauthorized, "CHALLENGE_STALE", "验证会话已失效，请重新登录")
			return
		}
		writeAuthErr(w, r, err)
		return
	}
	if err := a.emit(r, tk.TenantID, AuditEntry{
		ActorID: tk.UserID, Action: "auth.mfa", Result: "ok",
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

func (a *API) handleRefresh(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RefreshToken string `json:"refreshToken"`
	}
	if !decode(w, r, &req) {
		return
	}
	tk, err := a.Auth.Refresh(r.Context(), req.RefreshToken, clientIP(r), r.UserAgent())
	if err != nil {
		// 重放是安全事件，不是普通失败：必须进审计，否则"谁的会话因为
		// 令牌被复用而吊销"只留在应用日志里，事后无法从审计侧还原。
		var replay *auth.RefreshReplayError
		if errors.As(err, &replay) {
			_ = a.emit(r, replay.TenantID, AuditEntry{
				ActorID: replay.UserID, Action: "auth.refresh_replay", ObjectID: replay.SessionID,
				Result: "denied",
				Detail: map[string]any{"reason": "token_reuse", "ip": clientIP(r)},
			})
			writeErr(w, r, http.StatusUnauthorized, "REFRESH_REPLAY",
				"检测到凭证重复使用，出于安全已结束该会话，请重新登录")
			return
		}
		writeAuthErr(w, r, err)
		return
	}
	writeOK(w, r, map[string]any{
		"accessToken":   tk.Access,
		"refreshToken":  tk.Refresh,
		"accessExpires": tk.AccessExpires.UTC().Format(time.RFC3339),
	})
}

func (a *API) handleLogout(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RefreshToken string `json:"refreshToken"`
	}
	if !decode(w, r, &req) {
		return
	}
	if err := a.Auth.Logout(r.Context(), req.RefreshToken); err != nil {
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "登出失败")
		return
	}
	writeOK(w, r, map[string]any{"loggedOut": true})
}

func (a *API) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	var req struct {
		OldPassword string `json:"oldPassword"`
		NewPassword string `json:"newPassword"`
	}
	if !decode(w, r, &req) {
		return
	}
	raw := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if err := a.Auth.ChangePassword(r.Context(), raw, req.OldPassword, req.NewPassword); err != nil {
		writeAuthErr(w, r, err)
		return
	}
	writeOK(w, r, map[string]any{"changed": true, "sessionsRevoked": true})
}

func (a *API) handleMe(w http.ResponseWriter, r *http.Request) {
	c, _ := claimsFrom(r.Context())

	// 前端需要用户名与角色来决定"是否显示管理入口"。
	// 只回角色编码（sysadmin/secadmin/auditor），不回权限明细：
	// 界面据此显示/隐藏入口，真正的拦截始终在服务端。
	var (
		username, displayName, email string
		// 用空切片而非 nil：nil slice 序列化是 null，前端 .length 会直接抛错
		roles                   = []string{}
		classification, ceiling int
	)
	_ = db.WithTenant(r.Context(), a.Pool, c.TenantID, func(tx pgx.Tx) error {
		if err := tx.QueryRow(r.Context(), `
			SELECT username, COALESCE(display_name,''), COALESCE(email,''), classification, ceiling
			  FROM app_user WHERE id = $1`, c.Subject).
			Scan(&username, &displayName, &email, &classification, &ceiling); err != nil {
			return err
		}
		rs, err := rbac.RolesOf(r.Context(), tx, c.TenantID, c.Subject)
		roles = rs
		return err
	})

	writeOK(w, r, map[string]any{
		"userId": c.Subject, "tenantId": c.TenantID,
		"sessionId": c.SessionID, "epoch": c.Epoch,
		"expiresAt": c.ExpiresAt.UTC().Format(time.RFC3339),
		"username":  username, "displayName": displayName, "email": email,
		"classification": classification, "ceiling": ceiling,
		"roles": roles,
	})
}

// logErr 安全地写错误日志。
//
// 为什么需要它：测试与部分嵌入场景不会注入 Logger，而 *slog.Logger 为 nil 时
// 调用 Error 会直接 panic——一次"记日志"把整个请求打成 500 甚至断连。
func (a *API) logErr(msg string, args ...any) {
	if a.Log != nil {
		a.Log.Error(msg, args...)
	}
}

// ---------------- 工具 ----------------

func (a *API) emit(r *http.Request, tenantID string, ev AuditEntry) error {
	if a.OnAudit == nil || tenantID == "" {
		return nil
	}
	ev.IP = clientIP(r)
	ev.RequestID = httpmw.RequestIDFrom(r.Context())
	return a.OnAudit(r.Context(), tenantID, ev)
}

func (a *API) auditLogin(r *http.Request, tenantID, username string, err error) {
	result := "ok"
	detail := map[string]any{"username": username}
	switch {
	case err == nil:
	case errors.Is(err, auth.ErrInvalidCredentials):
		result = "denied"
	case errors.Is(err, auth.ErrAccountLocked):
		result, detail["reason"] = "denied", "locked"
	case errors.Is(err, auth.ErrAccountDisabled):
		result, detail["reason"] = "denied", "disabled"
	default:
		result = "error"
	}
	if tenantID == "" {
		return // 无租户上下文无法写入受 RLS 保护的审计表
	}
	_ = a.emit(r, tenantID, AuditEntry{ActorType: "user", Action: "auth.login", Result: result, Detail: detail})
}

func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(v); err != nil {
		writeErr(w, r, http.StatusBadRequest, "INVALID_ARGUMENT", "请求体不是合法 JSON")
		return false
	}
	return true
}

func writeOK(w http.ResponseWriter, r *http.Request, data any) {
	writeJSON(w, r, http.StatusOK, map[string]any{
		"code": "OK", "message": "success", "requestId": httpmw.RequestIDFrom(r.Context()), "data": data,
	})
}

func writeErr(w http.ResponseWriter, r *http.Request, status int, code, msg string) {
	writeJSON(w, r, status, map[string]any{
		"code": code, "message": msg, "requestId": httpmw.RequestIDFrom(r.Context()), "data": nil,
	})
}

// writeErrHint 在错误体里附带"下一步怎么做"。
//
// 登录失败是唯一一类"用户能自己解决"的错误：口令过期要去改口令、
// 没同步要找管理员跑同步、目录挂了要等运维。只给一句"失败"，
// 用户只能来问客服；给出下一步，大部分情况能自助走通。
func writeErrHint(w http.ResponseWriter, r *http.Request, status int, code, msg, hint string) {
	body := map[string]any{
		"code": code, "message": msg, "requestId": httpmw.RequestIDFrom(r.Context()), "data": nil,
	}
	if hint != "" {
		body["hint"] = hint
	}
	writeJSON(w, r, status, body)
}

func writeJSON(w http.ResponseWriter, r *http.Request, status int, body any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeAuthErr(w http.ResponseWriter, r *http.Request, err error) {
	hint := auth.Hint(err)
	write := func(status int, code string) {
		writeErrHint(w, r, status, code, err.Error(), hint)
	}

	switch {
	case errors.Is(err, auth.ErrInvalidCredentials):
		write(http.StatusUnauthorized, "INVALID_CREDENTIALS")
	case errors.Is(err, auth.ErrAccountLocked):
		write(http.StatusTooManyRequests, "ACCOUNT_LOCKED")
	case errors.Is(err, auth.ErrAccountDisabled):
		write(http.StatusForbidden, "ACCOUNT_DISABLED")
	case errors.Is(err, auth.ErrSessionInvalid):
		write(http.StatusUnauthorized, "SESSION_INVALID")
	case errors.Is(err, auth.ErrWeakPassword):
		write(http.StatusBadRequest, "WEAK_PASSWORD")
	case errors.Is(err, auth.ErrUnknownLoginMode):
		write(http.StatusBadRequest, "INVALID_LOGIN_MODE")
	case errors.Is(err, auth.ErrDomainNotSynced):
		// 409：凭据是对的，是"状态没对齐"，不是鉴权失败
		write(http.StatusConflict, "DOMAIN_ACCOUNT_NOT_SYNCED")
	case errors.Is(err, auth.ErrDirectoryNotConfigured):
		write(http.StatusConflict, "DIRECTORY_NOT_CONFIGURED")
	case errors.Is(err, auth.ErrDomainUnavailable):
		write(http.StatusServiceUnavailable, "DIRECTORY_UNAVAILABLE")
	case errors.Is(err, auth.ErrDomainLocked):
		write(http.StatusLocked, "DIRECTORY_ACCOUNT_LOCKED")
	case errors.Is(err, auth.ErrDomainPasswordExpired):
		write(http.StatusForbidden, "DIRECTORY_PASSWORD_EXPIRED")
	case errors.Is(err, auth.ErrDomainPasswordMustChg):
		write(http.StatusForbidden, "DIRECTORY_PASSWORD_CHANGE_REQUIRED")
	case errors.Is(err, auth.ErrDomainDisabledInDir):
		write(http.StatusForbidden, "DIRECTORY_ACCOUNT_DISABLED")
	default:
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "处理失败")
	}
}

// clientIP 取本次请求的来源地址。
//
// 反向代理场景下 r.RemoteAddr 已经被 httpmw.RealIP 改写为真实客户端地址
// （仅当直连来源在可信网段内），因此这里仍然只读 RemoteAddr 即可：
// 不在网关层再做一次 XFF 解析，避免两处解析规则不一致。
func clientIP(r *http.Request) string {
	host := r.RemoteAddr
	if i := strings.LastIndex(host, ":"); i > 0 {
		host = strings.Trim(host[:i], "[]")
	}
	if host == "" {
		return ""
	}
	return host
}
