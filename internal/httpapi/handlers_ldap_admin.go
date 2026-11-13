package httpapi

// 目录认证（LDAP/AD）配置接口。
//
// PRD-IAM-11：配置页 + 「测试连接」返回匿名/绑定两种结果；
// PRD-IAM-20：每次同步记录耗时、条数、错误。
//
// 只对 sysadmin 开放：目录配置能决定"谁能登录"，与"改谁的权限"同级，
// secadmin/auditor 都不应能改（前者管密级，后者只读审计）。

import (
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"docvault/internal/directory"
	"docvault/internal/rbac"
)

func (a *API) registerLDAPAdmin(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/admin/directory", a.requireRole(rbac.SysAdmin)(a.handleGetDirectory))
	mux.HandleFunc("PUT /v1/admin/directory", a.requireRole(rbac.SysAdmin)(a.handlePutDirectory))
	mux.HandleFunc("POST /v1/admin/directory/test", a.requireRole(rbac.SysAdmin)(a.handleTestDirectory))
	mux.HandleFunc("POST /v1/admin/directory/sync", a.requireRole(rbac.SysAdmin)(a.handleSyncDirectory))
	mux.HandleFunc("GET /v1/admin/directory/runs", a.requireRole(rbac.SysAdmin)(a.handleDirectoryRuns))
}

// publicDirectoryView 抹掉口令与 CA 正文，只保留"有没有设置"。
//
// 即使是 sysadmin 也不回显口令：回显一次就会进浏览器缓存、录屏、工单截图，
// 之后再也收不回来。CA 正文不回传是为了避免每次读配置都搬一份大文本，
// 界面上用 hasCA 表示已配置，需要替换时重新粘贴即可。
func publicDirectoryView(s directory.Settings) directory.Settings {
	s.BindPassword = ""
	s.HasCA = strings.TrimSpace(s.CAPEM) != ""
	s.CAPEM = ""
	return s
}

func (a *API) handleGetDirectory(w http.ResponseWriter, r *http.Request) {
	c, _ := claimsFrom(r.Context())
	if a.DirResolver == nil || a.Directory == nil {
		writeErr(w, r, http.StatusNotImplemented, "DIRECTORY_UNAVAILABLE", "目录配置未启用")
		return
	}
	s, err := a.DirResolver.Effective(r.Context(), c.TenantID)
	if err != nil {
		a.logErr("读取目录配置失败", "err", err)
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "读取配置失败")
		return
	}
	if s.Source == "env" {
		// 环境变量来源的口令只在内存里，同样只报"有没有"
		s.HasPassword = s.BindPassword != ""
	}
	writeOK(w, r, publicDirectoryView(s))
}

func (a *API) handlePutDirectory(w http.ResponseWriter, r *http.Request) {
	c, _ := claimsFrom(r.Context())
	if a.Directory == nil {
		writeErr(w, r, http.StatusNotImplemented, "DIRECTORY_UNAVAILABLE", "目录配置未启用")
		return
	}
	// 目录认证是专业版及以上能力。拦在保存入口而不是只藏设置页：
	// 否则基础版客户拿到接口地址就能把域口令写进去，形成"配置好了但不生效"的困惑。
	if ed, eerr := a.editionState(r.Context(), c.TenantID); eerr != nil {
		writeErr(w, r, http.StatusServiceUnavailable, "ENTITLEMENT_UNAVAILABLE",
			"无法读取租户档位，请稍后重试")
		return
	} else if !ed.Spec.AD {
		writeErr(w, r, http.StatusForbidden, "FEATURE_NOT_ENABLED",
			"当前档位（"+ed.Spec.Name+"）不支持目录认证，请升级后使用")
		return
	}
	if a.SecretBox == nil || !a.SecretBox.Available() {
		// 没有密钥就无法加密保存域口令；明文落库是绝对不能接受的降级
		writeErr(w, r, http.StatusConflict, "NO_SECRET_KEY",
			"未配置 DOCVAULT_SECRET_KEY，无法加密保存目录口令")
		return
	}

	var in directory.Settings
	if !decode(w, r, &in) {
		return
	}
	// 前端拿不到 CA 正文，未提交时保留库里的旧值
	if strings.TrimSpace(in.CAPEM) == "" {
		if old, err := a.Directory.Load(r.Context(), c.TenantID); err == nil {
			in.CAPEM = old.CAPEM
		}
	}

	saved, err := a.Directory.Save(r.Context(), c.TenantID, c.Subject, in)
	if err != nil {
		switch {
		case errors.Is(err, directory.ErrInvalidInput):
			writeErr(w, r, http.StatusBadRequest, "INVALID_ARGUMENT", err.Error())
		case errors.Is(err, directory.ErrNoSecretKey):
			writeErr(w, r, http.StatusConflict, "NO_SECRET_KEY", err.Error())
		default:
			a.logErr("保存目录配置失败", "err", err)
			writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "保存失败")
		}
		return
	}
	// 立即失效缓存：保存后下一次登录就该用新配置，而不是等 60 秒
	if a.DirResolver != nil {
		a.DirResolver.Invalidate(c.TenantID)
	}

	host, port := ldapHostPort(saved.URL)
	_ = a.emit(r, c.TenantID, AuditEntry{
		ActorID: c.Subject, Action: "directory.config.update", Result: "ok",
		Detail: map[string]any{
			"enabled": saved.Enabled, "host": host, "port": port,
			"baseDn": saved.BaseDN, "adMode": saved.ADMode,
			"startTls":  saved.StartTLS,
			"plaintext": !saved.StartTLS && !strings.HasPrefix(saved.URL, "ldaps://"),
			"syncEvery": saved.SyncIntervalMinutes,
		},
	})
	writeOK(w, r, publicDirectoryView(saved))
}

func (a *API) handleTestDirectory(w http.ResponseWriter, r *http.Request) {
	c, _ := claimsFrom(r.Context())
	if a.Directory == nil {
		writeErr(w, r, http.StatusNotImplemented, "DIRECTORY_UNAVAILABLE", "目录配置未启用")
		return
	}

	var in directory.Settings
	if !decode(w, r, &in) {
		return
	}
	// 口令留空 = 用已保存的那个（"我只改了端口，用原口令测一下"是最常见的操作）
	old, _ := a.Directory.Load(r.Context(), c.TenantID)
	if in.BindPassword == "" {
		in.BindPassword = old.BindPassword
	}
	if strings.TrimSpace(in.CAPEM) == "" {
		in.CAPEM = old.CAPEM
	}

	// 只校验地址，不要求过滤器等字段齐全：管理员常常先测连通再补细节。
	// 但地址校验必须与保存时一致——那正是防 SSRF 的那一层。
	if err := directory.ValidateAddress(in.URL); err != nil {
		writeErr(w, r, http.StatusBadRequest, "INVALID_ARGUMENT", err.Error())
		return
	}

	res := directory.Probe(r.Context(), in)
	host, port := ldapHostPort(in.URL)
	_ = a.emit(r, c.TenantID, AuditEntry{
		ActorID: c.Subject, Action: "directory.test",
		Result: probeResultCode(res),
		Detail: map[string]any{
			"host": host, "port": port, "anonymous": res.Anonymous,
			"bind": res.Bind, "baseRead": res.BaseRead, "reason": res.Reason,
		},
	})
	// 连通失败不是 500：这是"测试的结论"，界面要展示原因，而不是弹一个系统错误
	writeOK(w, r, res)
}

func probeResultCode(res directory.ProbeResult) string {
	if res.Bind {
		return "ok"
	}
	return "error"
}

func (a *API) handleSyncDirectory(w http.ResponseWriter, r *http.Request) {
	c, _ := claimsFrom(r.Context())
	if a.DirRunner == nil {
		writeErr(w, r, http.StatusNotImplemented, "DIRECTORY_UNAVAILABLE", "目录同步未启用")
		return
	}
	// 同步与保存同属目录认证能力，不能只在保存处把关。
	if ed, eerr := a.editionState(r.Context(), c.TenantID); eerr != nil {
		writeErr(w, r, http.StatusServiceUnavailable, "ENTITLEMENT_UNAVAILABLE",
			"无法读取租户档位，请稍后重试")
		return
	} else if !ed.Spec.AD {
		writeErr(w, r, http.StatusForbidden, "FEATURE_NOT_ENABLED",
			"当前档位（"+ed.Spec.Name+"）不支持目录认证，请升级后使用")
		return
	}
	var req struct {
		Mode string `json:"mode"` // full | incremental
	}
	// 允许空 body：不传就是增量
	if r.ContentLength > 0 {
		if !decode(w, r, &req) {
			return
		}
	}
	if req.Mode == "" {
		req.Mode = "incremental"
	}

	if err := a.DirRunner.Trigger(r.Context(), c.TenantID, req.Mode); err != nil {
		switch {
		case errors.Is(err, directory.ErrSyncRunning):
			writeErr(w, r, http.StatusConflict, "SYNC_RUNNING", err.Error())
		case errors.Is(err, directory.ErrNotConfigured):
			writeErr(w, r, http.StatusBadRequest, "DIRECTORY_NOT_CONFIGURED", err.Error())
		default:
			a.logErr("触发目录同步失败", "err", err)
			writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "触发同步失败")
		}
		return
	}
	_ = a.emit(r, c.TenantID, AuditEntry{
		ActorID: c.Subject, Action: "directory.sync", Result: "ok",
		Detail: map[string]any{"mode": req.Mode},
	})
	// 已受理：同步可能跑几分钟，进度由 /runs 轮询
	writeOK(w, r, map[string]any{"accepted": true, "mode": req.Mode})
}

func (a *API) handleDirectoryRuns(w http.ResponseWriter, r *http.Request) {
	c, _ := claimsFrom(r.Context())
	if a.DirRunner == nil {
		writeErr(w, r, http.StatusNotImplemented, "DIRECTORY_UNAVAILABLE", "目录同步未启用")
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	rows, err := a.DirRunner.Runs(r.Context(), c.TenantID, limit)
	if err != nil {
		a.logErr("读取同步记录失败", "err", err)
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "读取记录失败")
		return
	}
	writeOK(w, r, map[string]any{"items": rows})
}

// ldapHostPort 拆出主机与端口用于审计。
// 不记完整 URL：地址里可能带查询串或内嵌凭据（ldap://user:pass@host）。
func ldapHostPort(raw string) (string, int) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", 0
	}
	port := 0
	switch {
	case u.Port() != "":
		port, _ = strconv.Atoi(u.Port())
	case u.Scheme == "ldaps":
		port = 636
	case u.Scheme == "ldap":
		port = 389
	}
	return u.Hostname(), port
}
