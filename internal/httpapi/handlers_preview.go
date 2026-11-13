package httpapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"docvault/internal/authz"
	"docvault/internal/content"
	"docvault/internal/db"
	"docvault/internal/preview"
	"docvault/internal/share"
	"docvault/internal/watermark"

	"github.com/jackc/pgx/v5"
)

// registerPreview 注册预览与在线编辑路由。
func (a *API) registerPreview(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/nodes/{id}/preview", a.requireAuth(a.handlePreview))
	mux.HandleFunc("GET /v1/nodes/{id}/edit", a.requireAuth(a.handleEditConfig))

	// 编辑会话：打开编辑时登记，前端定时心跳续期，回退时据此拒绝。
	mux.HandleFunc("POST /v1/nodes/{id}/doc-session/ping", a.requireAuth(a.handleDocSessionPing))
	mux.HandleFunc("GET /v1/nodes/{id}/doc-session", a.requireAuth(a.handleDocSessionList))

	// 供 ONLYOFFICE 文档服务访问（无会话，靠签名 URL / JWT 校验）
	mux.HandleFunc("GET /v1/onlyoffice/file/{id}", a.handleOfficeFile)
	mux.HandleFunc("POST /v1/onlyoffice/callback", a.handleOfficeCallback)
}

// 可内联直出的类型：不需要转换，直接流式返回。
//
// 先补 mime 再判断：iPhone 拍的 HEIC、WPS 导出的 docx 常常不带有效 Content-Type，
// 库里存成空或 application/octet-stream。只看 mime 会把它们当"未知二进制"，
// 一路丢给 LibreOffice，最后返回"转换失败，请下载后查看"——
// 用户看到的是"预览坏了"，而真实原因只是扩展名没被识别。
func inlineMime(mime string, name string) bool {
	mime = strings.ToLower(strings.TrimSpace(mime))
	if mime == "" || mime == "application/octet-stream" {
		mime = mimeByExt(name)
	}
	switch {
	case mime == "application/pdf":
		return true
	case strings.HasPrefix(mime, "image/"):
		return true
	case strings.HasPrefix(mime, "text/"), mime == "application/json", mime == "application/xml":
		return true
	case strings.HasPrefix(mime, "audio/"), strings.HasPrefix(mime, "video/"):
		return true
	}
	return false
}

func extOf(name string) string {
	if i := strings.LastIndex(name, "."); i >= 0 {
		return name[i:]
	}
	return ""
}

// safeInlineType 把"会以本域文档身份渲染"的类型降级为纯文本。
//
// 为什么要拦：预览页把内容放进同源 <iframe>。一旦响应是 text/html，
// 浏览器就把它当成**本站文档**渲染——同源 iframe 拥有完整的父页面 DOM 权限，
// 于是"上传一份 HTML 就能读写 localStorage 里的访问令牌"。
// 全局 CSP（script-src 'self'）能挡住内联脚本，但挡不住
// <meta http-equiv=refresh> 跳转、<form action="//evil"> 钓鱼表单这些非脚本手法。
//
// SVG 不在此列：它在入库前已被 SanitizeSVG 白名单重写（脚本/事件处理器/
// foreignObject 全部移除），保留 image/svg+xml 才能作为图片正常显示。
func safeInlineType(ct string) string {
	base := strings.ToLower(strings.TrimSpace(ct))
	if i := strings.IndexByte(base, ';'); i >= 0 {
		base = strings.TrimSpace(base[:i])
	}
	switch {
	case base == "text/html",
		base == "application/xhtml+xml",
		base == "text/xml",
		base == "application/xml",
		// 其余 *+xml（rss/atom/xslt…）同样按可执行文档处理
		strings.HasSuffix(base, "+xml") && base != "image/svg+xml":
		return "text/plain; charset=utf-8"
	}
	return ct
}

// handlePreview 返回可在线查看的 PDF（或内联原始字节）。
//
// 权限位用 preview 而不是 download：允许"看一眼"不等于允许"拿走"。
func (a *API) handlePreview(w http.ResponseWriter, r *http.Request) {
	c, _ := claimsFrom(r.Context())
	nodeID := r.PathValue("id")

	n, err := a.Content.GetNode(r.Context(), c.TenantID, nodeID)
	if err != nil {
		writeErr(w, r, http.StatusNotFound, "NOT_FOUND", "对象不存在")
		return
	}
	d, err := a.check(r.Context(), c, n.SpaceID, nodeID, authz.Preview)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "权限判定失败")
		return
	}
	if a.denyUnless(w, r, d) {
		return
	}
	if n.Kind != "file" {
		writeErr(w, r, http.StatusBadRequest, "INVALID_ARGUMENT", "目录不支持预览")
		return
	}

	// 预览此前完全没有埋点：用户日志里"看过什么"是一片空白，
	// 而预览恰恰是敏感文件最常见的接触方式（不必下载也能读全文）。
	_ = a.emit(r, c.TenantID, AuditEntry{
		ActorID: c.Subject, ActorType: "user", Action: "node.preview",
		ObjectType: "node", ObjectID: nodeID, Result: "ok",
		Detail: map[string]any{"name": n.Name},
	})

	// 已经是可直接看的内容：直接流出去，不做无意义的转换。
	//
	// 但 PDF 是例外（AC-55）：对 PDF 直接返回原字节，等于"通过预览接口取回原件"，
	// 密级、水印、下载位三道控制全部被绕过。所以 PDF 必须先过水印再输出。
	if inlineMime(n.Mime, n.Name) {
		rc, node, oerr := a.Content.OpenContent(r.Context(), c.TenantID, nodeID)
		if oerr != nil {
			writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "内容不可用")
			return
		}
		defer func() { _ = rc.Close() }()

		ct := node.Mime
		if ct == "" || ct == "application/octet-stream" {
			ct = mimeByExt(node.Name)
		}
		ct = safeInlineType(ct)
		if ct == "application/pdf" && a.Watermark != nil {
			raw, rerr := io.ReadAll(io.LimitReader(rc, maxWatermarkBytes+1))
			if rerr != nil || int64(len(raw)) > maxWatermarkBytes {
				writeErr(w, r, http.StatusRequestEntityTooLarge, "PREVIEW_TOO_LARGE",
					"文件过大，无法生成带水印的预览，请下载后查看")
				return
			}
			if !a.writeWatermarkedPDF(w, r, raw) {
				return
			}
			return
		}
		w.Header().Set("Content-Type", ct)
		w.Header().Set("Content-Disposition", "inline")
		w.Header().Set("Content-Length", strconv.FormatInt(node.SizeBytes, 10))
		w.Header().Set("Cache-Control", "private, max-age=60")
		w.WriteHeader(http.StatusOK)
		_, _ = io.Copy(w, rc)
		return
	}

	// RAW 走独立通道：LibRaw 解码 + 内嵌图首屏。它不依赖 LibreOffice，
	// 所以必须放在下面的 Preview==nil 判断之前。
	if a.tryRawPreview(w, r, c.TenantID, n) {
		return
	}

	if a.Preview == nil {
		// 未安装转换器时明确告知，前端可降级为"下载后本地查看"
		writeErr(w, r, http.StatusNotImplemented, "PREVIEW_UNAVAILABLE",
			"服务器未启用在线预览，请下载后查看")
		return
	}

	// 缓存 key 用"节点 + 大小 + 更新时间"：内容变了 key 就变，
	// 避免用户看到上一版的渲染结果
	key := fmt.Sprintf("%s:%d:%d", n.ID, n.SizeBytes, n.UpdatedAt.UnixNano())
	entry, err := a.Preview.Get(r.Context(), key, n.Name, func() (io.ReadCloser, error) {
		rc, _, oerr := a.Content.OpenContent(r.Context(), c.TenantID, nodeID)
		return rc, oerr
	})
	if err != nil {
		if errors.Is(err, preview.ErrUnsupported) {
			writeErr(w, r, http.StatusNotImplemented, "PREVIEW_UNAVAILABLE", "该类型暂不支持预览")
			return
		}
		writeErr(w, r, http.StatusInternalServerError, "PREVIEW_FAILED", "转换失败，请下载后查看")
		return
	}

	if a.Watermark != nil {
		// 转换产物（无水印 PDF）按版本缓存，水印在响应时叠加：
		// 若把带个人水印的 PDF 也缓存，缓存 key 就要带上用户维度，
		// 结果是"每个用户每份文件一份 PDF"，缓存会迅速失控。
		if entry.Size > maxWatermarkBytes {
			writeErr(w, r, http.StatusRequestEntityTooLarge, "PREVIEW_TOO_LARGE",
				"文件过大，无法生成带水印的预览，请下载后查看")
			return
		}
		raw, rerr := os.ReadFile(entry.Path)
		if rerr != nil {
			writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "读取预览失败")
			return
		}
		if !a.writeWatermarkedPDF(w, r, raw) {
			return
		}
		return
	}

	f, err := os.Open(entry.Path)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "读取预览失败")
		return
	}
	defer func() { _ = f.Close() }()

	w.Header().Set("Content-Type", "application/pdf")
	w.Header().Set("Content-Disposition", "inline")
	w.Header().Set("Content-Length", strconv.FormatInt(entry.Size, 10))
	w.Header().Set("Cache-Control", "private, max-age=300")
	w.Header().Set("X-Preview-Cache", map[bool]string{true: "hit", false: "miss"}[entry.FromCache])
	w.WriteHeader(http.StatusOK)
	_, _ = io.Copy(w, f)
}

// maxWatermarkBytes 是允许叠加水印的 PDF 上限。
// 超过就明确拒绝（而不是"跳过水印直接给原件"）——后者正是 AC-55 要防的事。
const maxWatermarkBytes int64 = 80 << 20

// writeWatermarkedPDF 给 PDF 叠水印并写出响应。返回 false 表示已写错误响应。
func (a *API) writeWatermarkedPDF(w http.ResponseWriter, r *http.Request, pdf []byte) bool {
	c, _ := claimsFrom(r.Context())
	account, footer := a.watermarkParts(r, c.TenantID, c.Subject)
	out, err := a.Watermark.Apply(r.Context(), pdf, account, footer)
	if err != nil {
		// 水印失败必须拒绝：返回未加水印的原件等于水印静默失效
		_ = a.emit(r, c.TenantID, AuditEntry{
			ActorID: c.Subject, Action: "preview.watermark", Result: "error",
			Detail: map[string]any{"reason": err.Error()},
		})
		writeErr(w, r, http.StatusInternalServerError, "WATERMARK_FAILED",
			"水印生成失败，已拒绝返回未加水印的预览")
		return false
	}
	w.Header().Set("Content-Type", "application/pdf")
	// inline + 不缓存：带个人水印的响应不能被中间层缓存后发给别人
	w.Header().Set("Content-Disposition", "inline")
	w.Header().Set("Content-Length", strconv.Itoa(len(out)))
	w.Header().Set("Cache-Control", "private, no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(out)
	return true
}

// watermarkParts 返回两层水印文字：账号（主）与页脚明细。
//
// 分成两层是页宽决定的：斜向平铺的长句会被裁掉句首，而"谁"恰恰在最前面。
// 主水印只放账号保证完整可见；时间与来源放页脚，取证时读得出来。
//
// 用登录名而不是 UUID：UUID 对人无意义，截图传播时看到 UUID 也追不到人。
func (a *API) watermarkParts(r *http.Request, tenantID, userID string) (account, footer string) {
	// 一次查询取齐：显示名（可能中文，需中文字体）+ 登录名 + 邮箱。
	// 三者一起写进水印，是为了让截图在不同语境下都能追到人：
	// 中文名便于业务同事辨认，登录名与邮箱便于管理员在日志里检索。
	var (
		username    string
		displayName string
		email       *string
	)
	_ = db.WithTenant(r.Context(), a.Pool, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(r.Context(), `
			SELECT username, COALESCE(display_name,''), email FROM app_user WHERE id = $1`, userID).
			Scan(&username, &displayName, &email)
	})
	if username == "" {
		username = userID
	}
	// 显示名优先（更易被人认出），登录名作为补充放在括号里便于管理员检索。
	// 邮箱不进正文：它最长，且可由账号反查，写进来只会把水印撑到超出页宽。
	// 主水印放"显示名 + 时分"：用 rotation 模式后宽度可控，
	// 40pt 下 8 个字符约 300pt，远小于页宽（595pt），可以完整显示中文名。
	account = username
	if displayName != "" && displayName != username {
		account = displayName
	}
	account = account + " " + time.Now().UTC().Format("15:04")
	_ = email
	// 页脚：精确时间（UTC，与审计一致）+ 来源 IP + 用途说明
	// 页脚只放"时间 + 来源"：再长的提示语在中文宽度估算偏差下会顶到右边界。
	// "禁止外传"这类提示放在预览页顶部的徽标与页脚之外，不占水印空间。
	// 页脚带上账号：主水印在极端宽高比的页面上会被裁切（见 publicWatermarkParts），
	// 页脚是短文本、左下角对齐，必须能独立回答"这是谁看的"。
	footer = watermark.FooterText(
		time.Now().UTC().Format("2006-01-02 15:04:05Z"),
		clientIP(r),
		username,
	)
	return account, footer
}

// publicWatermarkParts 是"匿名访客"版本的水印文字。
//
// 访客没有账号，能标识他的只有三样东西：哪条分享、从哪个 IP、什么时间。
// 三项拼起来足以在截图外流时定位到具体链接与访问来源。
// 主水印保持短（share-<8位>）：斜向平铺时长句会被裁掉句首，反而丢失可辨识信息。
func publicWatermarkParts(t share.Ticket, ip string) (account, footer string) {
	id := t.ShareID
	if len(id) > 8 {
		id = id[:8]
	}
	account = "share-" + id
	// 分享标识必须**同时**放进页脚。
	//
	// 主水印是 45° 斜向平铺的，在极端宽高比的页面上（例如表格导出成
	// 2008×274 的宽条）会被页面边界裁掉大半，实测只剩 "e-a95" 这种碎片，
	// 取证时等于没有。页脚是左下角的短文本，不会被裁。
	footer = watermark.FooterText(
		time.Now().UTC().Format("2006-01-02 15:04:05Z"),
		ip,
		"share-"+id,
	)
	return account, footer
}

// mimeByExt 按扩展名推断 MIME。
//
// 只列浏览器能直接渲染或服务端能原样流式返回的类型；
// office 文档不在这里——它们必须走 LibreOffice 转换，猜错 mime 只会让转换器更困惑。
func mimeByExt(name string) string {
	switch strings.ToLower(extOf(name)) {
	case ".pdf":
		return "application/pdf"
	case ".png":
		return "image/png"
	case ".jpg", ".jpeg":
		return "image/jpeg"
	case ".gif":
		return "image/gif"
	case ".webp":
		return "image/webp"
	case ".bmp":
		return "image/bmp"
	case ".ico":
		return "image/x-icon"
	case ".avif":
		return "image/avif"
	// HEIC/HEIF：服务端不解码，原样返回字节，由前端 wasm 转码后显示
	case ".heic":
		return "image/heic"
	case ".heif":
		return "image/heif"
	case ".svg":
		return "image/svg+xml"
	case ".tif", ".tiff":
		return "image/tiff"
	case ".mp4", ".m4v":
		return "video/mp4"
	case ".mov":
		return "video/quicktime"
	case ".webm":
		return "video/webm"
	case ".mkv":
		return "video/x-matroska"
	case ".mp3":
		return "audio/mpeg"
	case ".wav":
		return "audio/wav"
	case ".m4a":
		return "audio/mp4"
	case ".ogg":
		return "audio/ogg"
	// FLAC 与 OGV：Chrome/Firefox/现代 Safari 都能直接播，标 none 是低估能力
	case ".flac":
		return "audio/flac"
	case ".ogv":
		return "video/ogg"
	case ".txt", ".log":
		return "text/plain; charset=utf-8"
	case ".md":
		return "text/markdown; charset=utf-8"
	case ".csv":
		return "text/csv; charset=utf-8"
	case ".tsv":
		return "text/tab-separated-values; charset=utf-8"
	// 代码与配置：按纯文本预览（不执行），让"看一眼配置文件"不用下载
	case ".json":
		return "application/json"
	case ".xml":
		return "application/xml"
	case ".yaml", ".yml":
		return "text/yaml; charset=utf-8"
	case ".toml":
		return "text/plain; charset=utf-8"
	case ".ini", ".conf":
		return "text/plain; charset=utf-8"
	case ".sql", ".js", ".ts", ".py", ".java", ".go", ".sh", ".css":
		return "text/plain; charset=utf-8"
	case ".html", ".htm":
		// 不上内联：HTML 同源渲染等于给 XSS 开门，让它走下载
		return "application/octet-stream"
	default:
		return "application/octet-stream"
	}
}

// handleEditConfig 返回 ONLYOFFICE 编辑器配置。
func (a *API) handleEditConfig(w http.ResponseWriter, r *http.Request) {
	c, _ := claimsFrom(r.Context())
	nodeID := r.PathValue("id")

	if a.Office == nil {
		writeErr(w, r, http.StatusNotImplemented, "EDITOR_UNAVAILABLE", "未配置在线编辑服务")
		return
	}

	n, err := a.Content.GetNode(r.Context(), c.TenantID, nodeID)
	if err != nil {
		writeErr(w, r, http.StatusNotFound, "NOT_FOUND", "对象不存在")
		return
	}
	if n.Kind != "file" {
		writeErr(w, r, http.StatusBadRequest, "INVALID_ARGUMENT", "目录不支持在线编辑")
		return
	}

	mode := "view"
	if r.URL.Query().Get("mode") == "edit" {
		mode = "edit"
	}
	// 编辑要 edit 位，只读查看要 preview 位：两种模式分别判定，不能共用
	need := authz.Preview
	if mode == "edit" {
		need = authz.Edit
	}
	d, err := a.check(r.Context(), c, n.SpaceID, nodeID, need)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "权限判定失败")
		return
	}
	if a.denyUnless(w, r, d) {
		return
	}

	ec, err := a.Office.BuildEditorConfig(nodeID, c.TenantID, c.Subject, c.Subject, n.Name, mode)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "生成编辑器配置失败")
		return
	}

	// 登记编辑会话：回退时据此拒绝，避免编辑者保存后把回退覆盖掉。
	// 登记失败不阻断编辑，但要留痕——否则回退会静默失去这层保护。
	if mode == "edit" {
		if terr := a.Content.TouchDocSession(r.Context(), c.TenantID, nodeID, c.Subject, c.Subject); terr != nil {
			_ = a.emit(r, c.TenantID, AuditEntry{
				ActorType: "system", Action: "doc_session.touch", ObjectID: nodeID,
				Result: "error", Detail: map[string]any{"reason": terr.Error()},
			})
		}
	}

	writeOK(w, r, map[string]any{
		"documentServerUrl": ec.DocumentServerURL,
		"config":            ec.Config,
		"mode":              mode,
	})
}

// handleDocSessionPing 续期当前用户对该文件的编辑会话。
//
// 前端在编辑页每 2 分钟调用一次。没有心跳时，会话会在 10 分钟后过期，
// 长文档编辑期间回退就可能被放行——这是心跳存在的唯一目的。
func (a *API) handleDocSessionPing(w http.ResponseWriter, r *http.Request) {
	c, _ := claimsFrom(r.Context())
	nodeID := r.PathValue("id")

	n, err := a.Content.GetNode(r.Context(), c.TenantID, nodeID)
	if err != nil {
		writeErr(w, r, http.StatusNotFound, "NOT_FOUND", "对象不存在")
		return
	}
	d, err := a.check(r.Context(), c, n.SpaceID, nodeID, authz.Edit)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "权限判定失败")
		return
	}
	if a.denyUnless(w, r, d) {
		return
	}

	if err := a.Content.TouchDocSession(r.Context(), c.TenantID, nodeID, c.Subject, c.Subject); err != nil {
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "编辑会话续期失败")
		return
	}
	writeOK(w, r, map[string]any{"nodeId": nodeID, "ttlSeconds": 600})
}

// handleDocSessionList 列出该文件当前的活跃编辑会话（版本面板用来提示"正在编辑"）。
func (a *API) handleDocSessionList(w http.ResponseWriter, r *http.Request) {
	c, _ := claimsFrom(r.Context())
	nodeID := r.PathValue("id")

	n, err := a.Content.GetNode(r.Context(), c.TenantID, nodeID)
	if err != nil {
		writeErr(w, r, http.StatusNotFound, "NOT_FOUND", "对象不存在")
		return
	}
	d, err := a.check(r.Context(), c, n.SpaceID, nodeID, authz.Display)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "权限判定失败")
		return
	}
	if a.denyUnless(w, r, d) {
		return
	}

	sessions, err := a.Content.ListDocSessions(r.Context(), c.TenantID, nodeID)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "读取编辑会话失败")
		return
	}
	items := make([]map[string]any, 0, len(sessions))
	for _, s := range sessions {
		items = append(items, map[string]any{
			"userId":     s.UserID,
			"startedAt":  s.StartedAt.UTC().Format(time.RFC3339),
			"lastSeenAt": s.LastSeenAt.UTC().Format(time.RFC3339),
		})
	}
	writeOK(w, r, map[string]any{"items": items, "count": len(items)})
}

// handleOfficeFile 把文件内容交给文档服务。无会话，靠签名 URL 校验。
func (a *API) handleOfficeFile(w http.ResponseWriter, r *http.Request) {
	if a.Office == nil {
		http.Error(w, "editor disabled", http.StatusNotFound)
		return
	}
	nodeID := r.PathValue("id")
	q := r.URL.Query()
	tenantID := q.Get("t")

	if !a.Office.VerifyFileURL(nodeID, tenantID, q.Get("e"), q.Get("s")) {
		// 不区分"签名错"与"过期"：对外只说不允许
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	rc, node, err := a.Content.OpenContent(r.Context(), tenantID, nodeID)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	defer func() { _ = rc.Close() }()

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.FormatInt(node.SizeBytes, 10))
	// 文档服务必须拿到最新内容，不能被任何中间层缓存
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = io.Copy(w, rc)
}

// 回调体上限：正常只有几 KB，给 1MB 已经很宽松
const maxCallbackBody = 1 << 20

// handleOfficeCallback 处理文档服务回调，保存编辑结果。
func (a *API) handleOfficeCallback(w http.ResponseWriter, r *http.Request) {
	if a.Office == nil {
		http.Error(w, "editor disabled", http.StatusNotFound)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, maxCallbackBody+1))
	if err != nil || len(body) > maxCallbackBody {
		http.Error(w, "body too large", http.StatusRequestEntityTooLarge)
		return
	}

	// token 可能在 Authorization 头（官方推荐）或 body 里
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if token == "" {
		token = jsonField(body, "token")
	}

	cb, err := a.Office.ParseCallback(token, body)
	if err != nil {
		// 六步校验失败一律拒绝，且不透露具体哪一步失败
		_ = a.emit(r, "", AuditEntry{
			ActorType: "system", Action: "office.callback", Result: "denied",
			Detail: map[string]any{"reason": err.Error()},
		})
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	// 租户由节点反查得到，而不是信任回调里的任何自述字段
	tenantID, terr := a.Content.ResolveNodeTenant(r.Context(), cb.NodeID)
	if terr != nil {
		writeJSON(w, r, http.StatusOK, map[string]any{"error": 1})
		return
	}

	// 只需处理"要保存"的状态；其余状态（编辑中/无人编辑）直接应答成功
	if !cb.NeedsSave() || cb.URL == "" {
		writeJSON(w, r, http.StatusOK, map[string]any{"error": 0})
		return
	}

	// 能走到保存，说明刚才确实有人在编辑：续期会话。
	// 否则"打开编辑 → 编辑超过 10 分钟 → 保存"之后，会话早已过期，回退会被放行。
	sessionKey := cb.UserID
	if sessionKey == "" {
		sessionKey = "anonymous"
	}
	if terr := a.Content.TouchDocSession(r.Context(), tenantID, cb.NodeID, sessionKey, cb.UserID); terr != nil {
		_ = a.emit(r, tenantID, AuditEntry{
			ActorType: "system", Action: "doc_session.touch", ObjectID: cb.NodeID,
			Result: "error", Detail: map[string]any{"reason": terr.Error()},
		})
	}

	data, err := a.Office.FetchDocument(r.Context(), cb.URL)
	if err != nil {
		_ = a.emit(r, tenantID, AuditEntry{
			ActorID: cb.UserID, Action: "office.save", ObjectID: cb.NodeID, Result: "denied",
			Detail: map[string]any{"reason": err.Error()},
		})
		// 返回错误码让文档服务保留缓存并重试，避免用户编辑内容丢失
		writeJSON(w, r, http.StatusOK, map[string]any{"error": 1})
		return
	}

	// 必须用 bytes.NewReader：string(data) 会为最大 512MB 的文档再复制一份，
	// 峰值内存翻倍，容器很容易被一次大文档编辑 OOM 掉。
	versionID, size, err := a.Content.AppendVersion(r.Context(), tenantID, cb.NodeID,
		cb.UserID, bytes.NewReader(data), 512<<20)
	if err != nil {
		if errors.Is(err, content.ErrNotFound) {
			writeJSON(w, r, http.StatusOK, map[string]any{"error": 1})
			return
		}
		writeJSON(w, r, http.StatusOK, map[string]any{"error": 1})
		return
	}

	if err := a.emit(r, tenantID, AuditEntry{
		ActorID: cb.UserID, ActorType: "user", Action: "office.save",
		ObjectID: cb.NodeID, Result: "ok",
		Detail: map[string]any{"versionId": versionID, "size": size, "status": cb.Status},
	}); err != nil {
		// 审计写不进时不回滚已保存的内容，但要让文档服务知道"这次没成功"，
		// 它会重试——重复保存产生多版本比丢内容好。
		writeJSON(w, r, http.StatusOK, map[string]any{"error": 1})
		return
	}

	// 编辑后必须让预览缓存失效，否则用户切回预览看到的还是旧的 PDF
	if a.Preview != nil {
		if n, gerr := a.Content.GetNode(r.Context(), tenantID, cb.NodeID); gerr == nil {
			a.Preview.InvalidateVersion(
				fmt.Sprintf("%s:%d:%d", n.ID, n.SizeBytes, n.UpdatedAt.UnixNano()))
		}
	}

	// 每次在线保存都会追加版本，按租户保留数量清理一次。
	// 必须在响应前做：文档服务收到 error:0 后会认为本次保存彻底完成，
	// 之后再清理虽然也不影响正确性，但会拖到下一次保存才生效。
	a.pruneVersions(r.Context(), tenantID, cb.NodeID)

	writeJSON(w, r, http.StatusOK, map[string]any{"error": 0})
}

// jsonField 从 JSON 对象里取一个字符串字段（避免为此再解一遍结构体）。
func jsonField(body []byte, key string) string {
	var m map[string]any
	if err := json.Unmarshal(body, &m); err != nil {
		return ""
	}
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}
