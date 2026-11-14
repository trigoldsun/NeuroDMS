package httpapi

// 分片上传（AC-78 / AC-67 秒传）。
//
// 两条纪律：
//   1. complete 必须幂等——网络重试、双击、客户端超时重发都会重复调用，
//      没有"已完成"状态就只能靠唯一约束撞运气，结果是重复产生版本；
//   2. 秒传只能由服务端核对内容哈希，客户端声明的 size/sha256 只用于"找候选"。

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"docvault/internal/authz"
	"docvault/internal/content"
	"docvault/internal/tenant"
)

func (a *API) registerUpload(mux *http.ServeMux) {
	mux.HandleFunc("POST /v1/uploads", a.requireAuth(a.handleCreateUpload))
	// 整目录上传前的批量预检：一次把"哪些文件会被拒、为什么"说清楚
	mux.HandleFunc("POST /v1/uploads/preflight", a.requireAuth(a.handleUploadPreflight))
	// 查询会话：刷新页面后恢复续传要读"已收到哪些分片"。
	// 只返回本人会话——会话里有目标目录与文件名，跨用户可见等于泄露目录结构。
	mux.HandleFunc("GET /v1/uploads/{id}", a.requireAuth(a.handleGetUpload))
	mux.HandleFunc("PUT /v1/uploads/{id}/parts/{no}", a.requireAuth(a.handlePutPart))
	mux.HandleFunc("POST /v1/uploads/{id}/complete", a.requireAuth(a.handleCompleteUpload))
	mux.HandleFunc("DELETE /v1/uploads/{id}", a.requireAuth(a.handleAbortUpload))
}

// defaultPartSize 与前端 CHUNK 保持一致；客户端可传，但只在**新建**会话时生效。
// 1MB 的理由见前端 api.ts：片内进度不可信，颗粒度完全由分片大小决定。
const defaultPartSize = 1 << 20

// applyUploadDeadline 按租户策略放宽本次请求的读取截止时间。
//
// http.Server.ReadTimeout 是连接级的全局值，无法表达"这个租户上行慢，多给点时间"。
// Go 1.20 起可以用 ResponseController 为单个请求改截止时间，必须在**读取 body 之前**调用。
//
// 读不到策略时保持服务端默认（不报错）：这是"尽量给宽限"的优化，
// 不是安全边界——真正常驻的防线是 body 上限与租户配额。
func (a *API) applyUploadDeadline(w http.ResponseWriter, r *http.Request, tenantID string) {
	secs := tenant.DefaultUploadTimeoutSeconds
	if pol, err := a.tenantPolicy(r.Context(), tenantID); err == nil && pol.UploadTimeoutSeconds > 0 {
		secs = pol.UploadTimeoutSeconds
	}
	rc := http.NewResponseController(w)
	_ = rc.SetReadDeadline(time.Now().Add(time.Duration(secs) * time.Second))
}

// rejectByExtWhitelist 按租户白名单拦下不接受的扩展名。
//
// 这是**入口约束**：让"我们只收 office 和 pdf"这类要求在上传第一个字节前就生效。
// 危险扩展名与可执行魔数是另一套（安全），两者互不替代。
func (a *API) rejectByExtWhitelist(w http.ResponseWriter, r *http.Request, tenantID, filename string) bool {
	pol, err := a.tenantPolicy(r.Context(), tenantID)
	if err != nil {
		// 读不到策略时放行：白名单是体验约束，不是安全边界，
		// 让它因为一次数据库抖动阻断所有上传是更大的问题。
		return false
	}
	if pol.AllowsExt(filename) {
		return false
	}
	writeErr(w, r, http.StatusUnsupportedMediaType, "EXT_NOT_ALLOWED",
		"该文件类型不在本组织允许的范围内："+extOfHint(filename))
	return true
}

func extOfHint(name string) string {
	if e := strings.ToLower(extOf(name)); e != "" {
		return e
	}
	return "无扩展名"
}

// folderUploadEnabled 判断本租户此刻能不能用"整目录上传"。
//
// 两把锁，缺一不可：
//  1. 档位必须含该能力（基础版没有）——它是批量写入口，不是协议能力；
//  2. 租户管理员必须在系统设置里显式打开（默认关）。
//
// 读不到配置一律返回 false（fail-closed）。这里与"扩展名白名单读不到就放行"
// 的取舍不同：白名单是体验约束，而批量上传会一次创建大量目录与文件，
// 把配额、预览转码队列、审计量同时打满——宁可拒，也不能在数据库抖动时放开。
func (a *API) folderUploadEnabled(ctx context.Context, tenantID string) bool {
	st, err := a.editionState(ctx, tenantID)
	if err != nil || !st.Spec.FolderUpload {
		return false
	}
	pol, err := a.tenantPolicy(ctx, tenantID)
	if err != nil {
		return false
	}
	return pol.FolderUpload
}

// preflightItem 是一个待检文件。
type preflightItem struct {
	Name string `json:"name"`
	Size int64  `json:"size"`
	// Path 是相对路径（如 "项目A/设计/图.png"）。服务端只把它原样带回：
	// 目录结构由客户端解释，服务端不该猜路径分隔符的含义。
	Path string `json:"path"`
}

// maxPreflightEntries 是单次预检的文件数上限。
//
// 5000 的理由：一个真实项目目录很少超过这个量级；再大时应当分批预检，
// 否则一次请求就要把整棵树的文件名送到服务端，请求体与内存都不受控。
const maxPreflightEntries = 5000

// handleUploadPreflight 批量预检：整目录上传前，先回答"哪些会被拒、为什么"。
//
// 为什么不在前端按 allowedExts 自己判：
// 这里有三套规则（租户扩展名白名单、双扩展名/危险扩展、单文件大小），
// 前端复制一份就必然有一天与后端不一致——用户看到"通过"，传到一半才被拒，
// 比一开始就说清楚更糟。而且目录里往往几百个文件，逐个试错的代价太高。
func (a *API) handleUploadPreflight(w http.ResponseWriter, r *http.Request) {
	c, _ := claimsFrom(r.Context())
	var req struct {
		SpaceID  string          `json:"spaceId"`
		ParentID string          `json:"parentId"`
		Files    []preflightItem `json:"files"`
	}
	if !decode(w, r, &req) {
		return
	}
	if req.SpaceID == "" {
		writeErr(w, r, http.StatusBadRequest, "INVALID_ARGUMENT", "spaceId 必填")
		return
	}
	if len(req.Files) == 0 {
		writeErr(w, r, http.StatusBadRequest, "INVALID_ARGUMENT", "没有待检查的文件")
		return
	}
	if len(req.Files) > maxPreflightEntries {
		writeErr(w, r, http.StatusBadRequest, "TOO_MANY_FILES",
			"一次最多检查 "+strconv.Itoa(maxPreflightEntries)+" 个文件，请分多次上传")
		return
	}
	if !a.folderUploadEnabled(r.Context(), c.TenantID) {
		writeErr(w, r, http.StatusForbidden, "FEATURE_NOT_ENABLED",
			"当前未启用文件夹上传，请在「系统设置」中开启（需专业版及以上）")
		return
	}

	// 至少要能在目标目录里创建：只看单文件权限不够，
	// 否则会出现"预检全通过、上传全 403"。目录级判定包括对祖先的遍历权限。
	target := req.ParentID
	if target == "" {
		target = req.SpaceID
	}
	d, err := a.check(r.Context(), c, req.SpaceID, target, authz.Create)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "权限判定失败")
		return
	}
	if a.denyUnless(w, r, d) {
		return
	}

	st, err := a.editionState(r.Context(), c.TenantID)
	if err != nil {
		writeErr(w, r, http.StatusServiceUnavailable, "ENTITLEMENT_UNAVAILABLE",
			"无法读取租户档位，请稍后重试")
		return
	}
	pol, _ := a.tenantPolicy(r.Context(), c.TenantID)
	// 与单文件上传同一个上限：档位值与租户值取较小者
	limitMB := st.EffectiveMaxUploadMB(pol.MaxUploadMB)
	limitBytes := int64(limitMB) << 20

	type rejected struct {
		Index  int    `json:"index"`
		Path   string `json:"path"`
		Name   string `json:"name"`
		Code   string `json:"code"`   // ext | dangerous | size | name
		Reason string `json:"reason"` // 面向用户的一句话
	}
	unsupported := make([]rejected, 0, 8)
	for i, f := range req.Files {
		path := f.Path
		if path == "" {
			path = f.Name
		}
		switch {
		case strings.TrimSpace(f.Name) == "":
			unsupported = append(unsupported, rejected{Index: i, Path: path, Name: f.Name,
				Code: "name", Reason: "文件名为空"})
		case guardUploadName(f.Name) != nil:
			// 双扩展名里夹危险类型：shell.php.jpg 这类，某些错误配置会按第一段执行
			unsupported = append(unsupported, rejected{Index: i, Path: path, Name: f.Name,
				Code: "dangerous", Reason: "文件名包含不允许的扩展名组合"})
		case !pol.AllowsExt(f.Name):
			unsupported = append(unsupported, rejected{Index: i, Path: path, Name: f.Name,
				Code: "ext", Reason: "类型不在本组织允许的范围内（" + extOfHint(f.Name) + "）"})
		case f.Size < 0 || (limitBytes > 0 && f.Size > limitBytes):
			unsupported = append(unsupported, rejected{Index: i, Path: path, Name: f.Name,
				Code: "size", Reason: "超过单文件上限 " + strconv.Itoa(limitMB) + " MB"})
		}
	}

	writeOK(w, r, map[string]any{
		"total":       len(req.Files),
		"allowed":     len(req.Files) - len(unsupported),
		"unsupported": unsupported,
		"limits": map[string]any{
			"maxUploadMB": limitMB,
			// null 表示不限制；空数组会被前端误解为"一个都不许传"
			"allowedExts": pol.AllowedExts,
		},
	})
}

func (a *API) handleCreateUpload(w http.ResponseWriter, r *http.Request) {
	c, _ := claimsFrom(r.Context())
	var req struct {
		SpaceID   string `json:"spaceId"`
		ParentID  string `json:"parentId"`
		Name      string `json:"name"`
		SizeBytes int64  `json:"sizeBytes"`
		SHA256    string `json:"sha256"`
		PartSize  int64  `json:"partSize"`
		// FolderUpload 表示这次上传属于"整目录上传"批次。
		//
		// 单独打标记而不是"只看目录深度"：文件本身与普通上传完全一样，
		// 服务端无法从请求形状区分。打标记是为了让**关掉功能的租户**
		// 即使用脚本直接调接口也传不了整目录——功能开关在写入口生效，
		// 而不只是把界面按钮藏起来。
		FolderUpload bool `json:"folderUpload"`
	}
	if !decode(w, r, &req) {
		return
	}
	if req.SpaceID == "" || req.Name == "" {
		writeErr(w, r, http.StatusBadRequest, "INVALID_ARGUMENT", "spaceId 与 name 必填")
		return
	}
	if req.SizeBytes < 0 || req.SizeBytes > maxUploadBytes {
		writeErr(w, r, http.StatusBadRequest, "INVALID_ARGUMENT", "sizeBytes 非法")
		return
	}
	if req.PartSize == 0 {
		req.PartSize = defaultPartSize
	}
	// 分片一开始就校验扩展名：此时还没传任何字节，拒绝的代价最小
	if a.rejectByExtWhitelist(w, r, c.TenantID, req.Name) {
		return
	}
	if req.FolderUpload && !a.folderUploadEnabled(r.Context(), c.TenantID) {
		writeErr(w, r, http.StatusForbidden, "FEATURE_NOT_ENABLED",
			"当前未启用文件夹上传，请在「系统设置」中开启（需专业版及以上）")
		return
	}

	target := req.ParentID
	if target == "" {
		target = req.SpaceID
	}
	d, err := a.check(r.Context(), c, req.SpaceID, target, authz.Create)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "权限判定失败")
		return
	}
	if a.denyUnless(w, r, d) {
		return
	}

	sess, deduped, err := a.Content.CreateSession(r.Context(), c.TenantID, req.SpaceID,
		req.ParentID, req.Name, c.Subject, req.SizeBytes, req.SHA256, req.PartSize)
	if err != nil {
		if errors.Is(err, content.ErrBadInput) {
			writeErr(w, r, http.StatusBadRequest, "INVALID_ARGUMENT", "参数不合法（名称、哈希或分片大小）")
			return
		}
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "创建上传会话失败")
		return
	}

	_ = a.emit(r, c.TenantID, AuditEntry{
		ActorID: c.Subject, Action: "upload.session.create", ObjectID: sess.ID, Result: "ok",
		Detail: map[string]any{"name": req.Name, "size": req.SizeBytes,
			"deduped": deduped, "resumed": sess.Resumed, "receivedParts": len(sess.Parts)},
	})

	if deduped {
		writeOK(w, r, map[string]any{
			"deduped": true, "nodeId": sess.NodeID, "versionId": sess.VersionID,
			"status": "completed",
		})
		return
	}
	writeOK(w, r, map[string]any{
		"uploadId": sess.ID, "deduped": false, "status": "open",
		"declaredSize": sess.DeclaredSize,
		// partSize 以**会话**为准：客户端换了分片大小，续传仍要按旧边界补缺口，
		// 否则拼出来的内容是错位的，且只在 complete 校验哈希时才暴露。
		"partSize":      sess.PartSize,
		"receivedParts": partsOrEmpty(sess.Parts),
		"resumed":       sess.Resumed,
	})
}

// partsOrEmpty 让"没有已收分片"序列化成 []，而不是 null。
// 空的语义是"一个都没收到"，null 会被读成"字段不存在"，前端与外部调用方
// 都要多写一个分支——这类小分歧最后总会变成某个客户端的空指针。
func partsOrEmpty(p []int) []int {
	if p == nil {
		return []int{}
	}
	return p
}

func (a *API) handleGetUpload(w http.ResponseWriter, r *http.Request) {
	c, _ := claimsFrom(r.Context())
	sess, err := a.Content.GetSession(r.Context(), c.TenantID, r.PathValue("id"), c.Subject)
	if err != nil {
		if errors.Is(err, content.ErrSessionNotFound) {
			writeErr(w, r, http.StatusNotFound, "NOT_FOUND", "上传会话不存在")
			return
		}
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "读取上传会话失败")
		return
	}
	writeOK(w, r, map[string]any{
		"uploadId":      sess.ID,
		"name":          sess.Name,
		"declaredSize":  sess.DeclaredSize,
		"receivedBytes": sess.ReceivedBytes,
		"status":        sess.Status,
		"partSize":      sess.PartSize,
		"receivedParts": partsOrEmpty(sess.Parts),
	})
}

func (a *API) handlePutPart(w http.ResponseWriter, r *http.Request) {
	c, _ := claimsFrom(r.Context())
	// 分片上传走同一个租户超时：慢速上行下 1MB 也要几十秒
	a.applyUploadDeadline(w, r, c.TenantID)
	sessionID := r.PathValue("id")
	partNo, err := strconv.Atoi(r.PathValue("no"))
	if err != nil || partNo < 1 {
		writeErr(w, r, http.StatusBadRequest, "INVALID_ARGUMENT", "分片序号必须是正整数")
		return
	}

	n, err := a.Content.PutPart(r.Context(), c.TenantID, sessionID, c.Subject, partNo,
		http.MaxBytesReader(w, r.Body, maxUploadBytes), maxUploadBytes)
	if err != nil {
		switch {
		case errors.Is(err, content.ErrSessionNotFound):
			writeErr(w, r, http.StatusNotFound, "NOT_FOUND", "上传会话不存在")
		case errors.Is(err, content.ErrSessionDone):
			writeErr(w, r, http.StatusConflict, "SESSION_CLOSED", "上传会话已结束")
		case errors.Is(err, content.ErrBadInput):
			// 分片号超出声明片数：继续写下去只会在磁盘上留一份永远不会被合并的垃圾
			writeErr(w, r, http.StatusBadRequest, "INVALID_ARGUMENT", "分片序号超出该文件的片数")
		case errors.Is(err, content.ErrTooLarge):
			writeErr(w, r, http.StatusRequestEntityTooLarge, "TOO_LARGE", "分片超过上限")
		default:
			writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "保存分片失败")
		}
		return
	}
	writeOK(w, r, map[string]any{"partNo": partNo, "sizeBytes": n})
}

func (a *API) handleCompleteUpload(w http.ResponseWriter, r *http.Request) {
	c, _ := claimsFrom(r.Context())
	sessionID := r.PathValue("id")

	sess, err := a.Content.CompleteSession(r.Context(), c.TenantID, sessionID, c.Subject)
	if err != nil {
		switch {
		case errors.Is(err, content.ErrSessionNotFound):
			writeErr(w, r, http.StatusNotFound, "NOT_FOUND", "上传会话不存在")
		case errors.Is(err, content.ErrSessionDone):
			writeErr(w, r, http.StatusConflict, "SESSION_CLOSED", "上传会话已结束")
		case errors.Is(err, content.ErrPartsIncomplete):
			writeErr(w, r, http.StatusBadRequest, "PARTS_INCOMPLETE", "分片不完整")
		case errors.Is(err, content.ErrSizeMismatch):
			// AC-67：声明大小与实际不符必须拒绝，绝不能"按实际大小静默接受"
			writeErr(w, r, http.StatusBadRequest, "SIZE_MISMATCH", err.Error())
		case errors.Is(err, content.ErrHashMismatch):
			writeErr(w, r, http.StatusBadRequest, "HASH_MISMATCH", "内容哈希与声明不一致")
		default:
			writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "完成上传失败")
		}
		return
	}

	_ = a.emit(r, c.TenantID, AuditEntry{
		ActorID: c.Subject, Action: "upload.session.complete", ObjectID: sess.NodeID, Result: "ok",
		Detail: map[string]any{"sessionId": sessionID, "name": sess.Name, "size": sess.DeclaredSize},
	})
	writeOK(w, r, map[string]any{
		"nodeId": sess.NodeID, "versionId": sess.VersionID, "status": "completed",
		"sizeBytes": sess.DeclaredSize,
	})
}

func (a *API) handleAbortUpload(w http.ResponseWriter, r *http.Request) {
	c, _ := claimsFrom(r.Context())
	sessionID := r.PathValue("id")

	if err := a.Content.AbortSession(r.Context(), c.TenantID, sessionID, c.Subject); err != nil {
		if errors.Is(err, content.ErrSessionNotFound) {
			writeErr(w, r, http.StatusNotFound, "NOT_FOUND", "上传会话不存在")
			return
		}
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "中止上传失败")
		return
	}
	_ = a.emit(r, c.TenantID, AuditEntry{
		ActorID: c.Subject, Action: "upload.session.abort", ObjectID: sessionID, Result: "ok",
	})
	writeOK(w, r, map[string]any{"aborted": true})
}
