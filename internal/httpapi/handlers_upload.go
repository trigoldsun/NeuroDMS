package httpapi

// 分片上传（AC-78 / AC-67 秒传）。
//
// 两条纪律：
//   1. complete 必须幂等——网络重试、双击、客户端超时重发都会重复调用，
//      没有"已完成"状态就只能靠唯一约束撞运气，结果是重复产生版本；
//   2. 秒传只能由服务端核对内容哈希，客户端声明的 size/sha256 只用于"找候选"。

import (
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

func (a *API) handleCreateUpload(w http.ResponseWriter, r *http.Request) {
	c, _ := claimsFrom(r.Context())
	var req struct {
		SpaceID   string `json:"spaceId"`
		ParentID  string `json:"parentId"`
		Name      string `json:"name"`
		SizeBytes int64  `json:"sizeBytes"`
		SHA256    string `json:"sha256"`
		PartSize  int64  `json:"partSize"`
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
