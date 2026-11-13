package httpapi

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"docvault/internal/ace"
	"docvault/internal/auth"
	"docvault/internal/authz"
	"docvault/internal/classification"
	"docvault/internal/content"
	"docvault/internal/db"
	"docvault/internal/scan"

	"github.com/jackc/pgx/v5"
)

// registerContent 注册内容相关路由。
func (a *API) registerContent(mux *http.ServeMux) {
	mux.HandleFunc("POST /v1/spaces", a.requireAuth(a.handleCreateSpace))
	mux.HandleFunc("POST /v1/spaces/{spaceId}/folders", a.requireAuth(a.handleCreateFolder))
	mux.HandleFunc("POST /v1/spaces/{spaceId}/files", a.requireAuth(a.handleUpload))
	mux.HandleFunc("GET /v1/spaces/{spaceId}/nodes", a.requireAuth(a.handleList))
	mux.HandleFunc("GET /v1/nodes/{id}", a.requireAuth(a.handleNodeMeta))
	// 面包屑反查：页面地址里只有 folderId，刷新时要靠它还原"我在哪一层"
	mux.HandleFunc("GET /v1/nodes/{id}/path", a.requireAuth(a.handleNodePath))
	mux.HandleFunc("PATCH /v1/nodes/{id}", a.requireAuth(a.handleRename))
	mux.HandleFunc("DELETE /v1/nodes/{id}", a.requireAuth(a.handleDelete))
	mux.HandleFunc("POST /v1/nodes/{id}/move", a.requireAuth(a.handleMove))
	mux.HandleFunc("GET /v1/nodes/{id}/content", a.requireAuth(a.handleDownload))
}

// decision 是授权结果，附带原因便于排障与审计。
// 同时带回被判定的对象与动作：拒绝响应要据此区分 403 与 404。
type decision struct {
	allowed bool
	reason  string
	spaceID string
	nodeID  string
	act     authz.Bit
}

// check 对某对象执行一次权限判定。
//
// 判定在租户事务内完成：主体快照（部门祖先/角色/组）与 ACE 一起读，
// 避免"读到一半权限被改"造成的不一致。
func (a *API) check(ctx context.Context, c auth.Claims, spaceID, nodeID string, act authz.Bit) (decision, error) {
	var out decision
	err := db.WithTenant(ctx, a.Pool, c.TenantID, func(tx pgx.Tx) error {
		sub, err := ace.LoadSubject(ctx, tx, c.TenantID, c.Subject)
		if err != nil {
			return err
		}
		// 令牌里的 epoch 必须与库中一致，否则说明会话已被吊销
		sub.Epoch = sub.TokenEpoch
		sub.TokenEpoch = c.Epoch
		if sub.Epoch != c.Epoch {
			out = decision{allowed: false, reason: "SESSION_STALE", spaceID: spaceID, nodeID: nodeID, act: act}
			return nil
		}

		aces, err := ace.LoadForNode(ctx, tx, spaceID, nodeID)
		if err != nil {
			return err
		}

		// 对象密级必须真正进入判定。
		//
		// 这段曾经缺失：authz 里的密级门（sub.Class < obj.Class → 拒绝）一直在，
		// 但 Object.Class 从没被赋值，等价于"所有对象都是 0 级"。
		// 引擎测试全绿、线上密级完全不生效——这是最典型的"假功能"。
		// 现在把对象密级与标签策略下限一起算出来传进去（标签只收紧）。
		objClass, err := classification.EffectiveClass(ctx, tx, c.TenantID, nodeID, spaceID)
		if err != nil {
			return err
		}

		d, err := authz.Authorize(ctx, &ace.Source{Aces: aces}, sub,
			authz.Object{ID: nodeID, TenantID: c.TenantID, Class: objClass}, act, time.Now())
		if err != nil {
			// 判定过程出错一律判拒（fail-closed）
			out = decision{allowed: false, reason: "AUTHZ_ERROR", spaceID: spaceID, nodeID: nodeID, act: act}
			return nil
		}
		out = decision{allowed: d.Allowed, reason: d.Reason, spaceID: spaceID, nodeID: nodeID, act: act}
		return nil
	})
	return out, err
}

// denyUnless 在拒绝时决定返回 403 还是 404。
//
// 区分依据是"这个人还能不能看见这个对象"：
//   - 能看见（有 display）但缺更高权限 → 403。用户明明在列表里看到它，
//     再回 404 只会被当成 bug，也会掩盖真实的权限配置问题。
//   - 完全看不见 → 404，避免通过状态码枚举对象是否存在。
//
// 代价是拒绝路径多一次判定（仅拒绝时发生，且是纯计算），换来的是
// 错误语义与 AC-16/17/18/19（403）和 AC-25（404）同时自洽。
func (a *API) denyUnless(w http.ResponseWriter, r *http.Request, d decision) bool {
	if d.allowed {
		return false
	}

	visible := false
	if d.nodeID != "" && d.act != authz.Display {
		if c, ok := claimsFrom(r.Context()); ok {
			if dd, err := a.check(r.Context(), c, d.spaceID, d.nodeID, authz.Display); err == nil {
				visible = dd.allowed
			}
		}
	}

	a.emitQuiet(r, "authz.denied", d.reason)
	if visible {
		writeErr(w, r, http.StatusForbidden, "FORBIDDEN", "权限不足")
		return true
	}
	writeErr(w, r, http.StatusNotFound, "NOT_FOUND", "对象不存在或无权访问")
	return true
}

// emitQuiet 记录授权失败（失败不影响响应，因为此时本身就是拒绝）。
func (a *API) emitQuiet(r *http.Request, action, reason string) {
	c, ok := claimsFrom(r.Context())
	if !ok {
		return
	}
	_ = a.emit(r, c.TenantID, AuditEntry{
		ActorID: c.Subject, Action: action, Result: "denied",
		Detail: map[string]any{"reason": reason},
	})
}

func (a *API) handleCreateSpace(w http.ResponseWriter, r *http.Request) {
	c, _ := claimsFrom(r.Context())
	var req struct {
		Kind string `json:"kind"`
		Name string `json:"name"`
	}
	if !decode(w, r, &req) {
		return
	}
	id, err := a.Content.CreateSpace(r.Context(), c.TenantID, c.Subject, req.Kind, req.Name)
	if err != nil {
		if errors.Is(err, content.ErrBadInput) {
			writeErr(w, r, http.StatusBadRequest, "INVALID_ARGUMENT", "空间类型或名称不合法")
			return
		}
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "创建空间失败")
		return
	}
	if err := a.emit(r, c.TenantID, AuditEntry{
		ActorID: c.Subject, Action: "space.create", ObjectID: id, Result: "ok",
		Detail: map[string]any{"kind": req.Kind, "name": req.Name},
	}); err != nil {
		writeErr(w, r, http.StatusInternalServerError, "AUDIT_FAILED", "审计写入失败，操作已拒绝")
		return
	}
	writeOK(w, r, map[string]any{"spaceId": id})
}

func (a *API) handleCreateFolder(w http.ResponseWriter, r *http.Request) {
	c, _ := claimsFrom(r.Context())
	spaceID := r.PathValue("spaceId")
	var req struct {
		ParentID string `json:"parentId"`
		Name     string `json:"name"`
	}
	if !decode(w, r, &req) {
		return
	}

	// 在父目录（或空间根）上需要 create 权限
	target := req.ParentID
	if target == "" {
		target = spaceID
	}
	d, err := a.check(r.Context(), c, spaceID, target, authz.Create)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "权限判定失败")
		return
	}
	if a.denyUnless(w, r, d) {
		return
	}

	id, err := a.Content.CreateFolder(r.Context(), c.TenantID, spaceID, req.ParentID, c.Subject, req.Name)
	if err != nil {
		switch {
		case errors.Is(err, content.ErrBadInput):
			writeErr(w, r, http.StatusBadRequest, "INVALID_ARGUMENT", "名称不合法")
		case errors.Is(err, content.ErrNameTaken):
			writeErr(w, r, http.StatusConflict, "ALREADY_EXISTS", "同目录下已存在同名文件夹")
		case errors.Is(err, content.ErrNotFound):
			writeErr(w, r, http.StatusNotFound, "NOT_FOUND", "父目录不存在")
		default:
			writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "创建失败")
		}
		return
	}
	_ = a.emit(r, c.TenantID, AuditEntry{
		ActorID: c.Subject, Action: "folder.create", ObjectID: id, Result: "ok",
		Detail: map[string]any{"name": req.Name, "spaceId": spaceID},
	})
	writeOK(w, r, map[string]any{"folderId": id})
}

// maxUploadBytes 是单文件上限。用变量而非常量：测试需要把它调小来验证 413，
// 常量会让"超限不产生半个 blob"这条断言无法在测试里成立。
var maxUploadBytes int64 = 10 << 30 // 10GB，后续由设置表覆盖

// maxScanBytes 是需要扫描/净化的文件的内存上限。
// 超过就明确拒绝（TOO_LARGE_TO_SCAN），而不是"太大跳过扫描"。
const maxScanBytes int64 = 64 << 20

func (a *API) handleUpload(w http.ResponseWriter, r *http.Request) {
	c, _ := claimsFrom(r.Context())
	spaceID := r.PathValue("spaceId")

	// 按租户策略放宽读取截止时间，必须在读 body 之前设置
	a.applyUploadDeadline(w, r, c.TenantID)

	if err := r.ParseMultipartForm(32 << 20); err != nil {
		// 两种失败必须分开报，否则排查方向会被完全带偏：
		//   · 中断/超时：请求体没读完（慢速上行、切网、代理断开）——不是格式问题；
		//   · 其余：确实不是 multipart。
		// 之前一律报"请使用 multipart/form-data"，用户拿这条提示去查编码，永远查不到原因。
		if uploadInterrupted(err) {
			writeErr(w, r, http.StatusRequestTimeout, "UPLOAD_INTERRUPTED",
				"上传中断或网络过慢，请重试；大于 8MB 的文件会从断点继续")
			return
		}
		writeErr(w, r, http.StatusBadRequest, "INVALID_ARGUMENT", "上传数据不完整或不是 multipart/form-data")
		return
	}
	file, hdr, err := r.FormFile("file")
	if err != nil {
		writeErr(w, r, http.StatusBadRequest, "INVALID_ARGUMENT", "缺少 file 字段")
		return
	}
	defer func() { _ = file.Close() }()

	parentID := r.FormValue("parentId")
	target := parentID
	if target == "" {
		target = spaceID
	}
	d, err := a.check(r.Context(), c, spaceID, target, authz.Create)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "权限判定失败")
		return
	}
	if a.denyUnless(w, r, d) {
		return
	}

	// 浏览器给的空/octet-stream 一律按扩展名补全。
	// iPhone 拍的 HEIC、Windows 资源管理器拖的 docx 经常不带有效 Content-Type，
	// mime 留空会让下游（预览分流、图标、转换器选择）全部走错分支。
	mime := strings.TrimSpace(hdr.Header.Get("Content-Type"))
	if mime == "" || mime == "application/octet-stream" {
		if guess := mimeByExt(hdr.Filename); guess != "" {
			mime = guess
		}
	}

	// 上传即定密（AC-41）：密级不得高于上传者自身密级。
	//
	// 必须在写盘之前判：一旦内容落进 blob，"先上传成功、再发现越权"就只能靠删除补救，
	// 而删除是软删，blob 仍在。这里的顺序是刻意的。
	uploadClass := 0
	actorClass := 0
	// 档位能力先判：这是"产品有没有这个功能"，比"个人密级够不够"更靠前。
	// 顺序反了的话，客户会先去找管理员提升密级，办完才发现档位根本不支持。
	ed, eerr := a.editionState(r.Context(), c.TenantID)
	if eerr != nil {
		writeErr(w, r, http.StatusServiceUnavailable, "ENTITLEMENT_UNAVAILABLE",
			"无法读取租户档位，请稍后重试")
		return
	}
	if v := strings.TrimSpace(r.FormValue("classification")); v != "" {
		n, perr := strconv.Atoi(v)
		if perr != nil || n < 0 || n > classification.MaxLevel {
			writeErr(w, r, http.StatusBadRequest, "INVALID_ARGUMENT", "密级必须在 0..6 之间")
			return
		}
		if !ed.CanWriteClass(n) {
			_ = a.emit(r, c.TenantID, AuditEntry{
				ActorID: c.Subject, Action: "node.upload", ObjectID: spaceID, Result: "denied",
				Detail: map[string]any{"reason": "edition_classification", "requested": n,
					"edition": string(ed.Edition), "name": hdr.Filename},
			})
			writeErr(w, r, http.StatusForbidden, "FEATURE_NOT_ENABLED",
				"当前档位（"+ed.Spec.Name+"）不支持该密级")
			return
		}
		if err := db.WithTenant(r.Context(), a.Pool, c.TenantID, func(tx pgx.Tx) error {
			return tx.QueryRow(r.Context(),
				`SELECT classification FROM app_user WHERE id = $1`, c.Subject).Scan(&actorClass)
		}); err != nil {
			writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "读取用户密级失败")
			return
		}
		if n > actorClass {
			_ = a.emit(r, c.TenantID, AuditEntry{
				ActorID: c.Subject, Action: "node.upload", ObjectID: spaceID, Result: "denied",
				Detail: map[string]any{"reason": "classification_above_self",
					"requested": n, "actorClass": actorClass, "name": hdr.Filename},
			})
			writeErr(w, r, http.StatusForbidden, "ABOVE_SELF", "不能以上传方式设置高于自身密级的密级")
			return
		}
		uploadClass = n
	}

	// 租户级上传上限（策略）与存储配额。
	//
	// 都放在写盘之前：传完才发现超限，用户白等了十几分钟，且 blob 已经落盘。
	// 存储配额的最终一致性由数据库触发器保证（并发下也不会超），
	// 这里的作用是"给出可读的原因"，而不是"唯一的防线"。
	//
	// 实际上限取"档位上限"与"租户策略"的较小值：客户只能把上限调小，
	// 不能靠改策略突破档位，否则改一个配置就等于升级。
	policyMB := 0
	if pol, perr := a.tenantPolicy(r.Context(), c.TenantID); perr == nil {
		policyMB = pol.MaxUploadMB
	}
	if maxMB := ed.EffectiveMaxUploadMB(policyMB); hdr.Size > int64(maxMB)<<20 {
		writeErr(w, r, http.StatusRequestEntityTooLarge, "TENANT_UPLOAD_LIMIT",
			"超过当前单文件上限（"+strconv.Itoa(maxMB)+"MB，受档位与租户策略共同约束）")
		return
	}
	if a.Metering != nil {
		if v, qerr := a.Metering.Check(r.Context(), c.TenantID, "storage", hdr.Size); qerr == nil && !v.Allowed {
			_ = a.emit(r, c.TenantID, AuditEntry{
				ActorID: c.Subject, Action: "node.upload", ObjectID: spaceID, Result: "denied",
				Detail: map[string]any{"reason": "quota", "metric": v.Reason},
			})
			writeErr(w, r, http.StatusForbidden, "QUOTA_EXCEEDED",
				"存储配额已用尽（"+v.Reason+"），请联系管理员扩容")
			return
		}
	}

	// 上传前两道静态检查。它们不依赖权限，但必须挡在写盘之前：
	// 一旦内容落进 blob，后续就只能靠"隔离/删除"补救。
	if a.rejectByExtWhitelist(w, r, c.TenantID, hdr.Filename) {
		return
	}
	if err := guardUploadName(hdr.Filename); err != nil {
		writeErr(w, r, http.StatusBadRequest, "UNSAFE_FILENAME", "文件名包含不允许的扩展名组合")
		return
	}
	br := bufio.NewReaderSize(file, 4096)
	headBuf, _ := br.Peek(512)
	if kind := sniffExecutable(headBuf); kind != "" {
		writeErr(w, r, http.StatusUnsupportedMediaType, "UNSAFE_CONTENT",
			"检测到可执行文件特征（"+kind+"），已拒绝上传")
		return
	}
	// 必须用 br 而不是原 file：Peek 已经把开头读进缓冲区，
	// 再用 file 会丢掉前 512 字节，落库内容与原文不一致。
	var src io.Reader = br

	// ---- 写盘前的最后两道关：SVG 净化 + 病毒扫描 ----
	//
	// 顺序说明：两者都必须在 UploadFile 之前完成。
	// 一旦内容进入 blob，后续只能"删除"，而删除是软删、内容仍在磁盘上。
	// 需要扫描/净化时把内容读进内存：上限 64MB，超过则明确拒绝，
	// 绝不"太大就不扫了"——静默降级等于没有防护。
	needBuffer := a.Scanner != nil || content.LooksLikeSVG(hdr.Filename, mime, headBuf)
	if needBuffer {
		payload, rerr := io.ReadAll(io.LimitReader(br, maxScanBytes+1))
		if rerr != nil {
			writeErr(w, r, http.StatusBadRequest, "INVALID_ARGUMENT", "读取上传内容失败")
			return
		}
		if int64(len(payload)) > maxScanBytes {
			writeErr(w, r, http.StatusRequestEntityTooLarge, "TOO_LARGE_TO_SCAN",
				"文件超过可扫描上限（64MB），请压缩后上传或联系管理员")
			return
		}

		// SVG 净化（AC-70）：只放行白名单结构
		if content.LooksLikeSVG(hdr.Filename, mime, payload) {
			clean, serr := content.SanitizeSVG(payload)
			if serr != nil {
				_ = a.emit(r, c.TenantID, AuditEntry{
					ActorID: c.Subject, Action: "node.upload", ObjectID: spaceID, Result: "denied",
					Detail: map[string]any{"reason": "svg_unsafe", "name": hdr.Filename, "detail": serr.Error()},
				})
				writeErr(w, r, http.StatusUnsupportedMediaType, "UNSAFE_SVG", "SVG 含不安全结构，已拒绝")
				return
			}
			payload = clean
		}

		// 病毒扫描（AC-69）
		if a.Scanner != nil {
			res, serr := a.Scanner.Scan(r.Context(), bytes.NewReader(payload))
			switch res.Verdict {
			case scan.Infected:
				_ = a.emit(r, c.TenantID, AuditEntry{
					ActorID: c.Subject, Action: "node.upload", ObjectID: spaceID, Result: "denied",
					Detail: map[string]any{"reason": "virus", "signature": res.Signature, "name": hdr.Filename},
				})
				writeErr(w, r, http.StatusBadRequest, "VIRUS_DETECTED", "文件命中病毒特征，已拒绝上传")
				return
			case scan.Failed:
				// 扫描器故障时拒绝（fail-closed）：否则"打挂 ClamAV"就成了上传通道
				writeErr(w, r, http.StatusServiceUnavailable, "SCAN_UNAVAILABLE", "病毒扫描暂不可用，请稍后重试")
				return
			}
			_ = serr
		}
		src = bytes.NewReader(payload)
	}

	nodeID, versionID, size, err := a.Content.UploadFile(r.Context(), c.TenantID, spaceID, parentID,
		c.Subject, hdr.Filename, mime, src, maxUploadBytes)
	if err != nil {
		switch {
		case errors.Is(err, content.ErrBadInput):
			writeErr(w, r, http.StatusBadRequest, "INVALID_ARGUMENT", "文件名不合法")
		case errors.Is(err, content.ErrTooLarge):
			writeErr(w, r, http.StatusRequestEntityTooLarge, "TOO_LARGE", "文件超过上限")
		case errors.Is(err, content.ErrNotFound):
			writeErr(w, r, http.StatusNotFound, "NOT_FOUND", "目标目录不存在")
		default:
			// 数据库配额硬拦截要翻译成可读错误，否则客户只看到 500
			if metric, ok := isQuotaErr(err); ok {
				writeErr(w, r, http.StatusForbidden, "QUOTA_EXCEEDED",
					"配额已用尽（"+metric+"），请联系管理员扩容")
				return
			}
			writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "上传失败")
		}
		return
	}

	if uploadClass > 0 {
		// 定密失败必须让上传整体失败：否则会留下"高密内容以 0 级存在"的窗口，
		// 那是最危险的状态——文件已可被所有人看到，而审计显示"上传成功"。
		if err := db.WithTenant(r.Context(), a.Pool, c.TenantID, func(tx pgx.Tx) error {
			return classification.SetNode(r.Context(), tx, nodeID, uploadClass, actorClass)
		}); err != nil {
			_, _ = a.Content.SoftDeleteNode(r.Context(), c.TenantID, nodeID)
			writeErr(w, r, http.StatusInternalServerError, "CLASSIFICATION_FAILED",
				"定密失败，上传已回滚")
			return
		}
	}

	if err := a.emit(r, c.TenantID, AuditEntry{
		ActorID: c.Subject, Action: "node.upload", ObjectID: nodeID, Result: "ok",
		Detail: map[string]any{"name": hdr.Filename, "size": size, "versionId": versionID,
			"classification": uploadClass},
	}); err != nil {
		writeErr(w, r, http.StatusInternalServerError, "AUDIT_FAILED", "审计写入失败，操作已拒绝")
		return
	}
	writeOK(w, r, map[string]any{"nodeId": nodeID, "versionId": versionID, "size": size})

	// 覆盖上传会追加版本，按租户保留数量清理一次。
	// 放在响应之后：清理不该拖慢上传。
	a.pruneVersions(r.Context(), c.TenantID, nodeID)
}

func (a *API) handleList(w http.ResponseWriter, r *http.Request) {
	c, _ := claimsFrom(r.Context())
	spaceID := r.PathValue("spaceId")
	parentID := r.URL.Query().Get("parentId")

	target := parentID
	if target == "" {
		target = spaceID
	}
	d, err := a.check(r.Context(), c, spaceID, target, authz.Display)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "权限判定失败")
		return
	}
	if a.denyUnless(w, r, d) {
		return
	}

	nodes, err := a.Content.ListNodes(r.Context(), c.TenantID, spaceID, parentID)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "读取目录失败")
		return
	}
	items := make([]map[string]any, 0, len(nodes))
	for _, n := range nodes {
		// owner / updatedBy 只给显示名与 id：列表读者可能只有 display 权限，
		// 不该借"谁改的"这个字段泄露账号、邮箱等身份信息。
		items = append(items, map[string]any{
			"id": n.ID, "kind": n.Kind, "name": n.Name, "size": n.SizeBytes,
			"mime": n.Mime, "updatedAt": n.UpdatedAt.UTC().Format(time.RFC3339),
			"createdAt":      n.CreatedAt.UTC().Format(time.RFC3339),
			"classification": n.Classification,
			"versionNo":      n.VersionNo,
			"owner":          map[string]any{"id": n.OwnerID, "name": n.OwnerName},
			"updatedBy":      map[string]any{"name": n.UpdatedByName},
		})
	}
	writeOK(w, r, map[string]any{"items": items, "count": len(items)})
}

func (a *API) handleDownload(w http.ResponseWriter, r *http.Request) {
	c, _ := claimsFrom(r.Context())
	nodeID := r.PathValue("id")

	n, err := a.Content.GetNode(r.Context(), c.TenantID, nodeID)
	if err != nil {
		if errors.Is(err, content.ErrNotFound) {
			writeErr(w, r, http.StatusNotFound, "NOT_FOUND", "对象不存在")
			return
		}
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "读取失败")
		return
	}

	d, err := a.check(r.Context(), c, n.SpaceID, nodeID, authz.Download)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "权限判定失败")
		return
	}
	if a.denyUnless(w, r, d) {
		return
	}

	rc, node, err := a.Content.OpenContent(r.Context(), c.TenantID, nodeID)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "内容不可用")
		return
	}
	defer func() { _ = rc.Close() }()

	_ = a.emit(r, c.TenantID, AuditEntry{
		ActorID: c.Subject, Action: "node.download", ObjectID: nodeID, Result: "ok",
	})

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename*=UTF-8''%s", urlEscape(node.Name)))
	w.Header().Set("Content-Length", strconv.FormatInt(node.SizeBytes, 10))
	w.WriteHeader(http.StatusOK)
	_, _ = io.Copy(w, rc)
}

// urlEscape 做最小化的文件名转义（RFC 5987 的 filename*）。
func urlEscape(s string) string {
	var b []byte
	for _, r := range []byte(s) {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') ||
			r == '-' || r == '_' || r == '.' || r == '~' {
			b = append(b, r)
		} else {
			b = append(b, '%')
			const hexDigits = "0123456789ABCDEF"
			b = append(b, hexDigits[r>>4], hexDigits[r&0x0f])
		}
	}
	return string(b)
}

// ---------------- 节点元数据 / 重命名 / 删除 / 移动 ----------------

// handleNodeMeta 返回单个对象的信息（不含内容）。
// 需要 display 权限；无权限与不存在统一 404，避免枚举。
func (a *API) handleNodeMeta(w http.ResponseWriter, r *http.Request) {
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
	writeOK(w, r, map[string]any{
		"id": n.ID, "spaceId": n.SpaceID, "kind": n.Kind, "name": n.Name,
		"size": n.SizeBytes, "mime": n.Mime, "depth": n.Depth,
		"createdAt":      n.CreatedAt.UTC().Format(time.RFC3339),
		"updatedAt":      n.UpdatedAt.UTC().Format(time.RFC3339),
		"classification": n.Classification,
		"versionNo":      n.VersionNo,
		"owner":          map[string]any{"id": n.OwnerID, "name": n.OwnerName},
		"updatedBy":      map[string]any{"name": n.UpdatedByName},
	})
}

// handleNodePath 返回从空间根到该节点的祖先链，供页面地址恢复面包屑。
//
// 权限口径与列表一致（display）：能看见这一层，才有必要知道自己在哪一层。
func (a *API) handleNodePath(w http.ResponseWriter, r *http.Request) {
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

	path, err := a.Content.NodePath(r.Context(), c.TenantID, nodeID)
	if err != nil {
		writeErr(w, r, http.StatusNotFound, "NOT_FOUND", "对象不存在")
		return
	}
	items := make([]map[string]any, 0, len(path))
	for _, p := range path {
		items = append(items, map[string]any{"id": p.ID, "name": p.Name})
	}
	writeOK(w, r, map[string]any{"spaceId": n.SpaceID, "items": items})
}

func (a *API) handleRename(w http.ResponseWriter, r *http.Request) {
	c, _ := claimsFrom(r.Context())
	nodeID := r.PathValue("id")
	var req struct {
		Name string `json:"name"`
	}
	if !decode(w, r, &req) {
		return
	}

	n, err := a.Content.GetNode(r.Context(), c.TenantID, nodeID)
	if err != nil {
		writeErr(w, r, http.StatusNotFound, "NOT_FOUND", "对象不存在")
		return
	}
	// 判 rename 位而不是 edit：权限模型里两者是独立的原子位，
	// "可改内容但不可改名"是真实存在的策略（例如模板目录）。
	// 用 edit 判的后果是 rename 位形同虚设——授了却不起作用。
	d, err := a.check(r.Context(), c, n.SpaceID, nodeID, authz.Rename)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "权限判定失败")
		return
	}
	if a.denyUnless(w, r, d) {
		return
	}

	if err := a.Content.RenameNode(r.Context(), c.TenantID, nodeID, req.Name); err != nil {
		switch {
		case errors.Is(err, content.ErrNameTaken):
			writeErr(w, r, http.StatusConflict, "ALREADY_EXISTS", "同目录下已存在同名对象")
		case errors.Is(err, content.ErrBadInput):
			writeErr(w, r, http.StatusBadRequest, "INVALID_ARGUMENT", "名称不合法")
		case errors.Is(err, content.ErrNotFound):
			writeErr(w, r, http.StatusNotFound, "NOT_FOUND", "对象不存在")
		default:
			writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "重命名失败")
		}
		return
	}
	if err := a.emit(r, c.TenantID, AuditEntry{
		ActorID: c.Subject, Action: "node.rename", ObjectID: nodeID, Result: "ok",
		Detail: map[string]any{"from": n.Name, "to": req.Name},
	}); err != nil {
		writeErr(w, r, http.StatusInternalServerError, "AUDIT_FAILED", "审计写入失败，操作已拒绝")
		return
	}
	writeOK(w, r, map[string]any{"nodeId": nodeID, "name": req.Name})
}

func (a *API) handleDelete(w http.ResponseWriter, r *http.Request) {
	c, _ := claimsFrom(r.Context())
	nodeID := r.PathValue("id")

	n, err := a.Content.GetNode(r.Context(), c.TenantID, nodeID)
	if err != nil {
		writeErr(w, r, http.StatusNotFound, "NOT_FOUND", "对象不存在")
		return
	}
	d, err := a.check(r.Context(), c, n.SpaceID, nodeID, authz.Delete)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "权限判定失败")
		return
	}
	if a.denyUnless(w, r, d) {
		return
	}

	affected, err := a.Content.SoftDeleteNode(r.Context(), c.TenantID, nodeID)
	if err != nil {
		if errors.Is(err, content.ErrNotFound) {
			writeErr(w, r, http.StatusNotFound, "NOT_FOUND", "对象不存在")
			return
		}
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "删除失败")
		return
	}
	if err := a.emit(r, c.TenantID, AuditEntry{
		ActorID: c.Subject, Action: "node.delete", ObjectID: nodeID, Result: "ok",
		Detail: map[string]any{"name": n.Name, "affected": affected},
	}); err != nil {
		writeErr(w, r, http.StatusInternalServerError, "AUDIT_FAILED", "审计写入失败，操作已拒绝")
		return
	}
	writeOK(w, r, map[string]any{"deleted": affected})
}

// handleMove 移动对象。
//
// 两侧都要授权：源对象需要 move（把它从原处移走），
// 目标目录需要 create（往里放东西）。只判一侧就会出现
// "能从我这里拿走，但放不进别人那里"或反之的半成品语义。
func (a *API) handleMove(w http.ResponseWriter, r *http.Request) {
	c, _ := claimsFrom(r.Context())
	nodeID := r.PathValue("id")
	var req struct {
		ParentID string `json:"parentId"`
	}
	if !decode(w, r, &req) {
		return
	}

	n, err := a.Content.GetNode(r.Context(), c.TenantID, nodeID)
	if err != nil {
		writeErr(w, r, http.StatusNotFound, "NOT_FOUND", "对象不存在")
		return
	}

	// 判 Move 位而不是 Delete：移动不是销毁，二者混用会让
	// "只允许移动、不允许删除"这种常见策略无法表达。
	from, err := a.check(r.Context(), c, n.SpaceID, nodeID, authz.Move)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "权限判定失败")
		return
	}
	if a.denyUnless(w, r, from) {
		return
	}

	target := req.ParentID
	if target == "" {
		target = n.SpaceID
	}
	to, err := a.check(r.Context(), c, n.SpaceID, target, authz.Create)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "权限判定失败")
		return
	}
	// 目标无权时返回 403 而非 404：此时用户已知源对象存在，
	// 再假装"不存在"只会让人以为是系统 bug。
	if !to.allowed {
		a.emitQuiet(r, "authz.denied", "move_target:"+to.reason)
		writeErr(w, r, http.StatusForbidden, "FORBIDDEN", "目标目录无写入权限")
		return
	}

	if err := a.Content.MoveNode(r.Context(), c.TenantID, nodeID, req.ParentID); err != nil {
		switch {
		case errors.Is(err, content.ErrNameTaken):
			writeErr(w, r, http.StatusConflict, "ALREADY_EXISTS", "目标目录已存在同名对象")
		case errors.Is(err, content.ErrBadInput):
			writeErr(w, r, http.StatusBadRequest, "INVALID_ARGUMENT", "目标目录不合法（跨空间、非目录或形成环）")
		case errors.Is(err, content.ErrNotFound):
			writeErr(w, r, http.StatusNotFound, "NOT_FOUND", "对象或目标目录不存在")
		default:
			writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "移动失败")
		}
		return
	}
	if err := a.emit(r, c.TenantID, AuditEntry{
		ActorID: c.Subject, Action: "node.move", ObjectID: nodeID, Result: "ok",
		Detail: map[string]any{"name": n.Name, "toParent": req.ParentID},
	}); err != nil {
		writeErr(w, r, http.StatusInternalServerError, "AUDIT_FAILED", "审计写入失败，操作已拒绝")
		return
	}
	writeOK(w, r, map[string]any{"nodeId": nodeID, "parentId": req.ParentID})
}

// ---------------- 上传静态检查 ----------------

// dangerousExts 是"若出现在双扩展名中段就必须拒绝"的扩展名。
// 只查最后一段是不够的：shell.php.jpg 的最后一段是 jpg，
// 但某些老服务器/错误配置会按第一个可识别扩展名执行。
var dangerousExts = map[string]bool{
	".php": true, ".php3": true, ".php4": true, ".phtml": true,
	".jsp": true, ".jspx": true, ".asp": true, ".aspx": true, ".ashx": true,
	".exe": true, ".dll": true, ".bat": true, ".cmd": true, ".com": true,
	".sh": true, ".bash": true, ".ps1": true, ".vbs": true, ".js": true,
	".jar": true, ".war": true, ".scr": true, ".msi": true, ".hta": true,
}

// guardUploadName 拦截双扩展名与超长/超深的名字。
func guardUploadName(name string) error {
	name = strings.TrimSpace(name)
	if name == "" || len([]rune(name)) > 255 {
		return content.ErrBadInput
	}
	lower := strings.ToLower(name)
	parts := strings.Split(lower, ".")
	if len(parts) < 2 {
		return nil
	}
	// 除最后一段外，任何一段命中危险扩展名即拒绝
	for _, seg := range parts[1 : len(parts)-1] {
		if dangerousExts["."+seg] {
			return content.ErrBadInput
		}
	}
	return nil
}

// uploadInterrupted 判断 multipart 解析失败是否源于"请求体没读完"。
//
// Go 在连接被掐断/读超时时返回的并不是统一哨兵：
// 服务端 ReadTimeout 触发时是 net.Error 超时，客户端断开时是 unexpected EOF，
// 取消则通过 context 反映。三种都要认，否则真实的中断会被报成"格式错误"。
func uploadInterrupted(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, context.Canceled) ||
		errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "unexpected eof") || strings.Contains(msg, "timeout") ||
		strings.Contains(msg, "connection reset")
}

// sniffExecutable 通过文件头魔数识别可执行文件。
//
// 不依赖 Content-Type：客户端可以随便改；也不完全依赖 http.DetectContentType，
// 因为它对 ELF/Mach-O 没有签名。这里按魔数判断，结论稳定且可测试。
func sniffExecutable(head []byte) string {
	switch {
	case len(head) >= 2 && head[0] == 'M' && head[1] == 'Z':
		return "PE/Windows 可执行文件"
	case len(head) >= 4 && head[0] == 0x7f && head[1] == 'E' && head[2] == 'L' && head[3] == 'F':
		return "ELF 可执行文件"
	case len(head) >= 4 && head[0] == 0xfe && head[1] == 0xed && head[2] == 0xfa && head[3] == 0xce:
		return "Mach-O 可执行文件"
	case len(head) >= 4 && head[0] == 0xca && head[1] == 0xfe && head[2] == 0xba && head[3] == 0xbe:
		return "Mach-O 通用二进制"
	case len(head) >= 4 && head[0] == '#' && head[1] == '!' && head[2] == '/' && head[3] == 'b':
		return "脚本（shebang）"
	}
	return ""
}
