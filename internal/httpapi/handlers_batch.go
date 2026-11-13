package httpapi

// 批量操作（AC-27 / AC-28）。
//
// 批量是越权最容易被放大的地方：单文件接口好好判权限，
// 批量接口却"按第一个对象的权限执行整批"，一次就能带走大量不该看的文件。
//
// 本实现采取**全量预检 + 整体拒绝**：
//   任何一个对象不满足权限，整批都不执行，也不返回任何部分结果。
// 理由：批量接口如果返回"部分成功"，调用方很难知道哪几个失败了；
// 而"静默少给几个文件"在业务上会被当成 bug 而不是权限拦截，
// 最终演变成"以为下载了全部，其实漏了"或者"以为拦住了，其实下载了"。

import (
	"archive/zip"
	"context"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"docvault/internal/auth"
	"docvault/internal/authz"
	"docvault/internal/content"
)

const (
	maxBatchItems = 100
	maxBatchBytes = 512 << 20 // 单次批量下载上限 512MB
)

// registerBatch 注册批量端点。
func (a *API) registerBatch(mux *http.ServeMux) {
	mux.HandleFunc("POST /v1/batch/download", a.requireAuth(a.handleBatchDownload))
	mux.HandleFunc("POST /v1/batch/move", a.requireAuth(a.handleBatchMove))
}

// batchTarget 是一个已解析并预检通过的对象。
type batchTarget struct {
	nodeID  string
	spaceID string
	node    content.Node
}

// precheck 对一批对象做统一预检，返回首个失败原因。
func (a *API) precheck(ctx context.Context, c auth.Claims, nodeIDs []string, act authz.Bit) ([]batchTarget, *decision, error) {
	out := make([]batchTarget, 0, len(nodeIDs))
	for _, id := range nodeIDs {
		n, err := a.Content.GetNode(ctx, c.TenantID, id)
		if err != nil {
			d := decision{allowed: false, reason: "NOT_FOUND", nodeID: id, act: act}
			return nil, &d, nil
		}
		d, err := a.check(ctx, c, n.SpaceID, id, act)
		if err != nil {
			return nil, nil, err
		}
		if !d.allowed {
			return nil, &d, nil
		}
		out = append(out, batchTarget{nodeID: id, spaceID: n.SpaceID, node: n})
	}
	return out, nil, nil
}

// handleBatchDownload 打包下载多个文件。
func (a *API) handleBatchDownload(w http.ResponseWriter, r *http.Request) {
	c, _ := claimsFrom(r.Context())
	var req struct {
		NodeIDs []string `json:"nodeIds"`
	}
	if !decode(w, r, &req) {
		return
	}
	if len(req.NodeIDs) == 0 || len(req.NodeIDs) > maxBatchItems {
		writeErr(w, r, http.StatusBadRequest, "INVALID_ARGUMENT", "批量数量需在 1..100 之间")
		return
	}

	targets, bad, err := a.precheck(r.Context(), c, req.NodeIDs, authz.Download)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "权限判定失败")
		return
	}
	if bad != nil {
		// 整体拒绝：不返回任何部分内容
		a.denyUnless(w, r, *bad)
		return
	}

	// 先算总体积，避免"打到一半才发现超限"
	var total int64
	for _, t := range targets {
		if t.node.Kind != "file" {
			writeErr(w, r, http.StatusBadRequest, "INVALID_ARGUMENT", "批量下载只接受文件（目录请逐个选择）")
			return
		}
		total += t.node.SizeBytes
	}
	if total > maxBatchBytes {
		writeErr(w, r, http.StatusRequestEntityTooLarge, "TOO_LARGE", "批量下载总大小超过 512MB")
		return
	}

	if err := a.emit(r, c.TenantID, AuditEntry{
		ActorID: c.Subject, Action: "batch.download", Result: "ok",
		Detail: map[string]any{"count": len(targets), "bytes": total},
	}); err != nil {
		writeErr(w, r, http.StatusInternalServerError, "AUDIT_FAILED", "审计写入失败，操作已拒绝")
		return
	}

	zipName := "docvault-" + time.Now().Format("20060102-150405") + ".zip"
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename="`+zipName+`"`)
	w.Header().Set("Cache-Control", "no-store")

	zw := zip.NewWriter(w)
	defer func() { _ = zw.Close() }()

	used := map[string]int{}
	for _, t := range targets {
		rc, n, err := a.Content.OpenContent(r.Context(), c.TenantID, t.nodeID)
		if err != nil {
			// 已经写了响应头，无法改状态码；只能中断，由客户端发现 zip 不完整
			return
		}
		name := uniqueName(used, n.Name)
		fw, err := zw.Create(name)
		if err != nil {
			_ = rc.Close()
			return
		}
		_, _ = io.Copy(fw, rc)
		_ = rc.Close()
	}
}

// uniqueName 处理压缩包内的重名（同名文件来自不同目录时很常见）。
func uniqueName(used map[string]int, name string) string {
	if _, ok := used[name]; !ok {
		used[name] = 1
		return name
	}
	used[name]++
	base := name
	ext := ""
	if i := strings.LastIndex(name, "."); i > 0 {
		base, ext = name[:i], name[i:]
	}
	return base + " (" + strconv.Itoa(used[name]) + ")" + ext
}

// handleBatchMove 批量移动。
func (a *API) handleBatchMove(w http.ResponseWriter, r *http.Request) {
	c, _ := claimsFrom(r.Context())
	var req struct {
		NodeIDs        []string `json:"nodeIds"`
		TargetParentID string   `json:"targetParentId"`
	}
	if !decode(w, r, &req) {
		return
	}
	if len(req.NodeIDs) == 0 || len(req.NodeIDs) > maxBatchItems {
		writeErr(w, r, http.StatusBadRequest, "INVALID_ARGUMENT", "批量数量需在 1..100 之间")
		return
	}

	// 目标容器：先确认存在与所在空间，再单独判 create
	if req.TargetParentID != "" {
		parent, err := a.Content.GetNode(r.Context(), c.TenantID, req.TargetParentID)
		if err != nil {
			writeErr(w, r, http.StatusNotFound, "NOT_FOUND", "目标目录不存在")
			return
		}
		d, err := a.check(r.Context(), c, parent.SpaceID, req.TargetParentID, authz.Create)
		if err != nil {
			writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "权限判定失败")
			return
		}
		if a.denyUnless(w, r, d) {
			return
		}
	}

	// 逐个判"源删除 + 目标创建"：移动是唯一需要两个对象同时成立的动作
	for _, id := range req.NodeIDs {
		n, err := a.Content.GetNode(r.Context(), c.TenantID, id)
		if err != nil {
			writeErr(w, r, http.StatusNotFound, "NOT_FOUND", "对象不存在")
			return
		}
		d, err := a.check(r.Context(), c, n.SpaceID, id, authz.Delete)
		if err != nil {
			writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "权限判定失败")
			return
		}
		if a.denyUnless(w, r, d) {
			return
		}
		if req.TargetParentID != "" {
			dd, err := a.check(r.Context(), c, n.SpaceID, req.TargetParentID, authz.Create)
			if err != nil {
				writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "权限判定失败")
				return
			}
			if a.denyUnless(w, r, dd) {
				return
			}
		}
	}

	moved, err := a.Content.MoveNodes(r.Context(), c.TenantID, req.NodeIDs, req.TargetParentID)
	if err != nil {
		switch {
		case errors.Is(err, content.ErrNotFound):
			writeErr(w, r, http.StatusNotFound, "NOT_FOUND", "对象或目标目录不存在")
		case errors.Is(err, content.ErrNameTaken):
			writeErr(w, r, http.StatusConflict, "NAME_TAKEN", "目标目录存在同名对象")
		case errors.Is(err, content.ErrBadInput):
			writeErr(w, r, http.StatusBadRequest, "INVALID_ARGUMENT", "移动目标非法（跨空间或形成环）")
		default:
			writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "批量移动失败")
		}
		return
	}

	if err := a.emit(r, c.TenantID, AuditEntry{
		ActorID: c.Subject, Action: "batch.move", ObjectID: req.TargetParentID, Result: "ok",
		Detail: map[string]any{"count": moved, "nodeIds": req.NodeIDs},
	}); err != nil {
		writeErr(w, r, http.StatusInternalServerError, "AUDIT_FAILED", "审计写入失败，操作已拒绝")
		return
	}
	writeOK(w, r, map[string]any{"moved": moved})
}
