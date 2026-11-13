package httpapi

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"

	"docvault/internal/ace"
	"docvault/internal/authz"
	"docvault/internal/content"
	"docvault/internal/db"
	"docvault/internal/tenant"

	"github.com/jackc/pgx/v5"
)

// pruneVersions 按租户策略清理旧版本。
//
// 失败不回传、不阻断主流程：版本清理不是正确性的一部分，
// 下一次写入会再清一次；反过来，让一次清理失败把上传/回退判成失败，
// 客户会看到"文件传上去了但报错"，比不清理更糟。
func (a *API) pruneVersions(ctx context.Context, tenantID, nodeID string) {
	policyKeep := 0
	if pol, err := a.tenantPolicy(ctx, tenantID); err == nil {
		policyKeep = pol.VersionKeep
	}
	keep := tenant.DefaultVersionKeep
	if ed, err := a.editionState(ctx, tenantID); err == nil {
		// 取"档位上限"与"租户策略"的较小值：改策略不能突破档位。
		keep = ed.EffectiveVersionKeep(policyKeep)
	}
	// 读不到档位时退回默认值而不是跳过清理：
	// 清理失败不影响数据正确性，但"永远不清理"会让版本表无限增长。
	_, _ = a.Content.PruneVersions(ctx, tenantID, nodeID, keep)
}

// registerGovernance 注册权限治理类端点：解释、改档、继承断点、版本定版。
//
// 这一组端点的共同点：**都是"读起来无害、写错了致命"的操作**。
// 所以每一个都独立做权限判定，不复用列表类接口的宽松口径。
func (a *API) registerGovernance(mux *http.ServeMux) {
	mux.HandleFunc("PATCH /v1/acl/{id}", a.requireAuth(a.handlePatchACL))
	mux.HandleFunc("GET /v1/nodes/{id}/permissions/explain", a.requireAuth(a.handleExplain))
	mux.HandleFunc("POST /v1/nodes/{id}/inheritance", a.requireAuth(a.handleInheritance))
	mux.HandleFunc("GET /v1/nodes/{id}/versions", a.requireAuth(a.handleListVersions))
	mux.HandleFunc("POST /v1/nodes/{id}/versions/{no}/restore", a.requireAuth(a.handleRestoreVersion))
	mux.HandleFunc("GET /v1/nodes/{id}/versions/{no}/download", a.requireAuth(a.handleVersionDownload))
	// 旧接口：语义是"把某版本设为生效"，但实现只改了一个没人读的指针，
	// 导致"回退后内容不变"。现在行为等价于 restore，保留一个版本的兼容期。
	mux.HandleFunc("POST /v1/nodes/{id}/versions/{no}/effective", a.requireAuth(a.handleSetEffective))
}

// handlePatchACL 修改一条 ACE 的档位与有效期。
func (a *API) handlePatchACL(w http.ResponseWriter, r *http.Request) {
	c, _ := claimsFrom(r.Context())
	aceID := r.PathValue("id")

	var req struct {
		Preset         string `json:"preset"`
		ExpiresInHours int    `json:"expiresInHours"`
		ClearExpiry    bool   `json:"clearExpiry"`
	}
	if !decode(w, r, &req) {
		return
	}
	preset := authz.Preset(req.Preset)
	if !preset.Valid() {
		writeErr(w, r, http.StatusBadRequest, "INVALID_ARGUMENT", "未知权限档位")
		return
	}
	if req.ExpiresInHours < 0 {
		writeErr(w, r, http.StatusBadRequest, "INVALID_ARGUMENT", "有效期不能为负")
		return
	}

	// 先定位 ACE 所属对象，再按对象判 manage_acl
	var objectType, objectID string
	var err error
	err = db.WithTenant(r.Context(), a.Pool, c.TenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(r.Context(),
			`SELECT object_type, object_id::text FROM ace WHERE id = $1`, aceID).
			Scan(&objectType, &objectID)
	})
	if err != nil {
		writeErr(w, r, http.StatusNotFound, "NOT_FOUND", "权限条目不存在")
		return
	}

	spaceID, nodeID, err := a.aclTarget(r.Context(), c, objectType, objectID)
	if err != nil {
		writeErr(w, r, http.StatusNotFound, "NOT_FOUND", "对象不存在")
		return
	}
	d, err := a.check(r.Context(), c, spaceID, nodeID, authz.ManageACL)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "权限判定失败")
		return
	}
	if a.denyUnless(w, r, d) {
		return
	}

	var expires *time.Time
	if req.ExpiresInHours > 0 {
		t := time.Now().Add(time.Duration(req.ExpiresInHours) * time.Hour)
		expires = &t
	}

	err = db.WithTenant(r.Context(), a.Pool, c.TenantID, func(tx pgx.Tx) error {
		return ace.Update(r.Context(), tx, aceID, preset, expires, req.ClearExpiry, c.Subject)
	})
	switch {
	case errors.Is(err, ace.ErrInheritedACE):
		writeErr(w, r, http.StatusConflict, "INHERITED_ACE", "继承而来的权限不能单独修改，请先恢复继承")
		return
	case errors.Is(err, ace.ErrCeilingExceeded):
		_ = a.emit(r, c.TenantID, AuditEntry{
			ActorID: c.Subject, Action: "acl.update", ObjectID: objectID, Result: "denied",
			Detail: map[string]any{"reason": "ceiling", "aceId": aceID, "preset": req.Preset},
		})
		writeErr(w, r, http.StatusForbidden, "CEILING_EXCEEDED", "不能授出高于自身档位的权限")
		return
	case err != nil:
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "修改权限失败")
		return
	}

	if err := a.emit(r, c.TenantID, AuditEntry{
		ActorID: c.Subject, Action: "acl.update", ObjectID: objectID, Result: "ok",
		Detail: map[string]any{"aceId": aceID, "preset": req.Preset,
			"expiresInHours": req.ExpiresInHours, "clearExpiry": req.ClearExpiry},
	}); err != nil {
		writeErr(w, r, http.StatusInternalServerError, "AUDIT_FAILED", "审计写入失败，操作已拒绝")
		return
	}
	writeOK(w, r, map[string]any{"aceId": aceID, "preset": req.Preset, "allow": preset.Bits().Names()})
}

// handleExplain 返回一次权限判定的完整依据。
//
// 访问控制：只能查自己；查他人必须对该对象有 manage_acl。
// 这一条不是"顺手加的"——权限解释会暴露"谁被授权、缺哪个位、卡在哪一步"，
// 对普通用户开放等于把 ACL 结构泄露给所有能看见这个文件的人（AC-30）。
func (a *API) handleExplain(w http.ResponseWriter, r *http.Request) {
	c, _ := claimsFrom(r.Context())
	nodeID := r.PathValue("id")

	actionName := r.URL.Query().Get("action")
	if actionName == "" {
		actionName = "display"
	}
	act, ok := authz.ActionByName(actionName)
	if !ok {
		writeErr(w, r, http.StatusBadRequest, "INVALID_ARGUMENT", "未知动作："+actionName)
		return
	}

	n, err := a.Content.GetNode(r.Context(), c.TenantID, nodeID)
	if err != nil {
		writeErr(w, r, http.StatusNotFound, "NOT_FOUND", "对象不存在")
		return
	}

	targetID := r.URL.Query().Get("subjectId")
	askingForOther := targetID != "" && targetID != c.Subject
	if askingForOther {
		d, err := a.check(r.Context(), c, n.SpaceID, nodeID, authz.ManageACL)
		if err != nil {
			writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "权限判定失败")
			return
		}
		if a.denyUnless(w, r, d) {
			return
		}
	} else {
		targetID = c.Subject
	}

	var (
		ex      authz.Explanation
		subject authz.Subject
		matched []map[string]any
	)
	err = db.WithTenant(r.Context(), a.Pool, c.TenantID, func(tx pgx.Tx) error {
		sub, err := ace.LoadSubject(r.Context(), tx, c.TenantID, targetID)
		if err != nil {
			return err
		}
		if !askingForOther {
			// 自查时用令牌里的 epoch 校验会话是否已被吊销
			sub.TokenEpoch = c.Epoch
		} else {
			sub.TokenEpoch = sub.Epoch
		}
		subject = sub

		aces, err := ace.LoadForNode(r.Context(), tx, n.SpaceID, nodeID)
		if err != nil {
			return err
		}

		e, err := authz.Explain(r.Context(), &ace.Source{Aces: aces}, sub,
			authz.Object{ID: nodeID, TenantID: c.TenantID, Type: "node", Class: n.Classification},
			act, time.Now())
		if err != nil {
			return err
		}
		ex = e

		// 只回传"与目标主体相关"的条目，避免把整个对象的授权名单一起暴露
		keys := map[string]bool{
			"user:" + sub.ID: true, "external:" + sub.ID: true, "anonymous:": sub.IsAnonymous,
		}
		for _, dp := range sub.DeptPaths {
			keys["dept:"+dp] = true
		}
		for _, rID := range sub.RoleIDs {
			keys["role:"+rID] = true
		}
		for _, gID := range sub.GroupIDs {
			keys["group:"+gID] = true
		}
		for _, one := range aces {
			if !keys[one.SubjectType+":"+one.SubjectID] {
				continue
			}
			matched = append(matched, map[string]any{
				"aceId": one.ID, "subjectType": one.SubjectType, "subjectId": one.SubjectID,
				"allow": one.Allow.Names(), "deny": one.Deny.Names(),
				"depth": one.Depth, "conditions": one.Conditions,
			})
		}
		return nil
	})
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "权限判定失败")
		return
	}

	writeOK(w, r, map[string]any{
		"object": map[string]any{
			"type": "node", "id": nodeID, "classification": n.Classification,
			"ownerId": n.OwnerID,
		},
		"subject": map[string]any{
			"id": subject.ID, "external": subject.IsExternal, "active": subject.Active,
			"classification": subject.Class, "ceiling": subject.Ceiling,
			"deptPaths": subject.DeptPaths, "roleIds": subject.RoleIDs, "groupIds": subject.GroupIDs,
		},
		"action":  actionName,
		"allowed": ex.Allowed,
		"reason":  ex.Reason,
		"chain":   ex.Chain,
		"steps":   ex.Steps,
		"matched": matched,
	})
}

// handleInheritance 断开/恢复节点的权限继承。
func (a *API) handleInheritance(w http.ResponseWriter, r *http.Request) {
	c, _ := claimsFrom(r.Context())
	nodeID := r.PathValue("id")

	var req struct {
		Broken bool `json:"broken"`
	}
	if !decode(w, r, &req) {
		return
	}

	n, err := a.Content.GetNode(r.Context(), c.TenantID, nodeID)
	if err != nil {
		writeErr(w, r, http.StatusNotFound, "NOT_FOUND", "对象不存在")
		return
	}
	if n.Kind != "folder" && n.Kind != "file" {
		writeErr(w, r, http.StatusBadRequest, "INVALID_ARGUMENT", "继承只适用于文件或目录")
		return
	}

	d, err := a.check(r.Context(), c, n.SpaceID, nodeID, authz.ManageACL)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "权限判定失败")
		return
	}
	if a.denyUnless(w, r, d) {
		return
	}

	var (
		affected int
		state    ace.InheritState
	)
	err = db.WithTenant(r.Context(), a.Pool, c.TenantID, func(tx pgx.Tx) error {
		var e error
		if req.Broken {
			affected, e = ace.BreakInheritance(r.Context(), tx, c.TenantID, nodeID)
		} else {
			affected, e = ace.RestoreInheritance(r.Context(), tx, nodeID)
		}
		if e != nil {
			return e
		}
		state, e = ace.InheritStateOf(r.Context(), tx, nodeID)
		return e
	})
	if err != nil {
		if errors.Is(err, ace.ErrNotANode) {
			writeErr(w, r, http.StatusBadRequest, "INVALID_ARGUMENT", "继承只适用于文件或目录")
			return
		}
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "继承操作失败")
		return
	}

	if err := a.emit(r, c.TenantID, AuditEntry{
		ActorID: c.Subject, Action: "acl.inheritance", ObjectID: nodeID, Result: "ok",
		Detail: map[string]any{"broken": req.Broken, "affected": affected},
	}); err != nil {
		writeErr(w, r, http.StatusInternalServerError, "AUDIT_FAILED", "审计写入失败，操作已拒绝")
		return
	}
	writeOK(w, r, map[string]any{
		"nodeId": nodeID, "broken": state.Broken,
		"affected": affected, "inheritedAces": state.InheritedACEs,
	})
}

// handleListVersions 列出节点的版本。
func (a *API) handleListVersions(w http.ResponseWriter, r *http.Request) {
	c, _ := claimsFrom(r.Context())
	nodeID := r.PathValue("id")

	n, err := a.Content.GetNode(r.Context(), c.TenantID, nodeID)
	if err != nil {
		writeErr(w, r, http.StatusNotFound, "NOT_FOUND", "对象不存在")
		return
	}
	// 看版本列表 ≠ 看内容：只要能看到对象就允许列出元数据，
	// 但单个版本的字节流仍然只走 preview/download 判定。
	d, err := a.check(r.Context(), c, n.SpaceID, nodeID, authz.Display)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "权限判定失败")
		return
	}
	if a.denyUnless(w, r, d) {
		return
	}

	vs, err := a.Content.ListVersions(r.Context(), c.TenantID, nodeID)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "读取版本失败")
		return
	}
	items := make([]map[string]any, 0, len(vs))
	for _, v := range vs {
		items = append(items, map[string]any{
			"versionNo": v.VersionNo, "sizeBytes": v.SizeBytes, "sha256": v.SHA256,
			"state": v.State, "createdBy": v.CreatedBy, "note": v.Note,
			"origin": v.Origin, "restoredFromNo": v.RestoredFromNo,
			"createdAt": v.CreatedAt.UTC().Format(time.RFC3339),
			// isEffective 保留给旧前端，语义已与 isCurrent 合并
			"isCurrent": v.IsCurrent, "isEffective": v.IsEffective,
		})
	}
	// 保留数量随列表一起返回：前端要提示"仅保留最近 N 个版本"，
	// 否则客户会以为版本是永久留存的，等到被清理时才发现。
	keep := tenant.DefaultVersionKeep
	if pol, perr := a.tenantPolicy(r.Context(), c.TenantID); perr == nil && pol.VersionKeep > 0 {
		keep = pol.VersionKeep
	}
	writeOK(w, r, map[string]any{
		"items":     items,
		"count":     len(items),
		"retention": map[string]any{"keepVersions": keep},
	})
}

// handleRestoreVersion 把历史版本恢复为当前版本（追加新版本，不切换指针）。
func (a *API) handleRestoreVersion(w http.ResponseWriter, r *http.Request) {
	c, _ := claimsFrom(r.Context())
	nodeID := r.PathValue("id")
	no, err := strconv.Atoi(r.PathValue("no"))
	if err != nil || no <= 0 {
		writeErr(w, r, http.StatusBadRequest, "INVALID_ARGUMENT", "版本号必须是正整数")
		return
	}

	n, err := a.Content.GetNode(r.Context(), c.TenantID, nodeID)
	if err != nil {
		writeErr(w, r, http.StatusNotFound, "NOT_FOUND", "对象不存在")
		return
	}
	d, err := a.check(r.Context(), c, n.SpaceID, nodeID, authz.ManageVersion)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "权限判定失败")
		return
	}
	if a.denyUnless(w, r, d) {
		return
	}

	res, err := a.Content.RestoreVersion(r.Context(), c.TenantID, nodeID, no, c.Subject)
	switch {
	case errors.Is(err, content.ErrVersionNotFound):
		writeErr(w, r, http.StatusNotFound, "VERSION_NOT_FOUND", "版本不存在")
		return
	case errors.Is(err, content.ErrVersionVoid):
		writeErr(w, r, http.StatusConflict, "VERSION_VOID", "作废版本不能回退")
		return
	case errors.Is(err, content.ErrVersionAlreadyCurrent):
		writeErr(w, r, http.StatusConflict, "VERSION_ALREADY_CURRENT", "该版本已是当前版本")
		return
	case errors.Is(err, content.ErrVersionContentSame):
		writeErr(w, r, http.StatusConflict, "VERSION_CONTENT_SAME", "当前内容已与该版本相同，无需回退")
		return
	case errors.Is(err, content.ErrContentMissing):
		writeErr(w, r, http.StatusConflict, "CONTENT_MISSING", "该版本的内容已丢失，无法回退")
		return
	case errors.Is(err, content.ErrNodeEditing):
		writeErr(w, r, http.StatusConflict, "EDIT_SESSION_ACTIVE", "文件正在被编辑，请先关闭编辑窗口再回退")
		return
	case err != nil:
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "回退版本失败")
		return
	}

	sha, _ := a.Content.VersionSHA(r.Context(), c.TenantID, nodeID, res.VersionNo)
	if err := a.emit(r, c.TenantID, AuditEntry{
		ActorID: c.Subject, Action: "version.restore", ObjectID: nodeID, Result: "ok",
		Detail: map[string]any{
			"fromVersionNo": res.FromVersionNo,
			"newVersionNo":  res.VersionNo,
			"versionId":     res.VersionID,
			"sha256":        sha,
			// 记录当时的密级，用于证明"回退只换内容、没有顺带降密"
			"classification": n.Classification,
		},
	}); err != nil {
		writeErr(w, r, http.StatusInternalServerError, "AUDIT_FAILED", "审计写入失败，操作已拒绝")
		return
	}

	writeOK(w, r, map[string]any{
		"nodeId":        nodeID,
		"versionId":     res.VersionID,
		"versionNo":     res.VersionNo,
		"fromVersionNo": res.FromVersionNo,
		"sizeBytes":     res.SizeBytes,
		// 兼容旧前端字段名
		"effectiveVersionNo": res.FromVersionNo,
	})

	// 回退也是一次版本追加，同样要受保留数量约束。
	// 放在响应之后：清理慢一点不影响客户端拿到结果。
	a.pruneVersions(r.Context(), c.TenantID, nodeID)
}

// handleSetEffective 旧接口，已下线。
//
// 保留路由而不是直接 404：老客户端会拿到明确的迁移指引，
// 而不是一个看起来像"文件不存在"的 404。
func (a *API) handleSetEffective(w http.ResponseWriter, r *http.Request) {
	writeErr(w, r, http.StatusGone, "ENDPOINT_RETIRED",
		"该接口已下线，请改用 POST /v1/nodes/{id}/versions/{no}/restore")
}

// handleVersionDownload 下载指定版本的内容，不改变当前版本。
func (a *API) handleVersionDownload(w http.ResponseWriter, r *http.Request) {
	c, _ := claimsFrom(r.Context())
	nodeID := r.PathValue("id")
	no, err := strconv.Atoi(r.PathValue("no"))
	if err != nil || no <= 0 {
		writeErr(w, r, http.StatusBadRequest, "INVALID_ARGUMENT", "版本号必须是正整数")
		return
	}

	n, err := a.Content.GetNode(r.Context(), c.TenantID, nodeID)
	if err != nil {
		writeErr(w, r, http.StatusNotFound, "NOT_FOUND", "对象不存在")
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

	rc, node, size, err := a.Content.OpenVersionContent(r.Context(), c.TenantID, nodeID, no)
	if err != nil {
		switch {
		case errors.Is(err, content.ErrVersionNotFound):
			writeErr(w, r, http.StatusNotFound, "VERSION_NOT_FOUND", "版本不存在")
		case errors.Is(err, content.ErrContentMissing):
			writeErr(w, r, http.StatusConflict, "CONTENT_MISSING", "该版本的内容已丢失")
		default:
			writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "内容不可用")
		}
		return
	}
	defer func() { _ = rc.Close() }()

	_ = a.emit(r, c.TenantID, AuditEntry{
		ActorID: c.Subject, Action: "version.download", ObjectID: nodeID, Result: "ok",
		Detail: map[string]any{"versionNo": no},
	})

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition",
		fmt.Sprintf("attachment; filename*=UTF-8''%s", urlEscape(node.Name)))
	w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
	w.WriteHeader(http.StatusOK)
	_, _ = io.Copy(w, rc)
}
