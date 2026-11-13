package httpapi

import (
	"errors"
	"net/http"
	"strconv"
	"time"

	"docvault/internal/authz"
	"docvault/internal/classification"
	"docvault/internal/db"
	"docvault/internal/rbac"

	"github.com/jackc/pgx/v5"
)

// registerClassification 注册密级相关路由。
//
// 权限切分：
//   - 读密级定义：所有登录用户（界面上要显示"内部/秘密"这类标签）
//   - 改密级定义、审批降密、配标签策略：安全管理员（secadmin）
//   - 给对象定密（升密）：对象管理者（manage_acl）
//   - 申请降密：能看见对象的人（有 display）
func (a *API) registerClassification(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/classifications", a.requireAuth(a.handleListClassifications))
	mux.HandleFunc("GET /v1/nodes/{id}/classification", a.requireAuth(a.handleGetClass))
	mux.HandleFunc("PUT /v1/nodes/{id}/classification", a.requireAuth(a.handleSetClass))
	mux.HandleFunc("POST /v1/nodes/{id}/classification/requests", a.requireAuth(a.handleRequestDown))
	mux.HandleFunc("PUT /v1/admin/classifications/{level}", a.requireRole(rbac.SecAdmin)(a.handleSetClassLabel))
	mux.HandleFunc("GET /v1/admin/classification/requests", a.requireRole(rbac.SecAdmin)(a.handleListClassRequests))
	mux.HandleFunc("POST /v1/admin/classification/requests/{id}/decide", a.requireRole(rbac.SecAdmin)(a.handleDecideClassRequest))
	mux.HandleFunc("GET /v1/admin/label-policies", a.requireRole(rbac.SecAdmin)(a.handleListLabelPolicies))
	mux.HandleFunc("PUT /v1/admin/label-policies/{label}", a.requireRole(rbac.SecAdmin)(a.handleSetLabelPolicy))
}

func (a *API) handleListClassifications(w http.ResponseWriter, r *http.Request) {
	c, _ := claimsFrom(r.Context())
	var items []classification.Label
	err := db.WithTenant(r.Context(), a.Pool, c.TenantID, func(tx pgx.Tx) error {
		l, e := classification.Levels(r.Context(), tx, c.TenantID)
		items = l
		return e
	})
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "读取密级定义失败")
		return
	}
	writeOK(w, r, map[string]any{"items": items, "count": len(items)})
}

// handleGetClass 返回对象的密级视图（含标签收紧后的有效值）。
func (a *API) handleGetClass(w http.ResponseWriter, r *http.Request) {
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

	var (
		declared, effective int
		labels              []string
		pending             *classification.ChangeRequest
	)
	err = db.WithTenant(r.Context(), a.Pool, c.TenantID, func(tx pgx.Tx) error {
		if err := tx.QueryRow(r.Context(),
			`SELECT classification FROM node WHERE id = $1`, nodeID).Scan(&declared); err != nil {
			return err
		}
		eff, e := classification.EffectiveClass(r.Context(), tx, c.TenantID, nodeID, n.SpaceID)
		if e != nil {
			return e
		}
		effective = eff
		ls, e := classification.LabelsOf(r.Context(), tx, nodeID)
		if e != nil {
			return e
		}
		labels = ls
		p, e := classification.PendingOf(r.Context(), tx, nodeID)
		if e != nil {
			return e
		}
		pending = p
		return nil
	})
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "读取密级失败")
		return
	}

	out := map[string]any{
		"nodeId": nodeID, "classification": declared,
		"effectiveClassification": effective, "labels": labels,
	}
	if pending != nil {
		out["pendingChange"] = map[string]any{
			"id": pending.ID, "fromLevel": pending.FromLevel, "toLevel": pending.ToLevel,
			"reason": pending.Reason,
		}
	}
	writeOK(w, r, out)
}

// handleSetClass 定密（升密或维持），同时可设置标签。
//
// 降密不走这里：降密必须走申请审批（AC-42）。这里若收到更低的等级，
// 明确拒绝并提示"请提交降密申请"——而不是静默生效或静默忽略。
func (a *API) handleSetClass(w http.ResponseWriter, r *http.Request) {
	c, _ := claimsFrom(r.Context())
	nodeID := r.PathValue("id")

	var req struct {
		Level  *int     `json:"level"`
		Labels []string `json:"labels"`
	}
	if !decode(w, r, &req) {
		return
	}
	if req.Level == nil && req.Labels == nil {
		writeErr(w, r, http.StatusBadRequest, "INVALID_ARGUMENT", "level 与 labels 至少提供一个")
		return
	}

	n, err := a.Content.GetNode(r.Context(), c.TenantID, nodeID)
	if err != nil {
		writeErr(w, r, http.StatusNotFound, "NOT_FOUND", "对象不存在")
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

	// 档位允许写入的密级：与上传入口同一套判定，避免"上传被拒、改密级却能成功"。
	ed, eerr := a.editionState(r.Context(), c.TenantID)
	if eerr != nil {
		writeErr(w, r, http.StatusServiceUnavailable, "ENTITLEMENT_UNAVAILABLE",
			"无法读取租户档位，请稍后重试")
		return
	}
	if req.Level != nil && !ed.CanWriteClass(*req.Level) {
		_ = a.emit(r, c.TenantID, AuditEntry{
			ActorID: c.Subject, Action: "classification.set", ObjectID: nodeID, Result: "denied",
			Detail: map[string]any{"reason": "edition_classification", "requested": *req.Level,
				"edition": string(ed.Edition)},
		})
		writeErr(w, r, http.StatusForbidden, "FEATURE_NOT_ENABLED",
			"当前档位（"+ed.Spec.Name+"）不支持该密级")
		return
	}

	var (
		oldLevel int
		actorCls int
	)
	err = db.WithTenant(r.Context(), a.Pool, c.TenantID, func(tx pgx.Tx) error {
		if err := tx.QueryRow(r.Context(),
			`SELECT classification FROM node WHERE id = $1`, nodeID).Scan(&oldLevel); err != nil {
			return err
		}
		if err := tx.QueryRow(r.Context(),
			`SELECT classification FROM app_user WHERE id = $1`, c.Subject).Scan(&actorCls); err != nil {
			return err
		}

		if req.Level != nil {
			if *req.Level < oldLevel {
				// 降密必须审批：降密 = 扩大知悉范围
				return errNeedApproval
			}
			if err := classification.SetNode(r.Context(), tx, nodeID, *req.Level, actorCls); err != nil {
				return err
			}
		}
		if req.Labels != nil {
			if err := classification.SetLabels(r.Context(), tx, c.TenantID, nodeID, req.Labels); err != nil {
				return err
			}
		}
		return nil
	})
	switch {
	case errors.Is(err, errNeedApproval):
		writeErr(w, r, http.StatusConflict, "NEED_APPROVAL", "降密需提交申请并通过审批，请使用 /classification/requests")
		return
	case errors.Is(err, classification.ErrAboveSelf):
		_ = a.emit(r, c.TenantID, AuditEntry{
			ActorID: c.Subject, Action: "classification.set", ObjectID: nodeID, Result: "denied",
			Detail: map[string]any{"reason": "above_self", "requested": req.Level},
		})
		writeErr(w, r, http.StatusForbidden, "ABOVE_SELF", "不能设置高于自身密级的密级")
		return
	case errors.Is(err, classification.ErrBadLevel):
		writeErr(w, r, http.StatusBadRequest, "INVALID_ARGUMENT", "密级必须在 0..6 之间")
		return
	case err != nil:
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "定密失败")
		return
	}

	if err := a.emit(r, c.TenantID, AuditEntry{
		ActorID: c.Subject, Action: "classification.set", ObjectID: nodeID, Result: "ok",
		Detail: map[string]any{"from": oldLevel, "to": req.Level, "labels": req.Labels},
	}); err != nil {
		writeErr(w, r, http.StatusInternalServerError, "AUDIT_FAILED", "审计写入失败，操作已拒绝")
		return
	}
	writeOK(w, r, map[string]any{"nodeId": nodeID, "classification": req.Level})
}

// errNeedApproval 是内部哨兵：降密必须走审批。
var errNeedApproval = errors.New("需要审批")

// handleRequestDown 提交降密申请。
func (a *API) handleRequestDown(w http.ResponseWriter, r *http.Request) {
	c, _ := claimsFrom(r.Context())
	nodeID := r.PathValue("id")

	var req struct {
		ToLevel int    `json:"toLevel"`
		Reason  string `json:"reason"`
	}
	if !decode(w, r, &req) {
		return
	}

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

	var id string
	err = db.WithTenant(r.Context(), a.Pool, c.TenantID, func(tx pgx.Tx) error {
		i, e := classification.RequestDown(r.Context(), tx, c.TenantID, nodeID, req.ToLevel, req.Reason, c.Subject)
		id = i
		return e
	})
	switch {
	case errors.Is(err, classification.ErrPendingExists):
		writeErr(w, r, http.StatusConflict, "PENDING_EXISTS", "该对象已有待审批的密级变更申请")
		return
	case errors.Is(err, classification.ErrBadLevel):
		writeErr(w, r, http.StatusBadRequest, "INVALID_ARGUMENT", "密级必须在 0..6 之间")
		return
	case err != nil:
		writeErr(w, r, http.StatusBadRequest, "INVALID_ARGUMENT", err.Error())
		return
	}

	_ = a.emit(r, c.TenantID, AuditEntry{
		ActorID: c.Subject, Action: "classification.request_down", ObjectID: nodeID, Result: "ok",
		Detail: map[string]any{"requestId": id, "toLevel": req.ToLevel},
	})
	writeOK(w, r, map[string]any{"requestId": id, "status": "pending"})
}

// handleSetClassLabel 修改密级显示名（AC-40）。
//
// 注意这里**没有** level 的 rank/顺序参数：等级语义固定，
// 因此"在线把系统密级调低"在接口层就不存在。
func (a *API) handleSetClassLabel(w http.ResponseWriter, r *http.Request) {
	c, _ := claimsFrom(r.Context())
	level, err := strconv.Atoi(r.PathValue("level"))
	if err != nil || level < 0 || level > classification.MaxLevel {
		writeErr(w, r, http.StatusBadRequest, "INVALID_ARGUMENT", "密级必须在 0..6 之间")
		return
	}
	var req struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	if !decode(w, r, &req) {
		return
	}

	err = db.WithTenant(r.Context(), a.Pool, c.TenantID, func(tx pgx.Tx) error {
		return classification.SetLabelName(r.Context(), tx, c.TenantID, level, req.Name, req.Description)
	})
	if err != nil {
		writeErr(w, r, http.StatusBadRequest, "INVALID_ARGUMENT", err.Error())
		return
	}
	if err := a.emit(r, c.TenantID, AuditEntry{
		ActorID: c.Subject, Action: "classification.label.set", Result: "ok",
		Detail: map[string]any{"level": level, "name": req.Name},
	}); err != nil {
		writeErr(w, r, http.StatusInternalServerError, "AUDIT_FAILED", "审计写入失败，操作已拒绝")
		return
	}
	writeOK(w, r, map[string]any{"level": level, "name": req.Name})
}

// handleListClassRequests 列出降密申请。
func (a *API) handleListClassRequests(w http.ResponseWriter, r *http.Request) {
	c, _ := claimsFrom(r.Context())
	status := r.URL.Query().Get("status")
	if status == "" {
		status = "pending"
	}

	var items []map[string]any
	err := db.WithTenant(r.Context(), a.Pool, c.TenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(r.Context(), `
			SELECT r.id::text, r.node_id::text, n.name, r.from_level, r.to_level,
			       r.reason, r.status, r.requested_by::text, r.created_at
			  FROM classification_change r JOIN node n ON n.id = r.node_id
			 WHERE r.status = $1 ORDER BY r.created_at DESC LIMIT 200`, status)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var (
				id, nodeID, name, reason, st, by string
				from, to                         int
				created                          time.Time
			)
			if err := rows.Scan(&id, &nodeID, &name, &from, &to, &reason, &st, &by, &created); err != nil {
				return err
			}
			items = append(items, map[string]any{
				"id": id, "nodeId": nodeID, "nodeName": name,
				"fromLevel": from, "toLevel": to, "reason": reason,
				"status": st, "requestedBy": by,
				"createdAt": created.UTC().Format(time.RFC3339),
			})
		}
		return rows.Err()
	})
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "读取申请失败")
		return
	}
	writeOK(w, r, map[string]any{"items": items, "count": len(items)})
}

// handleDecideClassRequest 审批降密申请。
func (a *API) handleDecideClassRequest(w http.ResponseWriter, r *http.Request) {
	c, _ := claimsFrom(r.Context())
	requestID := r.PathValue("id")

	var req struct {
		Approve bool   `json:"approve"`
		Note    string `json:"note"`
	}
	if !decode(w, r, &req) {
		return
	}

	var (
		nodeID   string
		newLevel int
	)
	err := db.WithTenant(r.Context(), a.Pool, c.TenantID, func(tx pgx.Tx) error {
		n, lv, e := classification.Decide(r.Context(), tx, c.TenantID, requestID, c.Subject, req.Approve, req.Note)
		nodeID, newLevel = n, lv
		return e
	})
	switch {
	case errors.Is(err, classification.ErrNotPending):
		writeErr(w, r, http.StatusConflict, "NOT_PENDING", "该申请已处理")
		return
	case errors.Is(err, classification.ErrNotFound):
		writeErr(w, r, http.StatusNotFound, "NOT_FOUND", "申请不存在")
		return
	case err != nil:
		writeErr(w, r, http.StatusForbidden, "FORBIDDEN", err.Error())
		return
	}

	if err := a.emit(r, c.TenantID, AuditEntry{
		ActorID: c.Subject, Action: "classification.decide", ObjectID: nodeID, Result: "ok",
		Detail: map[string]any{"requestId": requestID, "approve": req.Approve,
			"newLevel": newLevel, "note": req.Note},
	}); err != nil {
		writeErr(w, r, http.StatusInternalServerError, "AUDIT_FAILED", "审计写入失败，操作已拒绝")
		return
	}
	writeOK(w, r, map[string]any{"requestId": requestID, "approved": req.Approve,
		"nodeId": nodeID, "classification": newLevel})
}

func (a *API) handleListLabelPolicies(w http.ResponseWriter, r *http.Request) {
	c, _ := claimsFrom(r.Context())
	var out map[string]int
	err := db.WithTenant(r.Context(), a.Pool, c.TenantID, func(tx pgx.Tx) error {
		p, e := classification.Policies(r.Context(), tx, c.TenantID)
		out = p
		return e
	})
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "读取标签策略失败")
		return
	}
	writeOK(w, r, map[string]any{"policies": out})
}

func (a *API) handleSetLabelPolicy(w http.ResponseWriter, r *http.Request) {
	c, _ := claimsFrom(r.Context())
	label := r.PathValue("label")

	var req struct {
		MinLevel int `json:"minLevel"`
	}
	if !decode(w, r, &req) {
		return
	}
	err := db.WithTenant(r.Context(), a.Pool, c.TenantID, func(tx pgx.Tx) error {
		return classification.SetPolicy(r.Context(), tx, c.TenantID, label, req.MinLevel)
	})
	if err != nil {
		writeErr(w, r, http.StatusBadRequest, "INVALID_ARGUMENT", err.Error())
		return
	}
	_ = a.emit(r, c.TenantID, AuditEntry{
		ActorID: c.Subject, Action: "classification.label_policy.set", Result: "ok",
		Detail: map[string]any{"label": label, "minLevel": req.MinLevel},
	})
	writeOK(w, r, map[string]any{"label": label, "minLevel": req.MinLevel})
}
