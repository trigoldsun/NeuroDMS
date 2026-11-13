package httpapi

// 空间所有权移交接口。
//
// 权限规则（与 content 层的写入原语分开：这一层决定"谁能发起、要不要确认"）：
//
//	调用方          目标        生效方式
//	当前所有者      任意可用成员  立即生效
//	sysadmin（非所有者） 第三方   立即生效（审计记发起人）
//	sysadmin（非所有者） 自己     生成请求，原所有者确认后生效
//	其他人                       不允许（移交不是授权）
//
// "管理员转给自己要确认"是这一组里唯一不能省略的规则：管理员天然可以
// 看到所有账号，如果不设这道闸，他可以把任何一个员工的空间收进自己名下。

import (
	"errors"
	"net/http"

	"docvault/internal/content"
	"docvault/internal/rbac"
)

func (a *API) registerTransfer(mux *http.ServeMux) {
	mux.HandleFunc("POST /v1/spaces/{spaceId}/transfer", a.requireAuth(a.handleTransferSpace))
	mux.HandleFunc("GET /v1/transfers/pending", a.requireAuth(a.handlePendingTransfers))
	mux.HandleFunc("POST /v1/transfers/{id}/decide", a.requireAuth(a.handleDecideTransfer))
	mux.HandleFunc("DELETE /v1/transfers/{id}", a.requireAuth(a.handleCancelTransfer))
	// 空间台账：只看元数据，点不进内容
	mux.HandleFunc("GET /v1/admin/spaces", a.requireRole(rbac.SysAdmin)(a.handleAdminSpaces))
}

// handleTransferSpace 发起移交。
func (a *API) handleTransferSpace(w http.ResponseWriter, r *http.Request) {
	c, _ := claimsFrom(r.Context())
	spaceID := r.PathValue("spaceId")
	var req struct {
		ToUserID string `json:"toUserId"`
		Reason   string `json:"reason"`
	}
	if !decode(w, r, &req) {
		return
	}
	if req.ToUserID == "" {
		writeErr(w, r, http.StatusBadRequest, "INVALID_ARGUMENT", "请选择接收人")
		return
	}
	if a.Content == nil || a.IAM == nil {
		writeErr(w, r, http.StatusNotImplemented, "UNAVAILABLE", "内容服务未启用")
		return
	}

	sp, err := a.Content.GetSpaceOwner(r.Context(), c.TenantID, spaceID)
	if err != nil {
		a.transferErr(w, r, err)
		return
	}
	isOwner := sp.OwnerID == c.Subject
	var isSys bool
	if !isOwner {
		isSys, err = a.IAM.IsSysAdmin(r.Context(), c.TenantID, c.Subject)
		if err != nil {
			writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "角色判定失败")
			return
		}
		if !isSys {
			a.emit(r, c.TenantID, AuditEntry{
				ActorID: c.Subject, Action: "space.transfer", ObjectID: spaceID, Result: "denied",
				Detail: map[string]any{"reason": "not_owner_nor_admin", "to": req.ToUserID},
			})
			writeErr(w, r, http.StatusForbidden, "FORBIDDEN", "只有空间所有者或系统管理员可以移交")
			return
		}
	}

	if isOwner {
		if err := a.Content.TransferNow(r.Context(), c.TenantID, spaceID, sp.OwnerID, req.ToUserID, c.Subject); err != nil {
			a.transferErr(w, r, err)
			return
		}
		if err := a.emit(r, c.TenantID, AuditEntry{
			ActorID: c.Subject, Action: "space.transfer", ObjectID: spaceID, Result: "ok",
			Detail: map[string]any{"mode": "owner", "from": sp.OwnerID, "to": req.ToUserID, "space": sp.Name},
		}); err != nil {
			writeErr(w, r, http.StatusInternalServerError, "AUDIT_FAILED", "审计写入失败")
			return
		}
		writeOK(w, r, map[string]any{"done": true, "from": sp.OwnerID, "to": req.ToUserID})
		return
	}

	// 管理员：原所有者不可用时不能转给自己（没人能点确认）
	if req.ToUserID == c.Subject {
		if sp.OwnerStatus != "active" {
			writeErr(w, r, http.StatusConflict, "OWNER_UNAVAILABLE",
				"原所有者账号已停用或已删除，无法取得确认；请转交给第三方，不要转给自己")
			return
		}
		tr, err := a.Content.RequestTransfer(r.Context(), c.TenantID, spaceID, sp.OwnerID, req.ToUserID, c.Subject, req.Reason)
		if err != nil {
			a.transferErr(w, r, err)
			return
		}
		if err := a.emit(r, c.TenantID, AuditEntry{
			ActorID: c.Subject, Action: "space.transfer.request", ObjectID: spaceID, Result: "ok",
			Detail: map[string]any{"mode": "admin_to_self", "from": sp.OwnerID, "to": req.ToUserID,
				"requestId": tr.ID, "expiresAt": tr.ExpiresAt},
		}); err != nil {
			writeErr(w, r, http.StatusInternalServerError, "AUDIT_FAILED", "审计写入失败")
			return
		}
		writeOK(w, r, map[string]any{"pending": true, "request": tr})
		return
	}

	// 管理员转给第三方：无利益冲突，立即生效
	if err := a.Content.TransferNow(r.Context(), c.TenantID, spaceID, sp.OwnerID, req.ToUserID, c.Subject); err != nil {
		a.transferErr(w, r, err)
		return
	}
	if err := a.emit(r, c.TenantID, AuditEntry{
		ActorID: c.Subject, Action: "space.transfer", ObjectID: spaceID, Result: "ok",
		Detail: map[string]any{"mode": "admin", "from": sp.OwnerID, "to": req.ToUserID, "space": sp.Name},
	}); err != nil {
		writeErr(w, r, http.StatusInternalServerError, "AUDIT_FAILED", "审计写入失败")
		return
	}
	writeOK(w, r, map[string]any{"done": true, "from": sp.OwnerID, "to": req.ToUserID})
}

// handlePendingTransfers 返回"等我确认"的请求。只回自己的，不接受查询参数指定他人。
func (a *API) handlePendingTransfers(w http.ResponseWriter, r *http.Request) {
	c, _ := claimsFrom(r.Context())
	items, err := a.Content.PendingForOwner(r.Context(), c.TenantID, c.Subject)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "读取待确认移交失败")
		return
	}
	writeOK(w, r, map[string]any{"items": items, "count": len(items)})
}

// handleDecideTransfer 由原所有者批准或拒绝。
func (a *API) handleDecideTransfer(w http.ResponseWriter, r *http.Request) {
	c, _ := claimsFrom(r.Context())
	id := r.PathValue("id")
	var req struct {
		Approve bool `json:"approve"`
	}
	if !decode(w, r, &req) {
		return
	}
	tr, err := a.Content.DecideTransfer(r.Context(), c.TenantID, id, c.Subject, req.Approve)
	if err != nil {
		a.transferErr(w, r, err)
		return
	}
	action := "space.transfer.reject"
	if req.Approve {
		action = "space.transfer.approve"
	}
	if err := a.emit(r, c.TenantID, AuditEntry{
		ActorID: c.Subject, Action: action, ObjectID: tr.SpaceID, Result: "ok",
		Detail: map[string]any{"requestId": tr.ID, "space": tr.SpaceName,
			"from": tr.FromUserID, "to": tr.ToUserID, "initiator": tr.InitiatedBy},
	}); err != nil {
		writeErr(w, r, http.StatusInternalServerError, "AUDIT_FAILED", "审计写入失败")
		return
	}
	writeOK(w, r, map[string]any{"request": tr})
}

// handleCancelTransfer 撤销待确认请求（发起人或管理员）。
func (a *API) handleCancelTransfer(w http.ResponseWriter, r *http.Request) {
	c, _ := claimsFrom(r.Context())
	id := r.PathValue("id")
	isSys, err := a.IAM.IsSysAdmin(r.Context(), c.TenantID, c.Subject)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "角色判定失败")
		return
	}
	if err := a.Content.CancelTransfer(r.Context(), c.TenantID, id, c.Subject, isSys); err != nil {
		a.transferErr(w, r, err)
		return
	}
	_ = a.emit(r, c.TenantID, AuditEntry{
		ActorID: c.Subject, Action: "space.transfer.cancel", ObjectID: id, Result: "ok",
	})
	writeOK(w, r, map[string]any{"cancelled": true})
}

// handleAdminSpaces 空间台账（sysadmin）。
//
// 刻意不返回任何文件内容，也不提供"进入空间"的接口：
// 管理员在这里能回答"谁有空间、谁的空间快没人管了"，
// 但看不到里面写了什么——管配置，不管内容。
func (a *API) handleAdminSpaces(w http.ResponseWriter, r *http.Request) {
	c, _ := claimsFrom(r.Context())
	items, err := a.Content.ListSpaceOverview(r.Context(), c.TenantID)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "读取空间台账失败")
		return
	}
	onlyOwner := 0
	for _, it := range items {
		if it.OnlyOwner {
			onlyOwner++
		}
	}
	writeOK(w, r, map[string]any{"items": items, "count": len(items), "onlyOwnerCount": onlyOwner})
}

// transferErr 把移交的业务错误映射成稳定状态码。
//
// 每个分支都对应一个"操作者能自己解决"的原因：目标不可用就换人、
// 密级不够就先提密、已有请求就等或撤。统一回 500 只能让人来问客服。
func (a *API) transferErr(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, content.ErrSpaceNotFound):
		writeErr(w, r, http.StatusNotFound, "NOT_FOUND", "空间不存在")
	case errors.Is(err, content.ErrNotSpaceOwner):
		writeErr(w, r, http.StatusForbidden, "FORBIDDEN", "只有空间所有者可以确认移交")
	case errors.Is(err, content.ErrTransferStale):
		writeErr(w, r, http.StatusConflict, "TRANSFER_STALE", "空间所有者已变更，请刷新后重新发起")
	case errors.Is(err, content.ErrSameOwner):
		writeErr(w, r, http.StatusBadRequest, "SAME_OWNER", "接收人已经是该空间的所有者")
	case errors.Is(err, content.ErrTargetUnavailable):
		writeErr(w, r, http.StatusConflict, "TARGET_UNAVAILABLE", "接收人账号不可用（已停用、已删除或已过期）")
	case errors.Is(err, content.ErrTargetClearance):
		writeErr(w, r, http.StatusConflict, "CLEARANCE_TOO_LOW", "接收人的密级低于空间密级，移交后也无法打开")
	case errors.Is(err, content.ErrTargetDenied):
		writeErr(w, r, http.StatusConflict, "TARGET_DENIED", "接收人在该空间上有显式拒绝，请先解除后再移交")
	case errors.Is(err, content.ErrTransferExists):
		writeErr(w, r, http.StatusConflict, "TRANSFER_PENDING", "该空间已有待确认的移交请求")
	case errors.Is(err, content.ErrTransferExpired):
		writeErr(w, r, http.StatusConflict, "TRANSFER_EXPIRED", "移交请求已过期，请重新发起")
	case errors.Is(err, content.ErrTransferNotFound):
		writeErr(w, r, http.StatusNotFound, "NOT_FOUND", "移交请求不存在或已处理")
	default:
		// 未分类错误必须留日志：这里曾经把"参数占位写错"静默成 500，
		// 前端只能看到"移交失败"，排查全靠猜。
		a.logErr("空间移交失败", "err", err)
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "移交失败")
	}
}
