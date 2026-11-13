package httpapi

import (
	"errors"
	"net/http"

	"docvault/internal/platformauth"
)

// registerPlatformUsers 注册平台账号管理端点。
//
// 与租户侧"成员管理"是两套东西：平台账号不属于任何租户，也不能从租户侧创建。
// 这里放开给平台运营自己管理，是为了避免"停用一个平台账号要登数据库"——
// 那种操作没有审计、没有护栏，是运维事故的常见来源。
func (a *API) registerPlatformUsers(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/platform/users", a.requirePlatform(a.handlePlatformUserList))
	mux.HandleFunc("POST /v1/platform/users", a.requirePlatformWrite(a.handlePlatformUserCreate))
	mux.HandleFunc("POST /v1/platform/users/{id}/status", a.requirePlatformWrite(a.handlePlatformUserStatus))
	mux.HandleFunc("POST /v1/platform/users/{id}/password", a.requirePlatformWrite(a.handlePlatformUserPassword))
}

func (a *API) platformUserErr(w http.ResponseWriter, r *http.Request, action, target string, err error) {
	code, status, msg := "INTERNAL", http.StatusInternalServerError, "操作失败"
	switch {
	case errors.Is(err, platformauth.ErrUserExists):
		code, status, msg = "USER_EXISTS", http.StatusConflict, "该邮箱已被占用"
	case errors.Is(err, platformauth.ErrInvalidRole):
		code, status, msg = "INVALID_ARGUMENT", http.StatusBadRequest, "角色仅支持 ops / readonly"
	case errors.Is(err, platformauth.ErrInvalidInput):
		code, status, msg = "INVALID_ARGUMENT", http.StatusBadRequest, err.Error()
	case errors.Is(err, platformauth.ErrSelfTarget):
		code, status, msg = "SELF_OPERATION", http.StatusBadRequest, err.Error()
	case errors.Is(err, platformauth.ErrLastOps):
		code, status, msg = "LAST_OPS", http.StatusConflict, err.Error()
	case errors.Is(err, platformauth.ErrSessionInvalid):
		code, status, msg = "NOT_FOUND", http.StatusNotFound, "平台账号不存在"
	}
	p, _ := platformFrom(r.Context())
	if status >= 400 {
		a.auditPlatform(r, p, action, target, "denied",
			map[string]any{"code": code, "err": err.Error()})
	}
	writeErr(w, r, status, code, msg)
}

func (a *API) handlePlatformUserList(w http.ResponseWriter, r *http.Request) {
	items, err := a.PlatformAuth.ListUsers(r.Context())
	if err != nil {
		a.logErr("读取平台账号失败", "err", err)
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "读取平台账号失败")
		return
	}
	writeOK(w, r, map[string]any{"items": items, "count": len(items)})
}

func (a *API) handlePlatformUserCreate(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email       string `json:"email"`
		DisplayName string `json:"displayName"`
		Role        string `json:"role"`
		Password    string `json:"password"`
	}
	if !decode(w, r, &req) {
		return
	}
	u, err := a.PlatformAuth.CreateUser(r.Context(), req.Email, req.DisplayName, req.Role, req.Password)
	if err != nil {
		a.platformUserErr(w, r, "platform.user.create", req.Email, err)
		return
	}
	p, _ := platformFrom(r.Context())
	// 审计里只记角色与邮箱，绝不记口令
	a.auditPlatform(r, p, "platform.user.create", u.Email, "ok",
		map[string]any{"role": u.Role})
	writeOK(w, r, u)
}

func (a *API) handlePlatformUserStatus(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !isUUID(id) {
		writeErr(w, r, http.StatusNotFound, "NOT_FOUND", "平台账号不存在")
		return
	}
	var req struct {
		Status string `json:"status"`
	}
	if !decode(w, r, &req) {
		return
	}
	p, _ := platformFrom(r.Context())
	if err := a.PlatformAuth.SetUserStatus(r.Context(), p.UserID, id, req.Status); err != nil {
		a.platformUserErr(w, r, "platform.user.status", id, err)
		return
	}
	a.auditPlatform(r, p, "platform.user.status", id, "ok",
		map[string]any{"status": req.Status, "sessionsRevoked": req.Status != "active"})
	writeOK(w, r, map[string]any{"userId": id, "status": req.Status})
}

func (a *API) handlePlatformUserPassword(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !isUUID(id) {
		writeErr(w, r, http.StatusNotFound, "NOT_FOUND", "平台账号不存在")
		return
	}
	var req struct {
		Password string `json:"password"`
	}
	if !decode(w, r, &req) {
		return
	}
	if err := a.PlatformAuth.ResetUserPassword(r.Context(), id, req.Password); err != nil {
		a.platformUserErr(w, r, "platform.user.password", id, err)
		return
	}
	p, _ := platformFrom(r.Context())
	a.auditPlatform(r, p, "platform.user.password", id, "ok",
		map[string]any{"sessionsRevoked": true})
	writeOK(w, r, map[string]any{"userId": id, "reset": true})
}
