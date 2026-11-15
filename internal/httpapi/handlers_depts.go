package httpapi

// 部门树的管理接口（E2E 验收 F-03）。
//
// 背景：原先部门只有读接口，数据只能由目录同步写入。后果是"不接 AD 的租户
// 永远只有一条「总部」"——而 ACL 支持 `subjectType=dept`，等于把一个卖点
// 锁死在"你必须先有 AD"这个前提上。
//
// 三条设计取舍：
//  1. **不做级联删除**：删部门时若还有子部门/成员/空间，一律拒绝并给出数量。
//     级联会把人的归属悄悄改掉，事后无从追溯；拒绝至少是可见的。
//  2. **目录同步来的部门不允许本地改**：下次同步会把它建回来或者与 AD 名字打架。
//     接口明确回 DEPT_DIRECTORY_MANAGED，让管理员去 AD 里改。
//  3. **改名不动路径**：路径是 ACL 的匹配依据，改名连带重写子树代价太大；
//     路径里的标签本来就是标识符，不是给人看的名字。

import (
	"errors"
	"net/http"

	"docvault/internal/dept"
	"docvault/internal/rbac"
)

func (a *API) registerDepts(mux *http.ServeMux) {
	// 部门是"授权主体"的载体，只给系统管理员：安全管理员按部门授权，
	// 但不该能凭空造出一个部门把权限授过去。
	mux.HandleFunc("GET /v1/admin/depts", a.requireRole(rbac.SysAdmin)(a.handleDeptList))
	mux.HandleFunc("POST /v1/admin/depts", a.requireRole(rbac.SysAdmin)(a.handleDeptCreate))
	mux.HandleFunc("PATCH /v1/admin/depts/{id}", a.requireRole(rbac.SysAdmin)(a.handleDeptRename))
	mux.HandleFunc("POST /v1/admin/depts/{id}/move", a.requireRole(rbac.SysAdmin)(a.handleDeptMove))
	mux.HandleFunc("DELETE /v1/admin/depts/{id}", a.requireRole(rbac.SysAdmin)(a.handleDeptDelete))
}

// handleDeptList 返回扁平的部门列表（按路径排序 = 树的先序）。
//
// 不返回嵌套结构：前端要同时用它渲染树和填充下拉框，
// 扁平列表两种用法都直接可用，嵌套则要再摊平一次。
func (a *API) handleDeptList(w http.ResponseWriter, r *http.Request) {
	c, _ := claimsFrom(r.Context())
	if a.Depts == nil {
		writeErr(w, r, http.StatusServiceUnavailable, "DEPT_UNAVAILABLE", "部门服务未启用")
		return
	}
	items, err := a.Depts.List(r.Context(), c.TenantID)
	if err != nil {
		a.logErr("读取部门失败", "err", err)
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "读取部门失败")
		return
	}
	writeOK(w, r, map[string]any{"items": items, "count": len(items)})
}

func (a *API) handleDeptCreate(w http.ResponseWriter, r *http.Request) {
	c, _ := claimsFrom(r.Context())
	var req struct {
		Name string `json:"name"`
		// ParentID 为空表示挂到顶层部门下（不会新建第二个顶层）
		ParentID string `json:"parentId"`
	}
	if !decode(w, r, &req) {
		return
	}
	if a.Depts == nil {
		writeErr(w, r, http.StatusServiceUnavailable, "DEPT_UNAVAILABLE", "部门服务未启用")
		return
	}
	n, err := a.Depts.Create(r.Context(), c.TenantID, req.Name, req.ParentID)
	if err != nil {
		a.deptErr(w, r, err)
		return
	}
	a.emitLogged(r, c.TenantID, AuditEntry{
		ActorID: c.Subject, Action: "admin.dept.create",
		ObjectType: "dept", ObjectID: n.ID, Result: "ok",
		Detail: map[string]any{
			"name": n.Name, "path": n.Path, "parentId": n.ParentID,
		},
	})
	writeOK(w, r, n)
}

func (a *API) handleDeptRename(w http.ResponseWriter, r *http.Request) {
	c, _ := claimsFrom(r.Context())
	id := r.PathValue("id")
	var req struct {
		Name string `json:"name"`
	}
	if !decode(w, r, &req) {
		return
	}
	if a.Depts == nil {
		writeErr(w, r, http.StatusServiceUnavailable, "DEPT_UNAVAILABLE", "部门服务未启用")
		return
	}
	ch, err := a.Depts.Rename(r.Context(), c.TenantID, id, req.Name)
	if err != nil {
		a.deptErr(w, r, err)
		return
	}
	if ch.Before.Name != ch.After.Name {
		a.emitLogged(r, c.TenantID, AuditEntry{
			ActorID: c.Subject, Action: "admin.dept.rename",
			ObjectType: "dept", ObjectID: id, Result: "ok",
			Detail: map[string]any{
				"before": map[string]any{"name": ch.Before.Name},
				"after":  map[string]any{"name": ch.After.Name},
			},
		})
	}
	writeOK(w, r, ch.After)
}

func (a *API) handleDeptMove(w http.ResponseWriter, r *http.Request) {
	c, _ := claimsFrom(r.Context())
	id := r.PathValue("id")
	var req struct {
		// ParentID 为目标上级；空串表示挂到顶层部门下
		ParentID string `json:"parentId"`
	}
	if !decode(w, r, &req) {
		return
	}
	if a.Depts == nil {
		writeErr(w, r, http.StatusServiceUnavailable, "DEPT_UNAVAILABLE", "部门服务未启用")
		return
	}
	ch, err := a.Depts.Move(r.Context(), c.TenantID, id, req.ParentID)
	if err != nil {
		a.deptErr(w, r, err)
		return
	}
	a.emitLogged(r, c.TenantID, AuditEntry{
		ActorID: c.Subject, Action: "admin.dept.move",
		ObjectType: "dept", ObjectID: id, Result: "ok",
		Detail: map[string]any{
			"before":  map[string]any{"path": ch.Before.Path, "parentId": ch.Before.ParentID},
			"after":   map[string]any{"path": ch.After.Path, "parentId": ch.After.ParentID},
			"movedTo": ch.MovedTo,
		},
	})
	writeOK(w, r, ch.After)
}

func (a *API) handleDeptDelete(w http.ResponseWriter, r *http.Request) {
	c, _ := claimsFrom(r.Context())
	id := r.PathValue("id")
	if a.Depts == nil {
		writeErr(w, r, http.StatusServiceUnavailable, "DEPT_UNAVAILABLE", "部门服务未启用")
		return
	}
	before, err := a.Depts.Delete(r.Context(), c.TenantID, id)
	if err != nil {
		a.deptErr(w, r, err)
		return
	}
	a.emitLogged(r, c.TenantID, AuditEntry{
		ActorID: c.Subject, Action: "admin.dept.delete",
		ObjectType: "dept", ObjectID: id, Result: "ok",
		Detail: map[string]any{"name": before.Name, "path": before.Path},
	})
	writeOK(w, r, map[string]any{"id": id, "deleted": true})
}

// deptErr 把部门层的业务错误映射成稳定错误码。
//
// 占用类错误（子部门/成员/空间）一律 409 + 具体数量：前端要能提示
// "先把这 3 个人挪走"，而不是只给一句"不能删除"。
func (a *API) deptErr(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, dept.ErrNotFound):
		writeErr(w, r, http.StatusNotFound, "NOT_FOUND", err.Error())
	case errors.Is(err, dept.ErrNoParent):
		writeErr(w, r, http.StatusBadRequest, "PARENT_NOT_FOUND", err.Error())
	case errors.Is(err, dept.ErrInvalidInput):
		writeErr(w, r, http.StatusBadRequest, "INVALID_ARGUMENT", err.Error())
	case errors.Is(err, dept.ErrNameTaken):
		writeErr(w, r, http.StatusConflict, "DEPT_NAME_TAKEN", err.Error())
	case errors.Is(err, dept.ErrDirectoryManaged):
		writeErr(w, r, http.StatusConflict, "DEPT_DIRECTORY_MANAGED",
			"该部门由目录同步维护，请到 AD / LDAP 里改；本地改动会在下次同步时被覆盖")
	case errors.Is(err, dept.ErrHasChildren), errors.Is(err, dept.ErrHasMembers),
		errors.Is(err, dept.ErrHasSpaces):
		writeErr(w, r, http.StatusConflict, "DEPT_NOT_EMPTY", err.Error())
	case errors.Is(err, dept.ErrCannotDeleteRoot):
		writeErr(w, r, http.StatusConflict, "DEPT_IS_ROOT",
			"根部门是\"成员未选部门\"时的归属，不能删除")
	case errors.Is(err, dept.ErrCycle):
		writeErr(w, r, http.StatusConflict, "DEPT_CYCLE", err.Error())
	case errors.Is(err, dept.ErrTooDeep):
		writeErr(w, r, http.StatusBadRequest, "DEPT_TOO_DEEP", err.Error())
	case errors.Is(err, dept.ErrAmbiguousRootPick):
		writeErr(w, r, http.StatusBadRequest, "DEPT_PARENT_REQUIRED",
			"该组织有多个顶层部门，请指定上级")
	default:
		a.logErr("部门操作失败", "err", err)
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "部门操作失败")
	}
}
