package httpapi

// 面向人的两类日志：我的活动（用户）+ 操作日志（管理）。
//
// 与 /v1/admin/audit/events 的区别是**定位**，不是数据源：
//   - audit/events 是取证入口，只给 auditor，返回原始 detail 与哈希链序号；
//   - 这里返回脱敏后的读模型，按角色收敛，按分类筛选，可导出。

import (
	"context"
	"net/http"
	"strconv"
	"time"

	"docvault/internal/audit"
	"docvault/internal/db"
	"docvault/internal/rbac"

	"github.com/jackc/pgx/v5"
)

func (a *API) registerActivity(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/me/activity", a.requireAuth(a.handleMyActivity))
	mux.HandleFunc("GET /v1/me/activity/export.csv", a.requireAuth(a.handleMyActivityExport))
	// 管理日志不走 requireRole：secadmin 只能看安全相关子集，
	// 需要"按角色裁剪查询条件"而不是"有/无权限"二选一。
	mux.HandleFunc("GET /v1/admin/activity", a.requireAuth(a.handleAdminActivity))
	mux.HandleFunc("GET /v1/admin/activity/export.csv", a.requireAuth(a.handleAdminActivityExport))
}

// parseActivityQuery 解析公共过滤参数。
//
// 解析失败一律忽略而不是报错：日志页的筛选器是"边点边查"的，
// 一个手改坏的 URL 参数不该把整页变成错误提示。
func parseActivityQuery(r *http.Request) audit.ActivityQuery {
	q := r.URL.Query()
	out := audit.ActivityQuery{
		ActorID: q.Get("actorId"),
		Action:  q.Get("action"),
		Result:  q.Get("result"),
	}
	if n, err := strconv.Atoi(q.Get("page")); err == nil {
		out.Page = n
	}
	if n, err := strconv.Atoi(q.Get("size")); err == nil {
		out.Size = n
	}
	if v := q.Get("from"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			out.From = &t
		}
	}
	if v := q.Get("to"); v != "" {
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			out.To = &t
		}
	}
	return out
}

// objectNames 批量解析日志里引用的对象名称（文件/目录/空间）。
//
// 为什么允许解析"已删除"的对象：日志是读模型，读者要回答的是"当时我对什么做了什么"。
// 对象删了以后只剩一串 uuid，日志就失去了可读性；这里只回名称，不回内容。
// 查不到时前端退回显示 id 前 8 位，不编造占位名称。
func (a *API) objectNames(ctx context.Context, tenantID string, rows []audit.EventRow) map[string]string {
	seen := map[string]bool{}
	var ids []string
	for _, r := range rows {
		if r.ObjectID != "" && !seen[r.ObjectID] {
			seen[r.ObjectID] = true
			ids = append(ids, r.ObjectID)
		}
	}
	out := map[string]string{}
	if len(ids) == 0 {
		return out
	}
	_ = db.WithTenant(ctx, a.Pool, tenantID, func(tx pgx.Tx) error {
		rs, err := tx.Query(ctx, `
			SELECT id::text, name FROM node WHERE id = ANY($1::uuid[])
			UNION ALL
			SELECT id::text, name FROM space WHERE id = ANY($1::uuid[])`, ids)
		if err != nil {
			return err
		}
		defer rs.Close()
		for rs.Next() {
			var id, name string
			if e := rs.Scan(&id, &name); e != nil {
				return e
			}
			out[id] = name
		}
		return rs.Err()
	})
	return out
}

// activityJSON 把行转成响应项（含脱敏后的 detail）。
func (a *API) activityJSON(ctx context.Context, tenantID string, rows []audit.EventRow) []map[string]any {
	names := a.actorNames(ctx, tenantID, rows)
	objs := a.objectNames(ctx, tenantID, rows)
	items := make([]map[string]any, 0, len(rows))
	for _, x := range rows {
		item := map[string]any{
			"seq": x.Seq, "actorId": x.ActorID, "actorType": x.ActorType,
			"actorName": displayActor(names[x.ActorID], x.ActorID),
			"action":    x.Action, "objectId": x.ObjectID, "objectName": objs[x.ObjectID], "result": x.Result,
			"ip": x.IP, "requestId": x.RequestID,
			"createdAt": x.CreatedAt.UTC().Format(time.RFC3339),
		}
		if d, ok := audit.RedactDetail(x.Detail); ok {
			item["detail"] = d
		}
		items = append(items, item)
	}
	return items
}

// actorNames 批量取显示名。
//
// 日志里只有 UUID 时，人得先去成员页对照着看——那等于没有可读性。
// 一次 IN 查询解决，不做 N+1。
func (a *API) actorNames(ctx context.Context, tenantID string, rows []audit.EventRow) map[string]string {
	seen := map[string]bool{}
	var ids []string
	for _, r := range rows {
		if r.ActorID != "" && !seen[r.ActorID] {
			seen[r.ActorID] = true
			ids = append(ids, r.ActorID)
		}
	}
	out := map[string]string{}
	if len(ids) == 0 {
		return out
	}
	_ = db.WithTenant(ctx, a.Pool, tenantID, func(tx pgx.Tx) error {
		rs, err := tx.Query(ctx, `
			SELECT id::text, COALESCE(NULLIF(display_name,''), username)
			  FROM app_user WHERE id = ANY($1::uuid[])`, ids)
		if err != nil {
			return err
		}
		defer rs.Close()
		for rs.Next() {
			var id, name string
			if e := rs.Scan(&id, &name); e != nil {
				return e
			}
			out[id] = name
		}
		return rs.Err()
	})
	return out
}

// scopedPatterns 把界面选的动作分组与调用者可用范围求交。
//
// 返回 nil 表示"分组内没有任何可见动作"——调用方必须返回空结果，
// 绝不能退化成"不加过滤"：那会把整张审计表暴露出去。
func (a *API) scopedPatterns(r *http.Request, base []string) []string {
	group := audit.GroupPatterns(r.URL.Query().Get("group"))
	if len(group) == 0 {
		return base
	}
	out := audit.IntersectPatterns(base, group)
	if len(out) == 0 {
		return nil
	}
	return out
}

// displayActor 给出可读的操作人。
//
// 三种情况必须区分清楚：
//   - 有关联账号      → 显示名
//   - 账号已被删除    → 短 id + 标记（日志要能对上工单，不能只显示"未知"）
//   - 没有操作人      → "系统"（定时任务、回调等由系统发起）
func displayActor(name, id string) string {
	if name != "" {
		return name
	}
	if id == "" {
		return "系统"
	}
	if len(id) > 8 {
		return id[:8] + "…（已删除）"
	}
	return id + "（已删除）"
}

// handleMyActivity 我的活动：只允许查自己。
//
// 请求里带的 actorId 一律忽略——否则任何一个员工都能翻阅同事的下载记录。
func (a *API) handleMyActivity(w http.ResponseWriter, r *http.Request) {
	c, _ := claimsFrom(r.Context())
	q := parseActivityQuery(r)
	q.ActorID = c.Subject

	patterns := a.scopedPatterns(r, audit.CategoryPatterns(audit.CategoryUser))
	if patterns == nil {
		// 分组与可用范围没有交集：返回空页而不是"无过滤"
		writeOK(w, r, map[string]any{"items": []any{}, "total": 0, "page": 1, "size": 20})
		return
	}
	page, err := audit.QueryActivity(r.Context(), a.Pool, c.TenantID, q, patterns)
	if err != nil {
		a.logErr("查询我的活动失败", "err", err)
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "查询失败")
		return
	}
	writeOK(w, r, map[string]any{
		"items": a.activityJSON(r.Context(), c.TenantID, page.Items),
		"total": page.Total, "page": page.Page, "size": page.Size,
	})
}

// handleMyActivityExport 导出我的活动。
func (a *API) handleMyActivityExport(w http.ResponseWriter, r *http.Request) {
	c, _ := claimsFrom(r.Context())
	q := parseActivityQuery(r)
	q.ActorID = c.Subject
	patterns := a.scopedPatterns(r, audit.CategoryPatterns(audit.CategoryUser))
	if patterns == nil {
		writeErr(w, r, http.StatusBadRequest, "EMPTY_SCOPE", "该分类下没有可导出的记录")
		return
	}
	a.writeActivityCSV(w, r, c.TenantID, q, patterns, "my-activity")
}

// adminScope 计算管理日志的可见范围并处理拒绝。
//
// 返回 ok=false 时已经写过响应，调用方直接 return。
func (a *API) adminScope(w http.ResponseWriter, r *http.Request) (tenantID string, patterns []string, ok bool) {
	// 必须由 requireAuth 包裹：没有身份就没有租户上下文，
	// 既查不到角色，也查不到任何日志（早先漏了这层，接口直接 500）。
	c, _ := claimsFrom(r.Context())
	if c.Subject == "" {
		writeErr(w, r, http.StatusUnauthorized, "UNAUTHENTICATED", "缺少访问令牌")
		return "", nil, false
	}
	var held []string
	err := db.WithTenant(r.Context(), a.Pool, c.TenantID, func(tx pgx.Tx) error {
		rs, e := rbac.RolesOf(r.Context(), tx, c.TenantID, c.Subject)
		held = rs
		return e
	})
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "读取角色失败")
		return "", nil, false
	}

	violation := rbac.SeparationViolation(held)
	patterns = audit.ManagementPatternsFor(held, violation)
	if patterns == nil {
		reason := "missing_role"
		if violation != "" {
			reason = "separation_violation"
		}
		// 与 requireRole 同口径留痕：越权尝试本身也是要能查到的
		_ = a.emit(r, c.TenantID, AuditEntry{
			ActorID: c.Subject, Action: "admin.denied", Result: "denied",
			Detail: map[string]any{"reason": reason, "held": held, "path": r.URL.Path},
		})
		writeErr(w, r, http.StatusForbidden, "FORBIDDEN", "需要管理角色")
		return "", nil, false
	}
	return c.TenantID, patterns, true
}

// handleAdminActivity 管理操作日志。
func (a *API) handleAdminActivity(w http.ResponseWriter, r *http.Request) {
	tenantID, patterns, ok := a.adminScope(w, r)
	if !ok {
		return
	}
	q := parseActivityQuery(r)
	patterns = a.scopedPatterns(r, patterns)
	if patterns == nil {
		writeOK(w, r, map[string]any{"items": []any{}, "total": 0, "page": 1, "size": 20})
		return
	}
	page, err := audit.QueryActivity(r.Context(), a.Pool, tenantID, q, patterns)
	if err != nil {
		a.logErr("查询管理日志失败", "err", err)
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "查询失败")
		return
	}
	writeOK(w, r, map[string]any{
		"items": a.activityJSON(r.Context(), tenantID, page.Items),
		"total": page.Total, "page": page.Page, "size": page.Size,
	})
}

// handleAdminActivityExport 导出管理日志。
func (a *API) handleAdminActivityExport(w http.ResponseWriter, r *http.Request) {
	tenantID, patterns, ok := a.adminScope(w, r)
	if !ok {
		return
	}
	q := parseActivityQuery(r)
	patterns = a.scopedPatterns(r, patterns)
	if patterns == nil {
		writeErr(w, r, http.StatusBadRequest, "EMPTY_SCOPE", "该分类下没有可导出的记录")
		return
	}
	a.writeActivityCSV(w, r, tenantID, q, patterns, "admin-activity")
}

// writeActivityCSV 分页收集后一次性写出。
//
// Query 单次上限 500，所以这里按 500 一页拉到 MaxExportRows。
// 到上限时在响应头里说明被截断，避免用户以为导出了全量。
func (a *API) writeActivityCSV(w http.ResponseWriter, r *http.Request, tenantID string, q audit.ActivityQuery, patterns []string, prefix string) {
	var all []audit.EventRow
	const pageSize = 500
	for page := 1; len(all) < audit.MaxExportRows; page++ {
		q.Page, q.Size = page, pageSize
		p, err := audit.QueryActivity(r.Context(), a.Pool, tenantID, q, patterns)
		if err != nil {
			a.logErr("导出日志失败", "err", err)
			writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "导出失败")
			return
		}
		all = append(all, p.Items...)
		if int64(page*pageSize) >= p.Total || len(p.Items) == 0 {
			break
		}
	}
	truncated := len(all) > audit.MaxExportRows
	if truncated {
		all = all[:audit.MaxExportRows]
	}

	names := a.actorNames(r.Context(), tenantID, all)
	for i := range all {
		all[i].ActorName = names[all[i].ActorID]
	}
	body := audit.WriteCSV(all)
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if truncated {
		w.Header().Set("X-Export-Truncated", "true")
	}
	w.Header().Set("Content-Disposition",
		`attachment; filename="`+prefix+"-"+time.Now().UTC().Format("20060102-1504")+`.csv"`)
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}
