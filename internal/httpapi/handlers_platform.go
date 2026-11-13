package httpapi

import (
	"net/http"
	"time"

	"docvault/internal/audit"
	"docvault/internal/db"

	"github.com/jackc/pgx/v5"
)

// registerPlatform 注册平台运营端点（跨租户只读）。
//
// 这一组端点不使用用户会话，只认独立的平台令牌：
// 跨租户视野属于"平台方"，不能挂在任何客户租户的账号上——
// 否则客户管理员就能通过给自己加角色获得别的租户的数据。
func (a *API) registerPlatform(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/platform/stats", a.requirePlatform(a.handlePlatformStats))
	mux.HandleFunc("GET /v1/platform/tenants/{slug}/audit/events", a.requirePlatform(a.handlePlatformAudit))
}

// handlePlatformStats 返回跨租户汇总。
//
// 只给数字，不给明细：平台运营的日常需求是"看总量与异常"，
// 而"看某个租户的某个文件"必须回到租户自己的审计视图，走租户上下文。
func (a *API) handlePlatformStats(w http.ResponseWriter, r *http.Request) {
	var (
		tenants, users, spaces, files, usedBytes int64
	)
	// 函数是 SECURITY DEFINER，因此在无租户上下文时也能返回汇总；
	// 它不返回任何业务字段，泄露面仅限"规模"。
	if err := a.Pool.QueryRow(r.Context(), // pool-ok: 平台汇总 SECURITY DEFINER 函数，无租户上下文，只返回规模数字
		`SELECT tenants, users, spaces, files, used_bytes FROM platform_stats()`).
		Scan(&tenants, &users, &spaces, &files, &usedBytes); err != nil {
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "读取平台统计失败")
		return
	}
	writeOK(w, r, map[string]any{
		"tenants": tenants, "users": users, "spaces": spaces,
		"files": files, "usedBytes": usedBytes,
		"generatedAt": time.Now().UTC().Format(time.RFC3339),
	})
}

// handlePlatformAudit 按租户 slug 读取审计事件（跨租户只读）。
//
// 强制留痕：这可能是整个系统里权限最高的一次读取（跨租户看别人做了什么），
// 所以每次访问都会在**目标租户**的审计链里留下 platform.access 事件。
// 被审计方自己就能看到"平台方读过我的审计"——这是可核查性的关键。
func (a *API) handlePlatformAudit(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("slug")

	var tenantID string
	if err := a.Pool.QueryRow(r.Context(), // pool-ok: 平台级租户解析函数，入参是 slug，尚未进入租户上下文
		`SELECT platform_resolve_tenant($1)::text`, slug).Scan(&tenantID); err != nil {
		writeErr(w, r, http.StatusNotFound, "NOT_FOUND", "租户不存在")
		return
	}
	if tenantID == "" {
		writeErr(w, r, http.StatusNotFound, "NOT_FOUND", "租户不存在")
		return
	}

	f := audit.QueryFilter{Action: r.URL.Query().Get("action"), Limit: 100}
	rows, err := audit.Query(r.Context(), a.Pool, tenantID, f)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "读取审计失败")
		return
	}

	// 访问留痕（写在目标租户，actor 标为 system）
	if err := db.WithTenant(r.Context(), a.Pool, tenantID, func(tx pgx.Tx) error {
		return audit.Append(r.Context(), tx, tenantID, audit.Event{
			ActorID: "", ActorType: "system", Action: "platform.access", Result: "ok",
			Detail: map[string]any{"scope": "audit_events", "tenantSlug": slug,
				"count": len(rows), "from": clientIP(r)},
			IP: clientIP(r),
		})
	}); err != nil {
		// 平台访问无法留痕时必须拒绝：否则"看不见的访问"等于没有审计
		writeErr(w, r, http.StatusInternalServerError, "AUDIT_FAILED", "审计写入失败，访问已拒绝")
		return
	}

	items := make([]map[string]any, 0, len(rows))
	for _, x := range rows {
		items = append(items, map[string]any{
			"seq": x.Seq, "actorId": x.ActorID, "actorType": x.ActorType,
			"action": x.Action, "result": x.Result,
			"createdAt": x.CreatedAt.UTC().Format(time.RFC3339),
		})
	}
	writeOK(w, r, map[string]any{"tenant": slug, "items": items, "count": len(items)})
}
