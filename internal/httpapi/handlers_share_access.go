package httpapi

// 外发访问记录：分享人视角。
//
// 之前只有"管理员能在审计里翻到"，分享人自己完全不知道链接发出去之后发生了什么——
// 这是外发功能最主要的信息不对称：发的人担心，却没有任何可见性。
// 这一组接口补上三件事：
//   1. 我的分享列表（含浏览/下载/打印次数、最近访问时间）；
//   2. 单条分享的访问明细（IP、可见范围、归属地、浏览器/系统、动作）；
//   3. 异常提示（短期内多个不同 IP 访问同一条链接）。

import (
	"net/http"
	"time"

	"docvault/internal/authz"
	"docvault/internal/db"
	"docvault/internal/netinfo"
	"docvault/internal/share"

	"github.com/jackc/pgx/v5"
)

// 打印上报的节流窗口：同一张票据 5 秒内只记一次。
//
// 打印是前端打点，不节流的话一个脚本能把 share_visit 灌满。
// 用内存而不是库：这是限流，不是业务状态，进程重启丢几次不影响正确性。
const printThrottle = 5 * time.Second

func (a *API) registerShareAccess(mux *http.ServeMux) {
	mux.HandleFunc("POST /v1/public/tickets/{ticket}/print", a.handleTicketPrint)
	mux.HandleFunc("GET /v1/shares/mine", a.requireAuth(a.handleMyShares))
	mux.HandleFunc("GET /v1/shares/{id}/visits", a.requireAuth(a.handleShareVisits))
}

// handleTicketPrint 记录一次"访客点了打印"。
//
// 它**不是**可信事实：前端可以伪造这次调用，甚至可以不调。
// 所以审计里记的是 share.print（声称打印），而不是"已打印"。
// 真正需要"确证打印"的场景，只能靠企业打印服务或终端代理，不在网页能力范围内。
func (a *API) handleTicketPrint(w http.ResponseWriter, r *http.Request) {
	raw := r.PathValue("ticket")
	t, err := share.ResolveTicket(r.Context(), a.Pool, raw, clientIP(r))
	if err != nil {
		writeErr(w, r, http.StatusGone, "TICKET_INVALID", "访问票据无效或已过期")
		return
	}
	if !t.AllowPrint {
		// 策略不允许打印却收到上报：要么是绕过界面，要么是配置刚改。
		// 两种情况都值得留痕（denied），但不影响用户已完成的行为。
		_ = a.emit(r, t.TenantID, AuditEntry{
			ActorType: "anonymous", Action: "share.print", ObjectID: t.ObjectID, Result: "denied",
			Detail: map[string]any{"shareId": t.ShareID, "reason": "policy"},
		})
		writeErr(w, r, http.StatusForbidden, "PRINT_FORBIDDEN", "该分享不允许打印")
		return
	}

	// 节流：同一张票据短时间内只记一次
	if !a.allowPrintEvent(raw) {
		writeOK(w, r, map[string]any{"recorded": false})
		return
	}

	if err := share.RecordEvent(r.Context(), a.Pool, t.TenantID, t.ShareID, "print",
		clientIP(r), r.UserAgent()); err != nil {
		// 记录失败不该让前端弹错：打印已经发生了
		a.logErr("记录打印事件失败", "shareId", t.ShareID, "err", err)
	}
	_ = a.emit(r, t.TenantID, AuditEntry{
		ActorType: "anonymous", Action: "share.print", ObjectID: t.ObjectID, Result: "ok",
		Detail: map[string]any{"shareId": t.ShareID},
	})
	writeOK(w, r, map[string]any{"recorded": true})
}

func (a *API) allowPrintEvent(ticket string) bool {
	now := time.Now()
	if v, ok := a.printSeen.Load(ticket); ok {
		if at, ok := v.(time.Time); ok && now.Sub(at) < printThrottle {
			return false
		}
	}
	a.printSeen.Store(ticket, now)
	return true
}

// handleMyShares 列出"我创建的分享"及其访问概况。
//
// 只按 creator_id 过滤，不按 manage_acl 展开：这一页回答的是
// "我发出去的链接怎么样了"，不是"这个文件的所有分享"。
func (a *API) handleMyShares(w http.ResponseWriter, r *http.Request) {
	c, _ := claimsFrom(r.Context())

	type row struct {
		ID             string     `json:"id"`
		ObjectType     string     `json:"objectType"`
		ObjectID       string     `json:"objectId"`
		Name           string     `json:"name"`
		CreatedAt      time.Time  `json:"createdAt"`
		ExpiresAt      *time.Time `json:"expiresAt"`
		RevokedAt      *time.Time `json:"revokedAt"`
		MaxUses        *int       `json:"maxUses"`
		UsedCount      int        `json:"usedCount"`
		ApprovalStatus string     `json:"approvalStatus"`
		AllowDownload  bool       `json:"allowDownload"`
		AllowSave      bool       `json:"allowSave"`
		AllowPrint     bool       `json:"allowPrint"`
		Views          int        `json:"views"`
		Downloads      int        `json:"downloads"`
		Prints         int        `json:"prints"`
		DistinctIPs    int        `json:"distinctIps"`
		LastSeenAt     *time.Time `json:"lastSeenAt"`
	}

	items := []row{}
	err := db.WithTenant(r.Context(), a.Pool, c.TenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(r.Context(), `
			SELECT s.id::text, s.object_type, s.object_id::text,
			       COALESCE(n.name, sp.name, '（对象已删除）'),
			       s.created_at, s.expires_at, s.revoked_at, s.max_uses, s.used_count,
			       s.approval_status, s.allow_download, s.allow_save, s.allow_print,
			       COALESCE(v.views, 0), COALESCE(v.downloads, 0), COALESCE(v.prints, 0),
			       COALESCE(v.ips, 0), v.last_seen
			  FROM share s
			  LEFT JOIN node n  ON s.object_type = 'node'  AND n.id = s.object_id
			  LEFT JOIN space sp ON s.object_type = 'space' AND sp.id = s.object_id
			  LEFT JOIN LATERAL (
			      SELECT COUNT(*) FILTER (WHERE action = 'preview')  AS views,
			             COUNT(*) FILTER (WHERE action = 'download') AS downloads,
			             COUNT(*) FILTER (WHERE action = 'print')    AS prints,
			             COUNT(DISTINCT ip)                          AS ips,
			             MAX(created_at)                             AS last_seen
			        FROM share_visit sv WHERE sv.share_id = s.id
			  ) v ON true
			 WHERE s.creator_id = $1 AND s.kind = 'link'
			 ORDER BY s.created_at DESC
			 LIMIT 100`, c.Subject)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var it row
			if err := rows.Scan(&it.ID, &it.ObjectType, &it.ObjectID, &it.Name,
				&it.CreatedAt, &it.ExpiresAt, &it.RevokedAt, &it.MaxUses, &it.UsedCount,
				&it.ApprovalStatus, &it.AllowDownload, &it.AllowSave, &it.AllowPrint,
				&it.Views, &it.Downloads, &it.Prints, &it.DistinctIPs, &it.LastSeenAt); err != nil {
				return err
			}
			items = append(items, it)
		}
		return rows.Err()
	})
	if err != nil {
		a.logErr("读取我的分享失败", "err", err)
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "读取分享记录失败")
		return
	}
	writeOK(w, r, map[string]any{"items": items, "count": len(items)})
}

// handleShareVisits 返回某条分享的访问明细。
//
// 权限：创建者本人，或对该对象有 manage_acl 的人。
// 与"撤销分享"的判定保持一致——能看到明细的人，本来就能处置这条链接。
func (a *API) handleShareVisits(w http.ResponseWriter, r *http.Request) {
	c, _ := claimsFrom(r.Context())
	shareID := r.PathValue("id")

	var (
		objectType, objectID, creatorID string
		createdAt                       time.Time
		expiresAt, revokedAt            *time.Time
	)
	err := db.WithTenant(r.Context(), a.Pool, c.TenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(r.Context(), `
			SELECT object_type, object_id::text, creator_id::text, created_at, expires_at, revoked_at
			  FROM share WHERE id = $1`, shareID).
			Scan(&objectType, &objectID, &creatorID, &createdAt, &expiresAt, &revokedAt)
	})
	if err != nil {
		if err == pgx.ErrNoRows {
			writeErr(w, r, http.StatusNotFound, "NOT_FOUND", "分享不存在")
			return
		}
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "读取分享失败")
		return
	}
	if creatorID != c.Subject {
		spaceID, nodeID, terr := a.aclTarget(r.Context(), c, objectType, objectID)
		if terr != nil {
			writeErr(w, r, http.StatusNotFound, "NOT_FOUND", "对象不存在")
			return
		}
		d, derr := a.check(r.Context(), c, spaceID, nodeID, authz.ManageACL)
		if derr != nil {
			writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "权限判定失败")
			return
		}
		if !d.allowed {
			writeErr(w, r, http.StatusForbidden, "FORBIDDEN", "只有分享人或该对象的管理者可以查看访问记录")
			return
		}
	}

	type visit struct {
		Action  string    `json:"action"`
		Result  string    `json:"result"`
		IP      string    `json:"ip"`
		Scope   string    `json:"scope"`
		Geo     string    `json:"geo,omitempty"`
		Browser string    `json:"browser"`
		OS      string    `json:"os"`
		At      time.Time `json:"at"`
	}
	items := []visit{}
	var (
		views, downloads, prints, opens int
		ips                             = map[string]bool{}
		lastSeen                        *time.Time
	)
	err = db.WithTenant(r.Context(), a.Pool, c.TenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(r.Context(), `
			SELECT action, result, COALESCE(host(ip), ''), COALESCE(user_agent, ''), created_at
			  FROM share_visit WHERE share_id = $1
			 ORDER BY created_at DESC LIMIT 200`, shareID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var (
				action, result, ip, ua string
				at                     time.Time
			)
			if err := rows.Scan(&action, &result, &ip, &ua, &at); err != nil {
				return err
			}
			if lastSeen == nil {
				t := at
				lastSeen = &t
			}
			switch action {
			case "preview":
				views++
			case "download":
				downloads++
			case "print":
				prints++
			case "redeem", "open":
				opens++
			}
			if ip != "" {
				ips[ip] = true
			}
			uaInfo := netinfo.DescribeUA(ua)
			items = append(items, visit{
				Action: action, Result: result, IP: ip,
				Scope: netinfo.Scope(ip), Geo: a.Geo.Describe(ip),
				Browser: uaInfo.Browser, OS: uaInfo.OS, At: at,
			})
		}
		return rows.Err()
	})
	if err != nil {
		a.logErr("读取访问记录失败", "shareId", shareID, "err", err)
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "读取访问记录失败")
		return
	}

	// 异常判定：3 个及以上不同 IP 访问同一条链接，提示"可能被转发"。
	// 阈值偏低是刻意的——外发场景里"多人用同一链接"通常就是转发，
	// 而误报的代价只是分享人点开看一眼。
	suspicious := len(ips) >= 3
	writeOK(w, r, map[string]any{
		"shareId": shareID, "objectType": objectType, "objectId": objectID,
		"createdAt": createdAt, "expiresAt": expiresAt, "revokedAt": revokedAt,
		"summary": map[string]any{
			"opens": opens, "views": views, "downloads": downloads, "prints": prints,
			"distinctIps": len(ips), "lastSeenAt": lastSeen,
		},
		"suspicious": suspicious,
		"items":      items,
	})
}
