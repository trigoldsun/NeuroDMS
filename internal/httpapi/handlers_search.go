package httpapi

// 搜索（AC-11）。
//
// 两个安全要点：
//   1. 租户隔离靠 RLS（查询本身不带 tenant 条件也不会越界），但**可见性**必须逐条判——
//      文件名会泄露"这个组织里有什么"，比内容更敏感；
//   2. 用户输入的 % 与 _ 必须转义，否则一个 "%%" 就能把全库文件名捞出来筛。

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"docvault/internal/authz"
	"docvault/internal/db"

	"github.com/jackc/pgx/v5"
)

const (
	searchMaxLimit      = 100
	searchMaxCandidates = 300
)

func (a *API) registerSearch(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/search", a.requireAuth(a.handleSearch))
}

// escapeLike 转义 LIKE 通配符。不转义时 "%%" 等价于"全部"，属于信息泄露。
func escapeLike(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, "%", `\%`)
	s = strings.ReplaceAll(s, "_", `\_`)
	return s
}

func (a *API) handleSearch(w http.ResponseWriter, r *http.Request) {
	c, _ := claimsFrom(r.Context())
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	if len([]rune(q)) < 1 {
		writeErr(w, r, http.StatusBadRequest, "INVALID_ARGUMENT", "q 至少 1 个字符")
		return
	}
	if len([]rune(q)) > 128 {
		writeErr(w, r, http.StatusBadRequest, "INVALID_ARGUMENT", "q 过长")
		return
	}
	limit := searchMaxLimit
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= searchMaxLimit {
			limit = n
		}
	}
	spaceID := r.URL.Query().Get("spaceId")

	type hit struct {
		nodeID  string
		spaceID string
		name    string
		kind    string
		ext     string
		size    int64
		updated time.Time
	}

	var candidates []hit
	err := db.WithTenant(r.Context(), a.Pool, c.TenantID, func(tx pgx.Tx) error {
		rows, e := tx.Query(r.Context(), `
			SELECT id::text, space_id::text, name, kind, COALESCE(ext,''), size_bytes, updated_at
			  FROM node
			 WHERE deleted_at IS NULL
			   AND name ILIKE '%' || $1 || '%' ESCAPE '\'
			   AND ($2 = '' OR space_id = nullif($2,'')::uuid)
			 ORDER BY updated_at DESC
			 LIMIT $3`, escapeLike(q), spaceID, searchMaxCandidates)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var h hit
			if e := rows.Scan(&h.nodeID, &h.spaceID, &h.name, &h.kind, &h.ext, &h.size, &h.updated); e != nil {
				return e
			}
			candidates = append(candidates, h)
		}
		return rows.Err()
	})
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "搜索失败")
		return
	}

	// 逐条判可见性：宁可慢也不能把"看不见的文件名"返回出去
	items := make([]map[string]any, 0, limit)
	for _, h := range candidates {
		if len(items) >= limit {
			break
		}
		d, err := a.check(r.Context(), c, h.spaceID, h.nodeID, authz.Display)
		if err != nil || !d.allowed {
			continue
		}
		items = append(items, map[string]any{
			"nodeId": h.nodeID, "spaceId": h.spaceID, "name": h.name,
			"kind": h.kind, "ext": h.ext, "sizeBytes": h.size,
			"updatedAt": h.updated.Format(time.RFC3339),
		})
	}

	writeOK(w, r, map[string]any{
		"items": items, "count": len(items),
		// 明确区分"没有结果"和"结果被截断"，避免用户以为组织里没有这个文件
		"truncated": len(items) >= limit && len(candidates) >= limit,
	})
}
