package httpapi

// 平台侧档位管理（docs/17 §2）。
//
// 这是 SaaS 形态下"交付分档"的唯一入口：合同签订 → 运营在这里改一行 →
// 租户下次请求即按新档位判定。没有激活码，也不需要客户做任何动作。

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"docvault/internal/platform/httpmw"
	"docvault/internal/tenant"
)

func (a *API) handlePlatformEditionGet(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("slug")
	info, err := a.Tenants.GetEdition(r.Context(), slug)
	if err != nil {
		switch {
		case errors.Is(err, tenant.ErrNotFound):
			writeErr(w, r, http.StatusNotFound, "NOT_FOUND", "租户不存在")
		default:
			a.logErr("读取档位失败", "slug", slug, "err", err)
			writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "读取档位失败")
		}
		return
	}
	writeOK(w, r, info)
}

func (a *API) handlePlatformEditionPut(w http.ResponseWriter, r *http.Request) {
	slug := r.PathValue("slug")
	var req struct {
		Edition string `json:"edition"`
		// ExpiresAt 为空表示不限期。传 RFC3339。
		ExpiresAt string `json:"expiresAt"`
		Reason    string `json:"reason"`
	}
	if !decode(w, r, &req) {
		return
	}

	var expires *time.Time
	if s := strings.TrimSpace(req.ExpiresAt); s != "" {
		t, err := time.Parse(time.RFC3339, s)
		if err != nil {
			writeErr(w, r, http.StatusBadRequest, "INVALID_ARGUMENT",
				"expiresAt 需为 RFC3339 时间（如 2027-11-01T00:00:00Z），留空表示不限期")
			return
		}
		expires = &t
	}

	p, _ := platformFrom(r.Context())
	operator := p.UserID
	if p.Static {
		operator = "static-token"
	}

	chg, err := a.Tenants.SetEdition(r.Context(), slug, req.Edition, expires, req.Reason, operator)
	if err != nil {
		switch {
		case errors.Is(err, tenant.ErrNotFound):
			writeErr(w, r, http.StatusNotFound, "NOT_FOUND", "租户不存在")
		case errors.Is(err, tenant.ErrInvalidEdition):
			writeErr(w, r, http.StatusBadRequest, "INVALID_ARGUMENT",
				"档位仅支持 basic / professional / business")
		case errors.Is(err, tenant.ErrEditionDowngradeBlocked):
			// 把清单带回去：只说"不能降档"运营还得自己一个个翻。
			writeJSON(w, r, http.StatusConflict, map[string]any{
				"code": "EDITION_DOWNGRADE_BLOCKED",
				"message": fmt.Sprintf(
					"存在 %d 个目标档位无法表达的密级对象，请先降密或先导出，再降档",
					chg.BlockedCount),
				"requestId": httpmw.RequestIDFrom(r.Context()),
				"data": map[string]any{
					"blockedCount": chg.BlockedCount,
					"samples":      chg.BlockedSamples,
					"fromEdition":  chg.PrevEdition,
					"toEdition":    strings.ToLower(strings.TrimSpace(req.Edition)),
				},
			})
		default:
			a.logErr("变更档位失败", "slug", slug, "err", err)
			writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "变更档位失败")
		}
		return
	}

	a.auditPlatform(r, p, "platform.tenant.edition", slug, "ok", map[string]any{
		"prev":        chg.PrevEdition,
		"cur":         chg.CurEdition,
		"prevExpires": chg.PrevExpires,
		"curExpires":  chg.CurExpires,
		"reason":      req.Reason,
	})
	writeOK(w, r, chg)
}
