package httpapi

import (
	"errors"
	"net/http"
	"time"

	"docvault/internal/audit"
	"docvault/internal/db"
	"docvault/internal/tenant"

	"github.com/jackc/pgx/v5"
)

// 平台侧"调整租户系统管理员密级"。
//
// 为什么需要这个入口：密级有"不能授出高于自己"的硬规则（见主文档 6.16），
// 而开通、升档、以及客户自己把管理员降到 0 级之后，租户里可能**没有任何人**
// 能把管理员提回去——不提供平台入口，就只剩运维改库（不可审计、不可追责）。
//
// 边界（刻意保留的三条）：
//  1. 只能改**系统管理员**的密级，不是"平台能改任何成员密级"；
//  2. 上限受租户档位约束（`SelectableClasses`），基础版只能 0；
//  3. 改密级**不等于能看到内容**：平台令牌没有租户数据通道，
//     这条操作只影响该账号在租户内的可见范围，且平台与租户两侧审计都留痕。
func (a *API) registerPlatformAdmins(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/platform/tenants/{slug}/admins",
		a.requirePlatform(a.handlePlatformAdmins))
	mux.HandleFunc("PUT /v1/platform/tenants/{slug}/admins/{id}/classification",
		a.requirePlatformWrite(a.handlePlatformAdminClassPut))
}

type platformAdmin struct {
	ID             string     `json:"id"`
	Username       string     `json:"username"`
	DisplayName    string     `json:"displayName"`
	Status         string     `json:"status"`
	Classification int        `json:"classification"`
	Ceiling        int        `json:"ceiling"`
	LastLoginAt    *time.Time `json:"lastLoginAt"`
}

var (
	errAdminNotFound = errors.New("该账号不是本租户的系统管理员")
	errAdminBadClass = errors.New("密级需在 0-6 之间")
)

// tenantIDBySlug 把 slug 解析成租户 id，并把"不存在"统一翻译成 404。
func (a *API) tenantIDBySlug(w http.ResponseWriter, r *http.Request) (string, bool) {
	tid, err := a.Tenants.ResolveID(r.Context(), r.PathValue("slug"))
	if err != nil {
		if errors.Is(err, tenant.ErrNotFound) {
			writeErr(w, r, http.StatusNotFound, "NOT_FOUND", "租户不存在")
		} else {
			writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "读取租户失败")
		}
		return "", false
	}
	return tid, true
}

// handlePlatformAdmins 列出该租户的系统管理员，并告诉前端"这个档位允许哪些密级"。
//
// 返回可选集合而不是让前端查表：档位与密级的对应关系只有服务端一处事实源，
// 前端复制一份必然有一天与后端不一致（那正是"选项有、提交被拒"的来源）。
func (a *API) handlePlatformAdmins(w http.ResponseWriter, r *http.Request) {
	tid, ok := a.tenantIDBySlug(w, r)
	if !ok {
		return
	}
	st, err := a.editionState(r.Context(), tid)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "读取租户档位失败")
		return
	}

	items := []platformAdmin{}
	err = db.WithTenant(r.Context(), a.Pool, tid, func(tx pgx.Tx) error {
		rows, e := tx.Query(r.Context(), `
			SELECT u.id::text, u.username, u.display_name, u.status,
			       u.classification, u.ceiling, u.last_login_at
			  FROM app_user u
			  JOIN user_role ur ON ur.user_id = u.id AND ur.tenant_id = u.tenant_id
			  JOIN role r ON r.id = ur.role_id
			 WHERE u.tenant_id = $1 AND r.code = 'sysadmin'
			   AND u.deleted_at IS NULL AND r.deleted_at IS NULL
			 ORDER BY u.created_at`, tid)
		if e != nil {
			return e
		}
		defer rows.Close()
		for rows.Next() {
			var it platformAdmin
			if e := rows.Scan(&it.ID, &it.Username, &it.DisplayName, &it.Status,
				&it.Classification, &it.Ceiling, &it.LastLoginAt); e != nil {
				return e
			}
			items = append(items, it)
		}
		return rows.Err()
	})
	if err != nil {
		a.logErr("读取租户管理员失败", "err", err)
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "读取系统管理员失败")
		return
	}

	levels := st.SelectableClasses()
	maxLevel := 0
	for _, v := range levels {
		if v > maxLevel {
			maxLevel = v
		}
	}
	writeOK(w, r, map[string]any{
		"items":                items,
		"edition":              st.Edition,
		"classificationLevels": levels, // nil = 该档位没有密级功能，只允许 0
		"maxClassification":    maxLevel,
	})
}

// handlePlatformAdminClassPut 改某个系统管理员的密级。
//
// 改密级与写两处审计在同一事务里完成：这是"谁给了谁更高可见范围"的记录，
// 不允许出现"改了、没记上"。
func (a *API) handlePlatformAdminClassPut(w http.ResponseWriter, r *http.Request) {
	tid, ok := a.tenantIDBySlug(w, r)
	if !ok {
		return
	}
	var in struct {
		Classification *int   `json:"classification"`
		Reason         string `json:"reason"`
	}
	if !decode(w, r, &in) {
		return
	}
	if in.Classification == nil || *in.Classification < 0 || *in.Classification > 6 {
		writeErr(w, r, http.StatusBadRequest, "INVALID_ARGUMENT", errAdminBadClass.Error())
		return
	}
	want := *in.Classification

	st, err := a.editionState(r.Context(), tid)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "读取租户档位失败")
		return
	}
	if !levelAllowed(st.SelectableClasses(), want) {
		writeErr(w, r, http.StatusForbidden, "FEATURE_NOT_ENABLED",
			"当前档位或授权不包含该密级（"+st.Spec.Name+"）")
		return
	}

	adminID := r.PathValue("id")
	if !isUUID(adminID) {
		writeErr(w, r, http.StatusNotFound, "NOT_FOUND", errAdminNotFound.Error())
		return
	}

	p, _ := platformFrom(r.Context())
	actor := p.Email
	if p.Static {
		actor = "static-token"
	}

	var before int
	err = db.WithTenant(r.Context(), a.Pool, tid, func(tx pgx.Tx) error {
		var isAdmin bool
		err := tx.QueryRow(r.Context(), `
			SELECT u.classification,
			       EXISTS (SELECT 1 FROM user_role ur JOIN role r ON r.id = ur.role_id
			                WHERE ur.user_id = u.id AND ur.tenant_id = u.tenant_id
			                  AND r.code = 'sysadmin' AND r.deleted_at IS NULL)
			  FROM app_user u
			 WHERE u.id = $1 AND u.tenant_id = $2 AND u.deleted_at IS NULL`,
			adminID, tid).Scan(&before, &isAdmin)
		if errors.Is(err, pgx.ErrNoRows) {
			return errAdminNotFound
		}
		if err != nil {
			return err
		}
		if !isAdmin {
			return errAdminNotFound
		}
		if before == want {
			return nil // 幂等：值没变就不写审计噪音
		}
		// ceiling 不低于 classification：否则会出现"密级高于可授出上限"的自相矛盾状态。
		if _, err := tx.Exec(r.Context(), `
			UPDATE app_user
			   SET classification = $2, ceiling = greatest(ceiling, $2), updated_at = now()
			 WHERE id = $1`, adminID, want); err != nil {
			return err
		}
		detail := map[string]any{
			"before": map[string]any{"classification": before},
			"after":  map[string]any{"classification": want},
			"source": "platform",
			"actor":  actor,
		}
		if len(in.Reason) > 0 {
			detail["reason"] = in.Reason
		}
		return audit.Append(r.Context(), tx, tid, audit.Event{
			ActorType:  "system",
			Action:     "admin.member.classification",
			ObjectType: "app_user",
			ObjectID:   adminID,
			Result:     audit.ResultOK,
			Detail:     detail,
			IP:         clientIP(r),
		})
	})
	if errors.Is(err, errAdminNotFound) {
		writeErr(w, r, http.StatusNotFound, "NOT_FOUND", errAdminNotFound.Error())
		return
	}
	if err != nil {
		a.logErr("平台修改管理员密级失败", "err", err, "slug", r.PathValue("slug"))
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "修改密级失败")
		return
	}

	a.auditPlatform(r, p, "platform.admin.classification", r.PathValue("slug"), "ok", map[string]any{
		"adminId": adminID,
		"before":  before,
		"after":   want,
		"reason":  in.Reason,
	})
	writeOK(w, r, map[string]any{"id": adminID, "classification": want})
}
