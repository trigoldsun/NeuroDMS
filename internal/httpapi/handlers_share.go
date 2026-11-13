package httpapi

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"time"

	"docvault/internal/ace"
	"docvault/internal/auth"
	"docvault/internal/authz"
	"docvault/internal/content"
	"docvault/internal/db"
	"docvault/internal/feature"
	"docvault/internal/preview"
	"docvault/internal/share"

	"github.com/jackc/pgx/v5"
)

// registerShare 注册分享与对外访问路由。
//
// 两段式：/v1/public/shares/{token} 用长期链接换 5 分钟票据；
// 之后所有取字节的请求只带票据，不再出现长期凭证。
func (a *API) registerShare(mux *http.ServeMux) {
	mux.HandleFunc("POST /v1/shares", a.requireAuth(a.handleCreateShare))
	mux.HandleFunc("GET /v1/shares/pending", a.requireAuth(a.handlePendingShareApprovals))
	mux.HandleFunc("POST /v1/shares/{id}/revoke", a.requireAuth(a.handleRevokeShare))
	mux.HandleFunc("POST /v1/shares/{id}/approve", a.requireAuth(a.handleApproveShare))

	// 对外（免登录）
	mux.HandleFunc("GET /v1/public/shares/{token}", a.handleRedeem)
	mux.HandleFunc("GET /v1/public/tickets/{ticket}", a.handleTicketInfo)
	mux.HandleFunc("GET /v1/public/tickets/{ticket}/nodes", a.handleTicketList)
	mux.HandleFunc("GET /v1/public/tickets/{ticket}/content", a.handleTicketContent)
}

type createShareReq struct {
	// Kind 区分外链（link）与内部分享（internal）。
	// 内部分享不产生 token：它本质是"给别人授权"的语法糖，
	// 状态只存在 ace 表里（单一真源），避免"分享记录已撤销但 ACE 还在"的双写不一致。
	Kind        string   `json:"kind"`
	SubjectType string   `json:"subjectType"`
	SubjectIDs  []string `json:"subjectIds"`
	Preset      string   `json:"preset"`

	ObjectType      string   `json:"objectType"`
	ObjectID        string   `json:"objectId"`
	MaxUses         *int     `json:"maxUses"`
	ExpiresInHour   *int     `json:"expiresInHours"`
	AllowDownload   bool     `json:"allowDownload"`
	Watermark       bool     `json:"watermark"`
	Password        string   `json:"password"`
	IPAllowlist     []string `json:"ipAllowlist"`
	RequireApproval bool     `json:"requireApproval"`
	// EmailWhitelist 限定可申请验证码的邮箱或域名（@example.com）
	EmailWhitelist []string `json:"emailWhitelist"`
	// RequireVerify 为真时访客必须先完成邮箱验证才能兑换。
	//
	// 注意：这个字段此前在 share 表与 Options 里都存在，但 handler 从未赋值——
	// 表现为"界面勾了要求验证，实际什么也没发生"。属于典型的假开关。
	RequireVerify bool `json:"requireVerify"`
	// NotifyEmails 是"通过邮件分享"的收件人。
	//
	// 服务端只负责把链接投进外发队列，不负责替用户保密：
	// 邮件里永远不包含访问口令，口令必须由分享人另行走另一条通道告知。
	NotifyEmails []string `json:"notifyEmails"`
}

func (a *API) handleCreateShare(w http.ResponseWriter, r *http.Request) {
	c, _ := claimsFrom(r.Context())
	var req createShareReq
	if !decode(w, r, &req) {
		return
	}
	if req.ObjectType != "node" && req.ObjectType != "space" {
		writeErr(w, r, http.StatusBadRequest, "INVALID_ARGUMENT", "objectType 仅支持 node 或 space")
		return
	}
	if req.ObjectID == "" {
		writeErr(w, r, http.StatusBadRequest, "INVALID_ARGUMENT", "objectId 必填")
		return
	}

	// 创建外链必须持有 share_external 位。
	//
	// 这一条此前缺失：任何能"看见"文件的人都能生成公开链接，
	// 等于把 download 权限放大成了"全互联网可访问"。
	spaceID, nodeID, terr := a.aclTarget(r.Context(), c, req.ObjectType, req.ObjectID)
	if terr != nil {
		writeErr(w, r, http.StatusNotFound, "NOT_FOUND", "对象不存在")
		return
	}

	kind := req.Kind
	if kind == "" {
		kind = "link"
	}
	if kind == "internal" {
		a.createInternalShare(w, r, c, req, spaceID, nodeID)
		return
	}
	if kind != "link" {
		writeErr(w, r, http.StatusBadRequest, "INVALID_ARGUMENT", "kind 仅支持 link 或 internal")
		return
	}

	// 灰度开关：平台可以整体关闭某租户的"对外分享"能力（合规要求常见）。
	// 必须在服务端拦，而不是前端隐藏按钮——隐藏按钮只挡住老实人。
	//
	// 读不到开关时拒绝（503），不当成开启：这条路径正是用来满足合规关闭的，
	// fail-open 等于数据库抖一下就自动放开对外分享。
	if fs, ferr := a.featureState(r.Context(), c.TenantID, feature.ShareExternal); ferr != nil {
		writeErr(w, r, http.StatusServiceUnavailable, "FEATURE_UNAVAILABLE",
			"分享能力暂时不可用，请稍后重试")
		return
	} else if !fs.Enabled {
		_ = a.emit(r, c.TenantID, AuditEntry{
			ActorID: c.Subject, Action: "share.external", ObjectID: req.ObjectID,
			Result: "denied",
			Detail: map[string]any{"reason": "feature_disabled", "source": fs.Source,
				"defaultEnabled": fs.DefaultEnabled, "rolloutPercent": fs.RolloutPercent},
		})
		writeErr(w, r, http.StatusForbidden, "FEATURE_DISABLED",
			featureDenyMessage(fs, "对外分享"))
		return
	}

	perm, perr := a.check(r.Context(), c, spaceID, nodeID, authz.ShareExternal)
	if perr != nil {
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "权限判定失败")
		return
	}
	if a.denyUnless(w, r, perm) {
		return
	}

	opt := share.Options{
		MaxUses:         req.MaxUses,
		AllowDownload:   req.AllowDownload,
		Watermark:       req.Watermark,
		IPAllowlist:     req.IPAllowlist,
		RequireApproval: req.RequireApproval,
		EmailWhitelist:  req.EmailWhitelist,
		RequireVerify:   req.RequireVerify,
	}

	// 收件人必须在建分享**之前**校验：先建后报错的话，
	// 会留下一条"发了邮件但没通知到人"的分享，用户还得自己去撤销。
	recipients, rerr := normalizeRecipients(req.NotifyEmails)
	if rerr != nil {
		writeErr(w, r, http.StatusBadRequest, "INVALID_RECIPIENT", rerr.Error())
		return
	}
	// 邮件外发通道是档位能力：基础版只能建链接，不能由服务器代发邮件。
	// 只拦"有收件人"这一种情况——没有收件人的普通分享仍然可用，
	// 否则基础版连分享功能都没有了，与产品定位不符。
	if len(recipients) > 0 {
		ed, eerr := a.editionState(r.Context(), c.TenantID)
		if eerr != nil {
			writeErr(w, r, http.StatusServiceUnavailable, "ENTITLEMENT_UNAVAILABLE",
				"无法读取租户档位，请稍后重试")
			return
		}
		if !ed.Spec.ShareMail {
			_ = a.emit(r, c.TenantID, AuditEntry{
				ActorID: c.Subject, Action: "share.create", ObjectID: nodeID, Result: "denied",
				Detail: map[string]any{"reason": "edition_share_mail", "edition": string(ed.Edition)},
			})
			writeErr(w, r, http.StatusForbidden, "FEATURE_NOT_ENABLED",
				"当前档位（"+ed.Spec.Name+"）不支持邮件外发，请改用链接分享")
			return
		}
	}
	// 服务端没配邮件通道时**不阻断创建**：链接本身仍然有价值，
	// 前端会降级为"用本机邮件客户端发送"（mailto:）。
	// 只是必须在响应里说清楚"邮件没有由服务器发出"，不能让用户以为已送达。
	// 要求邮箱验证时，收件人必须在白名单里，否则他们连验证码都申请不到。
	// 把收件人并入白名单是"我就是要发给这些人"的直接语义。
	if opt.RequireVerify && len(recipients) > 0 {
		opt.EmailWhitelist = append(opt.EmailWhitelist, recipients...)
	}
	// 灰度开关：关闭后**新建**链接不再要求邮箱验证。
	// 存量链接不受影响——如果连存量也拦，客户会突然打不开已经发出去的链接，
	// 那种"平台改了个开关、客户业务断了"的事故比功能少一块严重得多。
	//
	// 注意方向：读不到开关时**保持要求验证**（fail-closed）。这里"开着"
	// 指更严格的校验，静默降级等于在故障时放松外发管控。
	if opt.RequireVerify {
		if fs, ferr := a.featureState(r.Context(), c.TenantID, feature.ShareEmailVerify); ferr == nil && !fs.Enabled {
			opt.RequireVerify = false
		}
	}
	if req.ExpiresInHour != nil && *req.ExpiresInHour > 0 {
		exp := time.Now().Add(time.Duration(*req.ExpiresInHour) * time.Hour)
		opt.ExpiresAt = &exp
	}
	if req.Password != "" {
		hash, err := auth.HashPassword(req.Password)
		if err != nil {
			writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "口令处理失败")
			return
		}
		opt.PasswordHash = hash
	}

	// 密级上界取发起人当前密级：外链访客没有账号，能代表他的只有发起人。
	// 查不到就按 0 处理（fail-closed：0 级只能分享 0 级内容）。
	var creatorClass int
	if err := db.WithTenant(r.Context(), a.Pool, c.TenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(r.Context(),
			`SELECT classification FROM app_user WHERE id = $1`, c.Subject).Scan(&creatorClass)
	}); err != nil {
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "读取账号密级失败")
		return
	}

	created, err := share.Create(r.Context(), a.Pool, c.TenantID, c.Subject, req.ObjectType, req.ObjectID,
		creatorClass, opt)
	if err != nil {
		if errors.Is(err, share.ErrSpaceNotShareable) {
			// 拒绝要留痕：这是"想整体外发但被拦住"的信号，值得审计
			_ = a.emit(r, c.TenantID, AuditEntry{
				ActorID: c.Subject, Action: "share.external", ObjectID: req.ObjectID,
				Result: "denied", Detail: map[string]any{"reason": "space_contains_hidden_nodes"},
			})
			writeErr(w, r, http.StatusForbidden, "SPACE_NOT_SHAREABLE",
				"该空间内含你无权访问或密级更高的内容，请改为分享具体文件或目录")
			return
		}
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "创建分享失败")
		return
	}
	// 审计里绝不写 token 明文：审计日志本身也是可能被导出的数据
	if err := a.emit(r, c.TenantID, AuditEntry{
		ActorID: c.Subject, Action: "share.create", ObjectID: created.ID, Result: "ok",
		Detail: map[string]any{
			"objectType": req.ObjectType, "maxUses": req.MaxUses,
			"password": req.Password != "", "ipAllowlist": len(req.IPAllowlist),
			"requireApproval": req.RequireApproval,
		},
	}); err != nil {
		writeErr(w, r, http.StatusInternalServerError, "AUDIT_FAILED", "审计写入失败，操作已拒绝")
		return
	}
	resp := map[string]any{"shareId": created.ID, "token": created.Token}
	// 审批状态以服务端结果为准：密级驱动的审批调用方并不知道，
	// 不返回的话界面会显示"链接已可用"，转发出去才发现打不开。
	if created.Approval == "pending" {
		resp["approvalStatus"] = "pending"
		// 顺便告诉发起人"现在还有几个人能批"。
		//
		// 这是为了避免死亡链接：审批权 = 对象 manage_acl + 密级足够 + 非发起人。
		// 单人项目里这三条同时成立的人可能是 0 个——链接建出来就永远 pending，
		// 而发起人以为"等审批就行"，实际上没人能批。
		// 计数只作提示（按空间 ACE 估算，不计继承），不参与任何判定。
		if n, cerr := a.countEligibleApprovers(r.Context(), c.TenantID, spaceID, nodeID,
			c.Subject, created.ObjectClass); cerr == nil {
			resp["approverCount"] = n
		}
	}

	// 邮件外发：分享已建好，投递失败不回滚（回滚会让用户白填一遍表单），
	// 但必须如实告诉调用方"链接发出去了、邮件没发出去"。
	link := a.publicBaseURL(r) + "/s/" + created.Token
	resp["shareUrl"] = link
	if len(recipients) > 0 {
		if a.Outbox == nil {
			// 没配 SMTP/Graph：链接照建，但要明确告诉调用方邮件**没有**从服务器发出
			resp["mailSkipped"] = "服务器未配置邮件通道"
			resp["mailTo"] = recipients
		} else {
			name := a.shareObjectName(r.Context(), c.TenantID, req.ObjectType, req.ObjectID)
			queued, merr := a.enqueueShareMail(r.Context(), c.TenantID, created.ID,
				a.senderDisplayName(r.Context(), c.TenantID, c.Subject), name, link, opt, recipients)
			resp["mailQueued"] = queued
			if merr != nil {
				resp["mailWarning"] = "链接已生成，但邮件入队失败，请手工发送：" + merr.Error()
				a.logErr("分享邮件入队失败", "shareId", created.ID, "err", merr)
			}
		}
	}

	writeOK(w, r, resp)
}

func (a *API) handleRevokeShare(w http.ResponseWriter, r *http.Request) {
	c, _ := claimsFrom(r.Context())
	id := r.PathValue("id")

	// 撤销是"对某个对象处置外发通道"，必须先确认调用者对该对象有处置权。
	//
	// 这里原先只按 tenant_id 过滤，等于**任何同租户用户只要知道 share id**
	// 就能撤销别人的外链：轻则业务中断（客户点开链接提示已失效），
	// 重则掩盖外泄（撤销会连带吊销票据，访问记录停在撤销前）。
	// 规则：创建者本人可撤；其他人需要有该对象的 manage_acl。
	var objectType, objectID, creatorID string
	err := db.WithTenant(r.Context(), a.Pool, c.TenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(r.Context(), `
			SELECT object_type, object_id::text, creator_id::text
			  FROM share WHERE id = $1 AND revoked_at IS NULL`, id).
			Scan(&objectType, &objectID, &creatorID)
	})
	if err != nil {
		writeErr(w, r, http.StatusNotFound, "NOT_FOUND", "分享不存在或已撤销")
		return
	}
	if creatorID != c.Subject {
		spaceID, nodeID, terr := a.aclTarget(r.Context(), c, objectType, objectID)
		if terr != nil {
			writeErr(w, r, http.StatusNotFound, "NOT_FOUND", "分享对象不存在")
			return
		}
		d, derr := a.check(r.Context(), c, spaceID, nodeID, authz.ManageACL)
		if derr != nil {
			writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "权限判定失败")
			return
		}
		if a.denyUnless(w, r, d) {
			return
		}
	}

	if err := share.Revoke(r.Context(), a.Pool, c.TenantID, id, c.Subject); err != nil {
		if errors.Is(err, share.ErrUnavailable) {
			writeErr(w, r, http.StatusNotFound, "NOT_FOUND", "分享不存在或已撤销")
			return
		}
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "撤销失败")
		return
	}
	if err := a.emit(r, c.TenantID, AuditEntry{
		ActorID: c.Subject, Action: "share.revoke", ObjectID: id, Result: "ok",
	}); err != nil {
		writeErr(w, r, http.StatusInternalServerError, "AUDIT_FAILED", "审计写入失败，操作已拒绝")
		return
	}
	writeOK(w, r, map[string]any{"revoked": true, "ticketsRevoked": true})
}

// handlePendingShareApprovals 列出「当前用户有权审批」的外发链接。
//
// 为什么不能按角色返回：审批权与"是不是安全管理员"无关，只取决于
// "你对这个对象有没有 manage_acl，且你不是发起人"。按角色给列表会出现
// 两种坏情况——列出来却点不动（403），或者该看到的却看不到。
//
// 这条接口是补缺口：在此之前审批只有 POST /shares/{id}/approve，
// 但没有任何地方能列出 pending 的链接。结果是发起人看到"审批中"，
// 而所有有权审批的人根本不知道有这件事——审批功能事实上停摆。
func (a *API) handlePendingShareApprovals(w http.ResponseWriter, r *http.Request) {
	c, _ := claimsFrom(r.Context())
	items, err := a.pendingShareApprovals(r.Context(), c)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "读取待审批分享失败")
		return
	}
	writeOK(w, r, map[string]any{"items": items, "count": len(items)})
}

// pendingShareApprovals 列出"我能批"的外发链接。
//
// 抽成方法供工作台复用：工作台上的待办数字必须与审批页的条数一致，
// 各写一套 SQL 迟早会出现"首页说有 3 条、点进去 0 条"。
func (a *API) pendingShareApprovals(ctx context.Context, c auth.Claims) ([]map[string]any, error) {
	type cand struct {
		ShareID    string
		ObjectType string
		ObjectID   string
		Name       string
		Class      int
		Creator    string
		CreatedAt  time.Time
		ExpiresAt  *time.Time
	}

	var cands []cand
	err := db.WithTenant(ctx, a.Pool, c.TenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			SELECT s.id::text, s.object_type, s.object_id::text,
			       COALESCE(n.name, sp.name, ''),
			       COALESCE(n.classification, sp.classification, 0),
			       COALESCE(NULLIF(u.display_name, ''), u.username, ''),
			       s.created_at, s.expires_at
			  FROM share s
			  LEFT JOIN node n  ON s.object_type = 'node'  AND n.id = s.object_id
			  LEFT JOIN space sp ON s.object_type = 'space' AND sp.id = s.object_id
			  LEFT JOIN app_user u ON u.id = s.creator_id
			 WHERE s.approval_status = 'pending'
			   AND s.revoked_at IS NULL
			   AND s.creator_id <> $1
			 ORDER BY s.created_at
			 LIMIT 100`, c.Subject)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var x cand
			if err := rows.Scan(&x.ShareID, &x.ObjectType, &x.ObjectID, &x.Name,
				&x.Class, &x.Creator, &x.CreatedAt, &x.ExpiresAt); err != nil {
				return err
			}
			cands = append(cands, x)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}

	out := make([]map[string]any, 0, len(cands))
	for _, x := range cands {
		spaceID, nodeID := x.ObjectID, ""
		if x.ObjectType == "node" {
			n, nerr := a.Content.GetNode(ctx, c.TenantID, x.ObjectID)
			if nerr != nil {
				continue // 对象已删：跳过，不让一条脏数据挡住整页
			}
			spaceID, nodeID = n.SpaceID, x.ObjectID
		}
		// 判定出错时跳过而不是报错中断：一条对象的判定失败不该让
		// 整个待办列表打不开（那样审批人会以为"没有待办"）。
		d, derr := a.check(ctx, c, spaceID, nodeID, authz.ManageACL)
		if derr != nil || !d.allowed {
			continue
		}
		out = append(out, map[string]any{
			"shareId": x.ShareID, "objectType": x.ObjectType, "objectId": x.ObjectID,
			"name": x.Name, "classification": x.Class, "creator": x.Creator,
			"createdAt": x.CreatedAt, "expiresAt": x.ExpiresAt,
		})
	}
	return out, nil
}

// countEligibleApprovers 估算"还有谁可能审批这条外链"。
//
// 条件与 approve 接口一致：密级足够、不是发起人、在该空间上有 ManageACL
// 或 Owner 位。**只查空间根上的显式 ACE，不计继承与角色授权**，因此结果
// 可能偏低；它的用途是"没人能批时提醒发起人"，不参与任何权限判定。
func (a *API) countEligibleApprovers(ctx context.Context, tenantID, spaceID, nodeID, creatorID string, objClass int) (int, error) {
	var n int
	err := db.WithTenant(ctx, a.Pool, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
			SELECT count(*)
			  FROM app_user u
			 WHERE u.tenant_id = $1
			   AND u.status = 'active'
			   AND u.classification >= $2
			   AND u.id <> $3::uuid
			   AND (
			     EXISTS (
			       SELECT 1 FROM ace a
			        WHERE a.tenant_id = $1
			          AND a.object_type = 'space'
			          AND a.object_id = $4::uuid
			          AND a.subject_type = 'user'
			          AND a.subject_id = u.id
			          AND (a.allow_bits & 8192) <> 0
			          AND a.deny_bits = 0)
			     -- 也可能只在文件/目录上单独授过管理权限，不能漏
			     OR EXISTS (
			       SELECT 1 FROM ace a
			        WHERE a.tenant_id = $1
			          AND a.object_type = 'node'
			          AND a.object_id = NULLIF($5, '')::uuid
			          AND a.subject_type = 'user'
			          AND a.subject_id = u.id
			          AND (a.allow_bits & 8192) <> 0
			          AND a.deny_bits = 0)
			   )`,
			tenantID, objClass, creatorID, spaceID, nodeID).Scan(&n)
	})
	return n, err
}

// handleApproveShare 审批外发。审批人必须对分享对象有 manage_acl——
// 不能由发起人自己审批，否则审批形同虚设（这一点由上层 check 保证）。
func (a *API) handleApproveShare(w http.ResponseWriter, r *http.Request) {
	c, _ := claimsFrom(r.Context())
	id := r.PathValue("id")
	var req struct {
		Approve bool `json:"approve"`
	}
	if !decode(w, r, &req) {
		return
	}

	// 找到分享对象做一次权限判定
	var objectType, objectID string
	if err := a.Pool.QueryRow(r.Context(), // pool-ok: 显式带 tenant_id 过滤，且需先取对象才能进租户上下文判定
		`SELECT object_type, object_id::text FROM share WHERE id = $1 AND tenant_id = $2`,
		id, c.TenantID).Scan(&objectType, &objectID); err != nil {
		writeErr(w, r, http.StatusNotFound, "NOT_FOUND", "分享不存在")
		return
	}
	spaceID, nodeID := objectID, ""
	if objectType == "node" {
		n, err := a.Content.GetNode(r.Context(), c.TenantID, objectID)
		if err != nil {
			writeErr(w, r, http.StatusNotFound, "NOT_FOUND", "对象不存在")
			return
		}
		spaceID, nodeID = n.SpaceID, objectID
	}
	d, err := a.check(r.Context(), c, spaceID, nodeID, authz.ManageACL)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "权限判定失败")
		return
	}
	if a.denyUnless(w, r, d) {
		return
	}

	if err := share.Approve(r.Context(), a.Pool, c.TenantID, id, c.Subject, req.Approve); err != nil {
		if errors.Is(err, share.ErrSelfApproval) {
			_ = a.emit(r, c.TenantID, AuditEntry{
				ActorID: c.Subject, Action: "share.approve", ObjectID: id, Result: "denied",
				Detail: map[string]any{"reason": "self_approval"},
			})
			writeErr(w, r, http.StatusForbidden, "SELF_APPROVAL_DENIED",
				"不能审批自己发起的分享，请由他人复核")
			return
		}
		writeErr(w, r, http.StatusConflict, "INVALID_STATE", "该分享不在待审批状态")
		return
	}
	result := "rejected"
	if req.Approve {
		result = "approved"
	}
	if err := a.emit(r, c.TenantID, AuditEntry{
		ActorID: c.Subject, Action: "share.approve", ObjectID: id,
		// result 只能是 ok/denied/error（audit_event_result_check 约束）。
		// 之前这里写的是 approved/rejected，审批一提交就违反约束 →
		// 审计写不进 → 接口返回 500，而状态其实已经改了。
		// 表现为"审批报错，但链接已变成已通过/已驳回"，且审计里没有记录。
		Result: "ok",
		Detail: map[string]any{"decision": result},
	}); err != nil {
		writeErr(w, r, http.StatusInternalServerError, "AUDIT_FAILED", "审计写入失败，操作已拒绝")
		return
	}
	writeOK(w, r, map[string]any{"approvalStatus": result})
}

// handleRedeem 消费链接，返回票据。
//
// 口令通过请求头传递而不是查询参数：查询串会进访问日志、浏览器历史与 Referer，
// 等于把口令写进日志。
func (a *API) handleRedeem(w http.ResponseWriter, r *http.Request) {
	token := r.PathValue("token")
	password := r.Header.Get("X-Share-Password")

	res, err := share.Redeem(r.Context(), a.Pool, token, password, clientIP(r), r.UserAgent())
	if err != nil {
		a.redeemError(w, r, err)
		return
	}
	ticket, expires, err := share.IssueTicket(r.Context(), a.Pool, res, clientIP(r), share.DefaultTicketTTL)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "签发访问票据失败")
		return
	}
	if err := a.emit(r, res.TenantID, AuditEntry{
		ActorType: "anonymous", Action: "share.redeem", ObjectID: res.ShareID, Result: "ok",
		Detail: map[string]any{"oneTime": res.IsOneTime},
	}); err != nil {
		writeErr(w, r, http.StatusInternalServerError, "AUDIT_FAILED", "审计写入失败，操作已拒绝")
		return
	}
	writeOK(w, r, map[string]any{
		"shareId":       res.ShareID,
		"objectType":    res.ObjectType,
		"objectId":      res.ObjectID,
		"allowDownload": res.AllowDownload,
		"watermark":     res.Watermark,
		"oneTime":       res.IsOneTime,
		"ticket":        ticket,
		"expiresIn":     int(time.Until(expires).Seconds()),
	})
}

// redeemError 把分享层的失败原因映射成对访问者有意义、但不泄漏链接是否存在的响应。
func (a *API) redeemError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case errors.Is(err, share.ErrUnavailable):
		// 不存在 / 已用尽 / 已过期 / 已撤销 统一表现，避免枚举
		writeErr(w, r, http.StatusGone, "SHARE_UNAVAILABLE", "链接不可用")
	case errors.Is(err, share.ErrPasswordRequired):
		writeErr(w, r, 411, "PASSWORD_REQUIRED", "该链接需要访问口令")
	case errors.Is(err, share.ErrVerifyRequired):
		// 428 而不是 403：这是"还差一步"，不是"你没资格"。
		// 前端据此切到邮箱验证表单，而不是显示"无权访问"。
		writeErr(w, r, http.StatusPreconditionRequired, "VERIFY_REQUIRED",
			"该链接需要完成邮箱验证")
	case errors.Is(err, share.ErrPasswordWrong):
		writeErr(w, r, http.StatusForbidden, "PASSWORD_WRONG", "访问口令不正确")
	case errors.Is(err, share.ErrLinkLocked):
		// 429 而不是 403：这是"暂时性"拒绝，客户端应等待而非换口令硬试
		w.Header().Set("Retry-After", "1800")
		writeErr(w, r, http.StatusTooManyRequests, "LINK_LOCKED", "口令错误次数过多，请 30 分钟后再试")
	case errors.Is(err, share.ErrIPNotAllowed):
		writeErr(w, r, http.StatusForbidden, "IP_NOT_ALLOWED", "当前网络不在允许范围内")
	case errors.Is(err, share.ErrPendingApproval):
		writeErr(w, r, http.StatusForbidden, "PENDING_APPROVAL", "分享正在审批中")
	case errors.Is(err, share.ErrApprovalRejected):
		writeErr(w, r, http.StatusForbidden, "APPROVAL_REJECTED", "分享审批未通过")
	default:
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "处理失败")
	}
}

// handleTicketInfo 返回票据可访问对象的元信息（分享页首屏用）。
func (a *API) handleTicketInfo(w http.ResponseWriter, r *http.Request) {
	t, err := share.ResolveTicket(r.Context(), a.Pool, r.PathValue("ticket"), clientIP(r))
	if err != nil {
		writeErr(w, r, http.StatusGone, "TICKET_INVALID", "访问票据无效或已过期")
		return
	}

	out := map[string]any{
		"objectType":    t.ObjectType,
		"allowDownload": t.AllowDownload,
		"watermark":     t.Watermark,
		"expiresAt":     t.ExpiresAt.UTC().Format(time.RFC3339),
	}
	if t.ObjectType == "node" {
		n, err := a.Content.GetNode(r.Context(), t.TenantID, t.ObjectID)
		if err != nil || t.TooClassified(n.Classification) {
			writeErr(w, r, http.StatusGone, "TICKET_INVALID", "访问票据无效或已过期")
			return
		}
		out["name"] = n.Name
		out["size"] = n.SizeBytes
		out["mime"] = n.Mime
	}
	writeOK(w, r, out)
}

// handleTicketList 列出空间分享下的子节点。
func (a *API) handleTicketList(w http.ResponseWriter, r *http.Request) {
	t, err := share.ResolveTicket(r.Context(), a.Pool, r.PathValue("ticket"), clientIP(r))
	if err != nil {
		writeErr(w, r, http.StatusGone, "TICKET_INVALID", "访问票据无效或已过期")
		return
	}
	if t.ObjectType != "space" {
		writeErr(w, r, http.StatusBadRequest, "INVALID_ARGUMENT", "该票据指向单个文件")
		return
	}
	parent := r.URL.Query().Get("parentId")
	nodes, err := a.Content.ListNodes(r.Context(), t.TenantID, t.ObjectID, parent)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "读取目录失败")
		return
	}
	items := make([]map[string]any, 0, len(nodes))
	for _, n := range nodes {
		// 逐条按密级上界过滤：空间外链不应把发起人也看不到的内容列出来。
		// 这里不报错而是"看不见"，与站内搜索的处理一致——
		// 否则访客可以通过"哪些条目报错"反推哪些文件存在。
		if t.TooClassified(n.Classification) {
			continue
		}
		items = append(items, map[string]any{
			"id": n.ID, "kind": n.Kind, "name": n.Name, "size": n.SizeBytes,
			"mime": n.Mime, "updatedAt": n.UpdatedAt.UTC().Format(time.RFC3339),
		})
	}
	writeOK(w, r, map[string]any{"items": items, "count": len(items)})
}

// handleTicketContent 取字节。这是唯一能拿到文件内容的外部入口。
func (a *API) handleTicketContent(w http.ResponseWriter, r *http.Request) {
	t, err := share.ResolveTicket(r.Context(), a.Pool, r.PathValue("ticket"), clientIP(r))
	if err != nil {
		writeErr(w, r, http.StatusGone, "TICKET_INVALID", "访问票据无效或已过期")
		return
	}

	nodeID := t.ObjectID
	if t.ObjectType == "space" {
		// 空间分享必须显式指定子节点，且该节点必须属于该空间（防越权取任意文件）
		nodeID = r.URL.Query().Get("nodeId")
	}
	if nodeID == "" {
		writeErr(w, r, http.StatusBadRequest, "INVALID_ARGUMENT", "缺少 nodeId")
		return
	}

	n, err := a.Content.GetNode(r.Context(), t.TenantID, nodeID)
	if err != nil || n.SpaceID != t.ObjectID && t.ObjectType == "space" {
		writeErr(w, r, http.StatusGone, "TICKET_INVALID", "访问票据无效或已过期")
		return
	}
	// 密级强制门在外发通道上同样成立：分享的 max_class 是发起人创建时的密级，
	// 高于它的节点一律不可取——即使它就在被分享的空间里。
	if t.TooClassified(n.Classification) {
		_ = a.emit(r, t.TenantID, AuditEntry{
			ActorType: "anonymous", Action: "share.download", ObjectID: nodeID, Result: "denied",
			Detail: map[string]any{"reason": "classification", "shareId": t.ShareID},
		})
		writeErr(w, r, http.StatusGone, "TICKET_INVALID", "访问票据无效或已过期")
		return
	}

	inline := r.URL.Query().Get("inline") == "1"
	if !inline && !t.AllowDownload {
		// 只读分享不允许下载：返回 403 而不是假装成功
		writeErr(w, r, http.StatusForbidden, "DOWNLOAD_FORBIDDEN", "该分享不允许下载")
		return
	}

	if inline {
		a.serveShareInline(w, r, t, n)
		return
	}

	rc, node, err := a.Content.OpenContent(r.Context(), t.TenantID, nodeID)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "内容不可用")
		return
	}
	defer func() { _ = rc.Close() }()

	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition",
		fmt.Sprintf("attachment; filename*=UTF-8''%s", urlEscape(node.Name)))
	w.Header().Set("Content-Length", strconv.FormatInt(node.SizeBytes, 10))
	// 外部访问的内容禁止被中间层缓存：撤销后必须立刻取不到
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = io.Copy(w, rc)

	a.emitQuietPublic(r, t, "share.download", nodeID)
}

// serveShareInline 输出"外部访客能直接看到"的内容。
//
// 这里曾经直接把原始字节流出去，结果是：Word/Excel/PPT 的分享链接点开一片空白
// （浏览器渲染不了 Office 二进制），而"已开启水印"只写了一个 X-Watermark 响应头，
// 内容根本没加水印——等于对客户承诺了一件没做的事。
//
// 现在与站内预览走同一条管线：
//   - 需要转换的类型 → LibreOffice 转 PDF（复用同一份缓存）
//   - 要求水印 → 在响应时叠加（不写进缓存，否则水印就变成"谁都一样"）
//   - 原生可显示的类型 → 直出，但 html/xml 一律降级为纯文本
func (a *API) serveShareInline(w http.ResponseWriter, r *http.Request, t share.Ticket, n content.Node) {
	if !inlineMime(n.Mime, n.Name) {
		a.serveShareConverted(w, r, t, n)
		return
	}

	rc, node, err := a.Content.OpenContent(r.Context(), t.TenantID, n.ID)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "内容不可用")
		return
	}
	defer func() { _ = rc.Close() }()

	ct := node.Mime
	if ct == "" || ct == "application/octet-stream" {
		ct = mimeByExt(node.Name)
	}
	ct = safeInlineType(ct)

	if ct == "application/pdf" && t.Watermark && a.Watermark != nil {
		raw, rerr := io.ReadAll(io.LimitReader(rc, maxWatermarkBytes+1))
		if rerr != nil || int64(len(raw)) > maxWatermarkBytes {
			writeErr(w, r, http.StatusRequestEntityTooLarge, "PREVIEW_TOO_LARGE",
				"文件过大，无法生成带水印的预览，请下载后查看")
			return
		}
		a.writeShareWatermarkedPDF(w, r, t, raw)
		return
	}

	w.Header().Set("Content-Type", ct)
	w.Header().Set("Content-Disposition", fmt.Sprintf("inline; filename*=UTF-8''%s", urlEscape(node.Name)))
	w.Header().Set("Content-Length", strconv.FormatInt(node.SizeBytes, 10))
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = io.Copy(w, rc)

	a.emitQuietPublic(r, t, "share.preview", n.ID)
}

// serveShareConverted 把 Office 等类型转成 PDF 后输出。
func (a *API) serveShareConverted(w http.ResponseWriter, r *http.Request, t share.Ticket, n content.Node) {
	if a.Preview == nil {
		writeErr(w, r, http.StatusNotImplemented, "PREVIEW_UNAVAILABLE",
			"服务器未启用在线预览，请下载后查看")
		return
	}

	key := fmt.Sprintf("%s:%d:%d", n.ID, n.SizeBytes, n.UpdatedAt.UnixNano())
	entry, err := a.Preview.Get(r.Context(), key, n.Name, func() (io.ReadCloser, error) {
		rc, _, oerr := a.Content.OpenContent(r.Context(), t.TenantID, n.ID)
		return rc, oerr
	})
	if err != nil {
		if errors.Is(err, preview.ErrUnsupported) {
			writeErr(w, r, http.StatusNotImplemented, "PREVIEW_UNAVAILABLE", "该类型暂不支持在线查看")
			return
		}
		_ = a.emitPublic(r, t.TenantID, t.ShareID, "share.preview", "error",
			map[string]any{"reason": err.Error()})
		writeErr(w, r, http.StatusInternalServerError, "PREVIEW_FAILED", "转换失败，请下载后查看")
		return
	}

	if t.Watermark && a.Watermark != nil {
		if entry.Size > maxWatermarkBytes {
			writeErr(w, r, http.StatusRequestEntityTooLarge, "PREVIEW_TOO_LARGE",
				"文件过大，无法生成带水印的预览，请下载后查看")
			return
		}
		raw, rerr := os.ReadFile(entry.Path)
		if rerr != nil {
			writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "读取预览失败")
			return
		}
		a.writeShareWatermarkedPDF(w, r, t, raw)
		return
	}

	f, err := os.Open(entry.Path)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "读取预览失败")
		return
	}
	defer func() { _ = f.Close() }()

	w.Header().Set("Content-Type", "application/pdf")
	w.Header().Set("Content-Disposition", fmt.Sprintf("inline; filename*=UTF-8''%s", urlEscape(n.Name)))
	w.Header().Set("Content-Length", strconv.FormatInt(entry.Size, 10))
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = io.Copy(w, f)

	a.emitQuietPublic(r, t, "share.preview", n.ID)
}

// writeShareWatermarkedPDF 给外部分享的 PDF 叠溯源水印。
//
// 水印文字与站内预览不同：访客没有账号，能标识他的只有"哪条分享 + 从哪个 IP + 什么时候"。
// 这三项拼起来足以在截图外流时定位到具体那条链接与访问者。
// 水印失败必须拒绝（fail-closed）——返回未加水印的内容等于水印静默失效。
func (a *API) writeShareWatermarkedPDF(w http.ResponseWriter, r *http.Request, t share.Ticket, pdf []byte) {
	account, footer := publicWatermarkParts(t, clientIP(r))
	out, err := a.Watermark.Apply(r.Context(), pdf, account, footer)
	if err != nil {
		_ = a.emitPublic(r, t.TenantID, t.ShareID, "share.watermark", "error",
			map[string]any{"reason": err.Error()})
		writeErr(w, r, http.StatusInternalServerError, "WATERMARK_FAILED",
			"水印生成失败，已拒绝返回未加水印的内容")
		return
	}
	w.Header().Set("Content-Type", "application/pdf")
	w.Header().Set("Content-Disposition", "inline")
	w.Header().Set("Content-Length", strconv.Itoa(len(out)))
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(out)

	a.emitQuietPublic(r, t, "share.preview", t.ObjectID)
}

func (a *API) emitQuietPublic(r *http.Request, t share.Ticket, action, objectID string) {
	_ = a.emit(r, t.TenantID, AuditEntry{
		ActorType: "anonymous", Action: action, ObjectID: objectID, Result: "ok",
		Detail: map[string]any{"shareId": t.ShareID},
	})
}

// createInternalShare 创建"内部分享"：把对象按档位授给一批内部主体。
//
// 权限要求是 share_internal（不是 share_external）：
// 内部分享不产生可外传的链接，风险等级低于外链，但必须与外链分开授权——
// 否则"能对外分享的人"与"只能对内分享的人"就没有区别了（AC-24）。
//
// 不落 share 表：状态只存 ace。若两边都写，撤销时必然出现
// "分享记录已撤销但 ACE 还在（或反之）"的不一致，而权限是最终生效的那个。
func (a *API) createInternalShare(w http.ResponseWriter, r *http.Request, c auth.Claims,
	req createShareReq, spaceID, nodeID string) {

	preset := authz.Preset(req.Preset)
	if preset == "" {
		preset = authz.PresetViewer
	}
	if !preset.Valid() {
		writeErr(w, r, http.StatusBadRequest, "INVALID_ARGUMENT", "未知权限档位")
		return
	}
	switch req.SubjectType {
	case "user", "dept", "group", "role":
	case "":
		writeErr(w, r, http.StatusBadRequest, "INVALID_ARGUMENT", "subjectType 必填")
		return
	default:
		writeErr(w, r, http.StatusBadRequest, "INVALID_ARGUMENT", "subjectType 仅支持 user/dept/group/role")
		return
	}
	if len(req.SubjectIDs) == 0 || len(req.SubjectIDs) > 200 {
		writeErr(w, r, http.StatusBadRequest, "INVALID_ARGUMENT", "subjectIds 数量需在 1..200 之间")
		return
	}

	// 必须是 share_internal 位（外链位不能替代）
	perm, err := a.check(r.Context(), c, spaceID, nodeID, authz.ShareInternal)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "权限判定失败")
		return
	}
	if a.denyUnless(w, r, perm) {
		return
	}

	var expires *time.Time
	if req.ExpiresInHour != nil && *req.ExpiresInHour > 0 {
		t := time.Now().Add(time.Duration(*req.ExpiresInHour) * time.Hour)
		expires = &t
	}

	var aceIDs []string
	err = db.WithTenant(r.Context(), a.Pool, c.TenantID, func(tx pgx.Tx) error {
		for _, sid := range req.SubjectIDs {
			id, e := ace.Grant(r.Context(), tx, c.TenantID, req.ObjectType, req.ObjectID,
				req.SubjectType, sid, preset, c.Subject, expires)
			if e != nil {
				return e // 任一失败整体回滚：不允许"授了一半"
			}
			aceIDs = append(aceIDs, id)
		}
		return nil
	})
	if err != nil {
		if errors.Is(err, ace.ErrCeilingExceeded) {
			_ = a.emit(r, c.TenantID, AuditEntry{
				ActorID: c.Subject, Action: "share.internal", ObjectID: req.ObjectID, Result: "denied",
				Detail: map[string]any{"reason": "ceiling", "preset": string(preset)},
			})
			writeErr(w, r, http.StatusForbidden, "CEILING_EXCEEDED", "不能授出高于自身档位的权限")
			return
		}
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "内部分享失败")
		return
	}

	if err := a.emit(r, c.TenantID, AuditEntry{
		ActorID: c.Subject, Action: "share.internal", ObjectID: req.ObjectID, Result: "ok",
		Detail: map[string]any{"preset": string(preset), "subjectType": req.SubjectType,
			"count": len(aceIDs), "subjectIds": req.SubjectIDs},
	}); err != nil {
		writeErr(w, r, http.StatusInternalServerError, "AUDIT_FAILED", "审计写入失败，操作已拒绝")
		return
	}
	writeOK(w, r, map[string]any{
		"kind": "internal", "objectId": req.ObjectID,
		"preset": string(preset), "aceIds": aceIDs, "count": len(aceIDs),
	})
}
