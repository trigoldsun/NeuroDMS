package httpapi

import (
	"context"
	"net/http"
	"time"

	"docvault/internal/ace"
	"docvault/internal/auth"
	"docvault/internal/authz"
	"docvault/internal/classification"
	"docvault/internal/db"

	"github.com/jackc/pgx/v5"
)

// 审批人候选：把"谁能批"从一句注释变成可枚举的名单。
//
// 为什么必须枚举而不是只给个数：发起人需要"选一个最合适的人"，
// 而"有 3 个人能批"无法回答"是哪 3 个"。同时这也暴露了死链风险：
// 名单为空时，链接建出来就永远停在 pending。

const (
	// 第二层审批的起算密级：5 级（机密）与 6 级（绝密）。
	// 这两个级别一旦外发，除正常审批外还要空间所有者确认。
	ownerApprovalMinClass = 5
	// 候选人上限：超过这个数说明授权面过宽（例如给全员角色授了管理权），
	// 继续枚举既慢也没有选择意义。返回 truncated 让界面提示收窄授权。
	maxApproverCandidates = 500
)

type shareApprover struct {
	ID             string   `json:"id"`
	Name           string   `json:"name"`
	Username       string   `json:"username"`
	IsOwner        bool     `json:"isOwner"`
	Roles          []string `json:"roles,omitempty"`
	Classification int      `json:"classification"`
	// Eligible 仅对 owners 有意义：所有者密级不够时仍列出，但不可选。
	Eligible bool `json:"eligible"`
}

type shareApprovalPlan struct {
	RequireApproval bool            `json:"requireApproval"`
	Reason          string          `json:"reason"` // classification | manual | none
	ObjectClass     int             `json:"objectClass"`
	MinClass        int             `json:"minClass"`
	TwoLayer        bool            `json:"twoLayer"`
	Approvers       []shareApprover `json:"approvers"`
	Owners          []shareApprover `json:"owners"`
	CreatorIsOwner  bool            `json:"creatorIsOwner"`
	// OwnerLayerSkipped 说明为什么没有第二层：
	// requester_is_owner（发起人就是所有者）或 no_owner（空间没有可用所有者）。
	OwnerLayerSkipped string `json:"ownerLayerSkipped,omitempty"`
	Truncated         bool   `json:"truncated,omitempty"`
}

// handleShareApprovers 返回"这条分享需要谁批、可选谁"。
//
// 权限：与创建分享一致，必须持有 share_external。否则会把"谁能访问这个文件"
// 的人员名单泄露给只能查看的人。
func (a *API) handleShareApprovers(w http.ResponseWriter, r *http.Request) {
	c, _ := claimsFrom(r.Context())
	objectType := r.URL.Query().Get("objectType")
	objectID := r.URL.Query().Get("objectId")
	if objectType != "node" && objectType != "space" {
		writeErr(w, r, http.StatusBadRequest, "INVALID_ARGUMENT", "objectType 仅支持 node 或 space")
		return
	}
	if objectID == "" {
		writeErr(w, r, http.StatusBadRequest, "INVALID_ARGUMENT", "objectId 必填")
		return
	}
	spaceID, nodeID, err := a.aclTarget(r.Context(), c, objectType, objectID)
	if err != nil {
		writeErr(w, r, http.StatusNotFound, "NOT_FOUND", "对象不存在")
		return
	}
	d, err := a.check(r.Context(), c, spaceID, nodeID, authz.ShareExternal)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "权限判定失败")
		return
	}
	if a.denyUnless(w, r, d) {
		return
	}

	plan, err := a.resolveShareApprovalPlan(r.Context(), c, objectType, spaceID, nodeID)
	if err != nil {
		a.logErr("解析审批人失败", "objectType", objectType, "objectId", objectID, "err", err)
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "读取审批人失败")
		return
	}
	writeOK(w, r, plan)
}

// resolveShareApprovalPlan 计算审批要求与候选名单。
//
// 判定口径与 Approve 接口一致：
//   - 第一层：对该对象有 manage_acl、密级 ≥ 对象有效密级、在职、不是发起人；
//   - 第二层：空间所有者（owner_id 或 owner 档位 ACE 的主体），且同样满足密级与在职。
//
// 与旧实现（countEligibleApprovers）的区别：这里走权限内核逐人复核，
// 因此包含部门/角色/组继承、显式拒绝、继承断开与标签策略；旧实现只数了
// 空间根与文件上的直接用户 ACE，会漏掉"通过部门授权"的审批人。
func (a *API) resolveShareApprovalPlan(ctx context.Context, c auth.Claims, objectType, spaceID, nodeID string) (shareApprovalPlan, error) {
	plan := shareApprovalPlan{
		Approvers: []shareApprover{},
		Owners:    []shareApprover{},
	}

	var aces []authz.ACE
	err := db.WithTenant(ctx, a.Pool, c.TenantID, func(tx pgx.Tx) error {
		var e error
		aces, e = ace.LoadForNode(ctx, tx, spaceID, nodeID)
		if e != nil {
			return e
		}
		objClass, e := classification.EffectiveClass(ctx, tx, c.TenantID, nodeID, spaceID)
		if e != nil {
			return e
		}
		plan.ObjectClass = objClass
		if e := tx.QueryRow(ctx,
			`SELECT share_approval_min_class FROM tenant WHERE id = $1`, c.TenantID).Scan(&plan.MinClass); e != nil {
			return e
		}

		// 空间所有者集合：owner_id + owner 档位 ACE 展开到人。
		owners, creatorIsOwner, e := loadSpaceOwners(ctx, tx, c.TenantID, spaceID, c.Subject)
		if e != nil {
			return e
		}
		plan.CreatorIsOwner = creatorIsOwner

		// 候选人：只取"密级够、在职、非发起人"的人，再用内核逐条复核 manage_acl。
		// 这一步先用 SQL 缩小范围，避免对全租户用户做 O(n) 判定。
		rows, e := tx.Query(ctx, `
			SELECT u.id::text,
			       COALESCE(NULLIF(u.display_name, ''), u.username),
			       u.username, u.classification, u.ceiling,
			       COALESCE((SELECT array_agg(d2.path::text)
			                   FROM dept d1, dept d2
			                  WHERE d1.id = u.dept_id AND d2.path @> d1.path), '{}'::text[]),
			       COALESCE((SELECT array_agg(ur.role_id::text) FROM user_role ur WHERE ur.user_id = u.id), '{}'::text[]),
			       COALESCE((SELECT array_agg(gm.group_id::text) FROM group_member gm WHERE gm.user_id = u.id), '{}'::text[]),
			       COALESCE((SELECT array_agg(r.code)
			                   FROM user_role ur JOIN role r ON r.id = ur.role_id
			                  WHERE ur.user_id = u.id), '{}'::text[])
			  FROM app_user u
			 WHERE u.tenant_id = $1
			   AND u.status = 'active'
			   AND u.deleted_at IS NULL
			   AND u.classification >= $2
			   AND u.id <> $3::uuid
			 ORDER BY lower(COALESCE(NULLIF(u.display_name, ''), u.username))
			 LIMIT $4`, c.TenantID, plan.ObjectClass, c.Subject, maxApproverCandidates+1)
		if e != nil {
			return e
		}
		defer rows.Close()

		ownerSet := map[string]bool{}
		for _, o := range owners {
			ownerSet[o.ID] = true
		}

		for rows.Next() {
			var (
				u       shareApprover
				ceiling int
				depts   []string
				roles   []string
				groups  []string
				codes   []string
			)
			if e := rows.Scan(&u.ID, &u.Name, &u.Username, &u.Classification, &ceiling,
				&depts, &roles, &groups, &codes); e != nil {
				return e
			}
			u.Roles = codes
			u.IsOwner = ownerSet[u.ID]

			sub := authz.Subject{
				ID: u.ID, TenantID: c.TenantID, Active: true,
				Class: u.Classification, Ceiling: ceiling,
				DeptPaths: depts, RoleIDs: roles, GroupIDs: groups,
				// 名单是"权限与密级"层面的候选；IP/设备等运行期条件
				// 在真正审批时仍会按请求上下文判一次。
				MFASatisfied: true,
			}
			d, e := authz.Authorize(ctx, &ace.Source{Aces: aces}, sub,
				authz.Object{ID: nodeID, TenantID: c.TenantID, Class: plan.ObjectClass},
				authz.ManageACL, time.Now())
			if e != nil {
				return e
			}
			if !d.Allowed {
				continue
			}
			if len(plan.Approvers) >= maxApproverCandidates {
				plan.Truncated = true
				break
			}
			plan.Approvers = append(plan.Approvers, u)
		}
		if e := rows.Err(); e != nil {
			return e
		}

		// 第二层的可选所有者：排除发起人（不能自批），只保留密级够的。
		for _, o := range owners {
			if o.ID == c.Subject {
				continue
			}
			o.Eligible = o.Classification >= plan.ObjectClass
			plan.Owners = append(plan.Owners, o)
		}
		return nil
	})
	if err != nil {
		return plan, err
	}

	plan.RequireApproval = plan.ObjectClass >= plan.MinClass
	plan.TwoLayer = plan.ObjectClass >= ownerApprovalMinClass
	if plan.RequireApproval {
		plan.Reason = "classification"
	} else {
		plan.Reason = "none"
	}

	// 第二层是否可能：
	//   - 发起人本人就是所有者：他的发起即代表所有者知情，不能再要求他审批自己；
	//   - 没有其他可用所有者：无法完成第二层，必须让界面提示"先提密/换审批人"。
	if plan.TwoLayer && plan.RequireApproval {
		eligibleOwners := 0
		for _, o := range plan.Owners {
			if o.Eligible {
				eligibleOwners++
			}
		}
		switch {
		case plan.CreatorIsOwner && eligibleOwners == 0:
			plan.OwnerLayerSkipped = "requester_is_owner"
		case eligibleOwners == 0:
			plan.OwnerLayerSkipped = "no_owner"
		}
	}
	return plan, nil
}

// loadSpaceOwners 返回空间的所有者集合（含 owner 档位 ACE 展开到人）。
//
// creatorIsOwner 单独返回：它决定"发起人自己就是所有者时，第二层是否还要求确认"。
func loadSpaceOwners(ctx context.Context, tx pgx.Tx, tenantID, spaceID, creatorID string) ([]shareApprover, bool, error) {
	rows, err := tx.Query(ctx, `
		SELECT u.id::text,
		       COALESCE(NULLIF(u.display_name, ''), u.username),
		       u.username, u.classification,
		       (u.id = sp.owner_id) AS is_primary
		  FROM space sp
		  JOIN app_user u ON u.tenant_id = sp.tenant_id
		 WHERE sp.id = $2
		   AND sp.tenant_id = $1
		   AND u.status = 'active'
		   AND u.deleted_at IS NULL
		   AND (
		     u.id = sp.owner_id
		     OR EXISTS (
		       SELECT 1 FROM ace a
		        WHERE a.object_type = 'space'
		          AND a.object_id = sp.id
		          AND a.preset = 'owner'
		          AND (
		            (a.subject_type = 'user'  AND a.subject_id = u.id)
		            OR (a.subject_type = 'dept'  AND EXISTS (
		                  SELECT 1 FROM dept d
		                   WHERE d.id = a.subject_id
		                     AND d.path @> (SELECT path FROM dept WHERE id = u.dept_id)))
		            OR (a.subject_type = 'role'  AND EXISTS (
		                  SELECT 1 FROM user_role ur WHERE ur.user_id = u.id AND ur.role_id = a.subject_id))
		            OR (a.subject_type = 'group' AND EXISTS (
		                  SELECT 1 FROM group_member gm WHERE gm.user_id = u.id AND gm.group_id = a.subject_id))
		          )
		     )
		   )
		 ORDER BY (u.id = sp.owner_id) DESC,
		          lower(COALESCE(NULLIF(u.display_name, ''), u.username))`,
		tenantID, spaceID)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()

	var (
		out     []shareApprover
		creator bool
	)
	for rows.Next() {
		var (
			o         shareApprover
			isPrimary bool
		)
		if err := rows.Scan(&o.ID, &o.Name, &o.Username, &o.Classification, &isPrimary); err != nil {
			return nil, false, err
		}
		o.IsOwner = true
		o.Eligible = true
		out = append(out, o)
		if o.ID == creatorID {
			creator = true
		}
	}
	if err := rows.Err(); err != nil {
		return nil, false, err
	}
	return out, creator, nil
}

// findApprover 在名单里按 id 找一个人；用于把落库的指派关系还原成可读姓名。
func findApprover(list []shareApprover, id string) *shareApprover {
	if id == "" {
		return nil
	}
	for i := range list {
		if list[i].ID == id {
			return &list[i]
		}
	}
	return nil
}
