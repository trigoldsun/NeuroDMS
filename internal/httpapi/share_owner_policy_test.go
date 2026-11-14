package httpapi

// 「外发需空间所有者确认」改为按密级配置后的用例。
//
// 旧规则写死 5/6 级；现在由安全管理员在「密级定义」页逐级勾选。
// 这一组守住两件容易做错的事：
//  1. 配置真的生效——低密级可以要求所有者确认，高密级也可以关掉；
//  2. 老分享按创建时的快照执行，不会被后来的规则变更回头修改。

import (
	"context"
	"net/http"
	"testing"

	"docvault/internal/rbac"
)

// setOwnerApproval 通过 HTTP 接口改某密级的「外发需所有者确认」开关。
//
// 刻意走接口而不是直接 UPDATE：这条路径顺带验证了"谁能改"（secadmin）
// 与"改完立刻生效"（下一次 plan 计算就该看到新值）。
func setOwnerApproval(t *testing.T, srvURL, secTok string, level int, on bool) {
	t.Helper()
	resp, out := sendJSONMap(t, http.MethodPut, srvURL+"/v1/admin/classifications/"+itoaSmall(level), secTok,
		map[string]any{"name": "级别" + itoaSmall(level), "description": "用例", "ownerApproval": on})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("设置 %d 级所有者确认=%v 失败 %d: %v", level, on, resp.StatusCode, out)
	}
	if got, _ := dataMap(t, out)["ownerApproval"].(bool); got != on {
		t.Fatalf("%d 级开关未生效，期望 %v 实际 %v", level, on, got)
	}
}

// 低密级也能要求所有者确认；关掉之后新链接不再要求第二层。
//
// 同时验证"老分享老政策"：先按开启时创建的那条，在开关关闭后
// 第一层通过仍然会转给所有者，而不是被新规则"放行"。
func TestOwnerApprovalConfiguredPerLevel(t *testing.T) {
	srv, pool, slug := setup(t)
	tenantID := tenantOf(t, pool, slug)
	ctx := context.Background()

	// 安全管理员：负责改密级策略
	sec := seedUser(t, srv.URL, slug, "polsec")
	seedRole(t, pool, tenantID, userIDByName(t, slug, "polsec"), rbac.SecAdmin)

	owner := login(t, srv.URL, slug) // bob，空间所有者，密级 6
	if _, err := pool.Exec(ctx,
		`UPDATE app_user SET classification = 6 WHERE tenant_id = $1 AND username = 'bob'`, tenantID); err != nil {
		t.Fatal(err)
	}
	_, body := postJSON(t, srv.URL+"/v1/spaces", owner,
		map[string]any{"kind": "project", "name": "密级策略空间"})
	spaceID := dataMap(t, body)["spaceId"].(string)
	_, up := upload(t, srv.URL+"/v1/spaces/"+spaceID+"/files", owner, "策略.pdf", "policy-needle")
	nodeID := dataMap(t, up)["nodeId"].(string)
	// 4 级：缺省不要求所有者确认（缺省起算 5 级），用来验证"可以打开"
	if _, err := pool.Exec(ctx, `UPDATE node SET classification = 4 WHERE id = $1`, nodeID); err != nil {
		t.Fatal(err)
	}
	bobID := userIDByName(t, slug, "bob")

	// uploader：有外发权但不是空间所有者，第二层才有意义
	seedUser(t, srv.URL, slug, "poluploader")
	uploaderID := userIDByName(t, slug, "poluploader")
	grantBits(t, pool, tenantID, "node", nodeID, uploaderID, 1|1<<11)
	setUserClass(t, pool, uploaderID, 6)

	// approver：有管理权、密级足够
	seedUser(t, srv.URL, slug, "polapprover")
	approverID := userIDByName(t, slug, "polapprover")
	grantBits(t, pool, tenantID, "node", nodeID, approverID, 1<<13)
	setUserClass(t, pool, approverID, 6)

	uploaderTok := loginAs(t, srv.URL, slug, "poluploader")
	approverTok := loginAs(t, srv.URL, slug, "polapprover")

	// ---------- 1) 缺省：4 级不要求所有者确认 ----------
	_, plan := getJSON(t, srv.URL+"/v1/shares/approvers?objectType=node&objectId="+nodeID, uploaderTok)
	if pm := dataMap(t, plan); pm["twoLayer"] != false {
		t.Fatalf("4 级缺省不应要求所有者确认，实际 %v", pm["twoLayer"])
	}

	// ---------- 2) 打开 4 级的开关 ----------
	setOwnerApproval(t, srv.URL, sec, 4, true)
	_, plan = getJSON(t, srv.URL+"/v1/shares/approvers?objectType=node&objectId="+nodeID, uploaderTok)
	pm := dataMap(t, plan)
	if pm["twoLayer"] != true || pm["ownerApproval"] != true {
		t.Fatalf("打开后 4 级应要求所有者确认，实际 %v", pm)
	}
	owners := pm["owners"].([]any)
	if len(owners) != 1 || owners[0].(map[string]any)["id"] != bobID {
		t.Fatalf("所有者候选应只有 bob，实际 %v", owners)
	}

	// 只给第一层、不给所有者：拒绝
	resp, out := postJSON(t, srv.URL+"/v1/shares", uploaderTok, map[string]any{
		"objectType": "node", "objectId": nodeID, "approverId": approverID,
	})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("缺少所有者审批人应 400，实际 %d: %v", resp.StatusCode, out)
	}

	// 两层一次性选定，得到一条"老分享"
	resp, sh := postJSON(t, srv.URL+"/v1/shares", uploaderTok, map[string]any{
		"objectType": "node", "objectId": nodeID,
		"approverId": approverID, "ownerApproverId": bobID,
	})
	if resp.StatusCode != 200 {
		t.Fatalf("创建失败 %d: %v", resp.StatusCode, sh)
	}
	oldShareID := dataMap(t, sh)["shareId"].(string)

	// ---------- 3) 关掉开关：新分享不再要求二层 ----------
	setOwnerApproval(t, srv.URL, sec, 4, false)
	_, plan = getJSON(t, srv.URL+"/v1/shares/approvers?objectType=node&objectId="+nodeID, uploaderTok)
	if pm := dataMap(t, plan); pm["twoLayer"] != false {
		t.Fatalf("关闭后 4 级不应再要求所有者确认，实际 %v", pm)
	}

	resp, sh = postJSON(t, srv.URL+"/v1/shares", uploaderTok, map[string]any{
		"objectType": "node", "objectId": nodeID, "approverId": approverID,
	})
	if resp.StatusCode != 200 {
		t.Fatalf("关闭后创建不应再要求所有者，实际 %d: %v", resp.StatusCode, sh)
	}
	newShareID := dataMap(t, sh)["shareId"].(string)

	// 新分享：第一层通过即结束
	resp, out = postJSON(t, srv.URL+"/v1/shares/"+newShareID+"/approve", approverTok,
		map[string]any{"approve": true})
	if resp.StatusCode != 200 {
		t.Fatalf("新分享审批失败 %d: %v", resp.StatusCode, out)
	}
	if dataMap(t, out)["approvalStatus"] != "approved" {
		t.Fatalf("关闭后新分享应一层通过，实际 %v", dataMap(t, out))
	}

	// ---------- 4) 老分享：仍按创建时的两层走 ----------
	resp, out = postJSON(t, srv.URL+"/v1/shares/"+oldShareID+"/approve", approverTok,
		map[string]any{"approve": true})
	if resp.StatusCode != 200 {
		t.Fatalf("老分享第一层审批失败 %d: %v", resp.StatusCode, out)
	}
	if dataMap(t, out)["ownerPending"] != true {
		t.Fatalf("规则变更不应放行已发起的分享，仍应等待所有者，实际 %v", dataMap(t, out))
	}
}

// 「需所有者确认」本身也意味着必须审批：即使密级低于租户的审批阈值。
//
// 否则会出现"要所有者确认、却没有第一层审批"的自相矛盾状态——
// 界面上没有任何人能批，链接永远停在 pending。
func TestOwnerApprovalImpliesApproval(t *testing.T) {
	srv, pool, slug := setup(t)
	tenantID := tenantOf(t, pool, slug)
	ctx := context.Background()

	sec := seedUser(t, srv.URL, slug, "implsec")
	seedRole(t, pool, tenantID, userIDByName(t, slug, "implsec"), rbac.SecAdmin)

	owner := login(t, srv.URL, slug)
	if _, err := pool.Exec(ctx,
		`UPDATE app_user SET classification = 6 WHERE tenant_id = $1 AND username = 'bob'`, tenantID); err != nil {
		t.Fatal(err)
	}
	// 把"必须审批"的阈值抬到 6 级，让 2 级文件本身不触发审批
	if _, err := pool.Exec(ctx,
		`UPDATE tenant SET share_approval_min_class = 6 WHERE id = $1`, tenantID); err != nil {
		t.Fatal(err)
	}

	_, body := postJSON(t, srv.URL+"/v1/spaces", owner,
		map[string]any{"kind": "project", "name": "并集空间"})
	spaceID := dataMap(t, body)["spaceId"].(string)
	_, up := upload(t, srv.URL+"/v1/spaces/"+spaceID+"/files", owner, "普通.docx", "impl-needle")
	nodeID := dataMap(t, up)["nodeId"].(string)
	if _, err := pool.Exec(ctx, `UPDATE node SET classification = 2 WHERE id = $1`, nodeID); err != nil {
		t.Fatal(err)
	}

	_, plan := getJSON(t, srv.URL+"/v1/shares/approvers?objectType=node&objectId="+nodeID, owner)
	pm := dataMap(t, plan)
	if pm["requireApproval"] != false {
		t.Fatalf("2 级低于阈值且未开所有者确认时应免审批，实际 %v", pm)
	}

	setOwnerApproval(t, srv.URL, sec, 2, true)
	_, plan = getJSON(t, srv.URL+"/v1/shares/approvers?objectType=node&objectId="+nodeID, owner)
	pm = dataMap(t, plan)
	if pm["requireApproval"] != true {
		t.Fatalf("开启所有者确认后即使低于阈值也必须审批，实际 %v", pm)
	}
	if pm["reason"] != "owner_policy" {
		t.Fatalf("原因应标记为 owner_policy，实际 %v", pm["reason"])
	}
}
