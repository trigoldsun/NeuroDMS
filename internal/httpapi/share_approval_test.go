package httpapi

import (
	"context"
	"net/http"
	"testing"
)

// 外发审批：发起人指定审批人，且只让被指定的人看到待办。
//
// 旧行为是"任何对该对象有 manage_acl 的人都能批"，没有指派关系：
// 发起人不知道在等谁，多个管理者之间也会互相以为对方会批。
// 新行为把"谁批"变成创建时的一次明确选择，并把选择结果落库。
func TestPendingShareApprovalsOnlyForDesignatedApprover(t *testing.T) {
	srv, pool, slug := setup(t)
	tenantID := tenantOf(t, pool, slug)
	ctx := context.Background()
	// 发起人的密级必须够高：密级 3 的文件对密级 0 的账号不可见，
	// 否则连"创建分享"都会 404——这不是本用例要测的东西。
	if _, err := pool.Exec(ctx,
		`UPDATE app_user SET classification = 6 WHERE tenant_id = $1 AND username = 'bob'`, tenantID); err != nil {
		t.Fatal(err)
	}
	owner := login(t, srv.URL, slug)

	_, body := postJSON(t, srv.URL+"/v1/spaces", owner,
		map[string]any{"kind": "project", "name": "审批待办"})
	spaceID := dataMap(t, body)["spaceId"].(string)

	resp, up := upload(t, srv.URL+"/v1/spaces/"+spaceID+"/files", owner,
		"需要审批的函.docx", "approval-needle")
	if resp.StatusCode != 200 {
		t.Fatalf("上传失败 %d: %v", resp.StatusCode, up)
	}
	nodeID := dataMap(t, up)["nodeId"].(string)

	// 密级提到阈值（默认 3 = 秘密），触发按密级的自动审批
	if _, err := pool.Exec(ctx, `UPDATE node SET classification = 3 WHERE id = $1`, nodeID); err != nil {
		t.Fatal(err)
	}

	// 1) 没有其他可审批人时，不允许建链。
	//    旧实现会建出一条永远 pending 的链接，发起人以为"等审批就行"，
	//    实际上租户里没人能批。现在在创建时就拒绝，并说明怎么修。
	resp, out := postJSON(t, srv.URL+"/v1/shares", owner,
		map[string]any{"objectType": "node", "objectId": nodeID, "allowDownload": true})
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("无人可批时应 409，实际 %d: %v", resp.StatusCode, out)
	}
	if code, _ := out["code"].(string); code != "NO_ELIGIBLE_APPROVER" {
		t.Fatalf("应返回 NO_ELIGIBLE_APPROVER，实际 %q", code)
	}

	// 候选名单此时为空
	_, plan := getJSON(t, srv.URL+"/v1/shares/approvers?objectType=node&objectId="+nodeID, owner)
	pm := dataMap(t, plan)
	if n := len(pm["approvers"].([]any)); n != 0 {
		t.Fatalf("此时不应有可审批人，实际 %d 个", n)
	}
	if pm["requireApproval"] != true {
		t.Fatalf("密级 3 应要求审批，实际 %v", pm["requireApproval"])
	}

	// 2) 造两个都有管理权限、密级足够的人；只有被指定的那个能收到待办。
	for _, u := range []string{"approver", "backup-approver"} {
		seedUser(t, srv.URL, slug, u)
		grantBits(t, pool, tenantID, "node", nodeID, userIDByName(t, slug, u), 1<<13)
		if _, err := pool.Exec(ctx, `UPDATE app_user SET classification = 6 WHERE username = $1`, u); err != nil {
			t.Fatal(err)
		}
	}
	approverID := userIDByName(t, slug, "approver")
	appTok := loginAs(t, srv.URL, slug, "approver")
	backupTok := loginAs(t, srv.URL, slug, "backup-approver")

	_, plan = getJSON(t, srv.URL+"/v1/shares/approvers?objectType=node&objectId="+nodeID, owner)
	pm = dataMap(t, plan)
	approvers := pm["approvers"].([]any)
	if len(approvers) != 2 {
		t.Fatalf("应有 2 个候选审批人，实际 %d", len(approvers))
	}
	if n := len(pm["owners"].([]any)); n != 0 {
		// 发起人就是空间所有者，第二层候选里不应再出现他自己
		t.Fatalf("所有者候选应排除发起人，实际 %d 个", n)
	}

	// 3) 未选择审批人 / 选了不符合条件的人，都应被拒
	resp, out = postJSON(t, srv.URL+"/v1/shares", owner,
		map[string]any{"objectType": "node", "objectId": nodeID})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("未选审批人应 400，实际 %d: %v", resp.StatusCode, out)
	}
	resp, _ = postJSON(t, srv.URL+"/v1/shares", owner,
		map[string]any{"objectType": "node", "objectId": nodeID, "approverId": "00000000-0000-0000-0000-000000000001"})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("无效审批人应 400，实际 %d", resp.StatusCode)
	}

	// 4) 指定 approver 后建链成功，响应里带回"在等谁"
	resp, sh := postJSON(t, srv.URL+"/v1/shares", owner,
		map[string]any{"objectType": "node", "objectId": nodeID, "approverId": approverID})
	if resp.StatusCode != 200 {
		t.Fatalf("创建外链失败 %d: %v", resp.StatusCode, sh)
	}
	d := dataMap(t, sh)
	if got, _ := d["approvalStatus"].(string); got != "pending" {
		t.Fatalf("应进入待审批，实际 %q", got)
	}
	if a, ok := d["approver"].(map[string]any); !ok || a["name"] == "" {
		t.Fatalf("响应应带指派的审批人，实际 %v", d["approver"])
	}
	shareID := d["shareId"].(string)
	token := d["token"].(string)

	// 5) 发起人、未被指定的人都不该看到；被指定的人看到 1 条
	_, list := getJSON(t, srv.URL+"/v1/shares/pending", owner)
	if n := len(dataMap(t, list)["items"].([]any)); n != 0 {
		t.Fatalf("发起人不应看到自己的待办，实际 %d 条", n)
	}
	_, list = getJSON(t, srv.URL+"/v1/shares/pending", backupTok)
	if n := len(dataMap(t, list)["items"].([]any)); n != 0 {
		t.Fatalf("未被指定的人不应看到待办，实际 %d 条", n)
	}
	_, list = getJSON(t, srv.URL+"/v1/shares/pending", appTok)
	items := dataMap(t, list)["items"].([]any)
	if len(items) != 1 {
		t.Fatalf("被指定的人应看到 1 条待办，实际 %d 条", len(items))
	}
	if items[0].(map[string]any)["stage"] != "first" {
		t.Fatalf("待办应处于第一层，实际 %v", items[0])
	}

	// 6) 未被指定的人即使有 manage_acl 也不能代批
	resp, _ = postJSON(t, srv.URL+"/v1/shares/"+shareID+"/approve", backupTok,
		map[string]any{"approve": true})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("非指定审批人应 403，实际 %d", resp.StatusCode)
	}

	// 7) 指定审批人通过后：待办清空，链接可用
	resp, out = postJSON(t, srv.URL+"/v1/shares/"+shareID+"/approve", appTok,
		map[string]any{"approve": true})
	if resp.StatusCode != 200 {
		t.Fatalf("审批失败 %d: %v", resp.StatusCode, out)
	}
	if dataMap(t, out)["approvalStatus"] != "approved" {
		t.Fatalf("应已通过，实际 %v", dataMap(t, out))
	}
	_, list = getJSON(t, srv.URL+"/v1/shares/pending", appTok)
	if n := len(dataMap(t, list)["items"].([]any)); n != 0 {
		t.Fatalf("审批后待办应清空，实际 %d 条", n)
	}
	resp, rd := getJSON(t, srv.URL+"/v1/public/shares/"+token, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("审批通过后链接应可用，实际 %d: %v", resp.StatusCode, rd)
	}
}

// 驳回后链接不可用，且不再出现在待办里。
func TestRejectedShareLeavesPendingList(t *testing.T) {
	srv, pool, slug := setup(t)
	tenantID := tenantOf(t, pool, slug)
	ctx := context.Background()
	if _, err := pool.Exec(ctx,
		`UPDATE app_user SET classification = 6 WHERE tenant_id = $1 AND username = 'bob'`, tenantID); err != nil {
		t.Fatal(err)
	}
	owner := login(t, srv.URL, slug)

	_, body := postJSON(t, srv.URL+"/v1/spaces", owner,
		map[string]any{"kind": "project", "name": "驳回测试"})
	spaceID := dataMap(t, body)["spaceId"].(string)
	_, up := upload(t, srv.URL+"/v1/spaces/"+spaceID+"/files", owner, "reject.docx", "reject-me")
	nodeID := dataMap(t, up)["nodeId"].(string)
	if _, err := pool.Exec(ctx, `UPDATE node SET classification = 4 WHERE id = $1`, nodeID); err != nil {
		t.Fatal(err)
	}

	seedUser(t, srv.URL, slug, "rejector")
	grantBits(t, pool, tenantID, "node", nodeID, userIDByName(t, slug, "rejector"), 1<<13)
	if _, err := pool.Exec(ctx, `UPDATE app_user SET classification = 6 WHERE username = 'rejector'`); err != nil {
		t.Fatal(err)
	}
	rejTok := loginAs(t, srv.URL, slug, "rejector")

	_, sh := postJSON(t, srv.URL+"/v1/shares", owner, map[string]any{
		"objectType": "node", "objectId": nodeID,
		"approverId": userIDByName(t, slug, "rejector"),
	})
	shareID := dataMap(t, sh)["shareId"].(string)
	token := dataMap(t, sh)["token"].(string)

	if resp, _ := postJSON(t, srv.URL+"/v1/shares/"+shareID+"/approve", rejTok,
		map[string]any{"approve": false}); resp.StatusCode != 200 {
		t.Fatalf("驳回失败 %d", resp.StatusCode)
	}
	_, list := getJSON(t, srv.URL+"/v1/shares/pending", rejTok)
	if n := len(dataMap(t, list)["items"].([]any)); n != 0 {
		t.Fatalf("驳回后待办应清空，实际 %d 条", n)
	}
	resp, rd := getJSON(t, srv.URL+"/v1/public/shares/"+token, "")
	if resp.StatusCode == http.StatusOK {
		t.Fatal("驳回后链接不应可用")
	}
	_ = rd
}

// 5/6 级：第一层审批人不是空间所有者时，再加一层所有者确认。
//
// 这条是"防止审批人绕过所有者"的关键：高密文件外发，所有者必须知道。
// 两层在同一次创建里选定，避免审批到一半才发现没人能批。
func TestHighClassificationShareRequiresOwnerApproval(t *testing.T) {
	srv, pool, slug := setup(t)
	tenantID := tenantOf(t, pool, slug)
	ctx := context.Background()
	owner := login(t, srv.URL, slug) // bob 是空间所有者
	if _, err := pool.Exec(ctx,
		`UPDATE app_user SET classification = 6 WHERE tenant_id = $1 AND username = 'bob'`, tenantID); err != nil {
		t.Fatal(err)
	}

	_, body := postJSON(t, srv.URL+"/v1/spaces", owner,
		map[string]any{"kind": "project", "name": "高密外发"})
	spaceID := dataMap(t, body)["spaceId"].(string)
	_, up := upload(t, srv.URL+"/v1/spaces/"+spaceID+"/files", owner, "并购方案.docx", "top-secret")
	nodeID := dataMap(t, up)["nodeId"].(string)
	if _, err := pool.Exec(ctx, `UPDATE node SET classification = 5 WHERE id = $1`, nodeID); err != nil {
		t.Fatal(err)
	}
	bobID := userIDByName(t, slug, "bob")

	// uploader 有外发权但不是所有者；approver 有管理权但不是所有者。
	seedUser(t, srv.URL, slug, "uploader")
	uploaderID := userIDByName(t, slug, "uploader")
	grantBits(t, pool, tenantID, "node", nodeID, uploaderID, 1|1<<11)
	setUserClass(t, pool, uploaderID, 6)

	seedUser(t, srv.URL, slug, "owner-approver")
	approverID := userIDByName(t, slug, "owner-approver")
	grantBits(t, pool, tenantID, "node", nodeID, approverID, 1<<13)
	setUserClass(t, pool, approverID, 6)

	uploaderTok := loginAs(t, srv.URL, slug, "uploader")
	approverTok := loginAs(t, srv.URL, slug, "owner-approver")

	// 候选名单应说明：需要两层，且所有者候选是 bob
	_, plan := getJSON(t, srv.URL+"/v1/shares/approvers?objectType=node&objectId="+nodeID, uploaderTok)
	pm := dataMap(t, plan)
	if pm["twoLayer"] != true || pm["requireApproval"] != true {
		t.Fatalf("5 级应要求两层审批，实际 %v", pm)
	}
	owners := pm["owners"].([]any)
	if len(owners) != 1 || owners[0].(map[string]any)["id"] != bobID {
		t.Fatalf("所有者候选应只有 bob，实际 %v", owners)
	}

	// 只给第一层审批人、不给所有者：应被拒
	resp, out := postJSON(t, srv.URL+"/v1/shares", uploaderTok, map[string]any{
		"objectType": "node", "objectId": nodeID, "approverId": approverID,
	})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("缺少所有者审批人应 400，实际 %d: %v", resp.StatusCode, out)
	}

	// 两层一次性选定
	resp, sh := postJSON(t, srv.URL+"/v1/shares", uploaderTok, map[string]any{
		"objectType": "node", "objectId": nodeID,
		"approverId": approverID, "ownerApproverId": bobID,
	})
	if resp.StatusCode != 200 {
		t.Fatalf("创建失败 %d: %v", resp.StatusCode, sh)
	}
	d := dataMap(t, sh)
	shareID := d["shareId"].(string)
	token := d["token"].(string)
	if d["approvalStage"] != "first" {
		t.Fatalf("初始应在第一层，实际 %v", d["approvalStage"])
	}

	// 第一层通过后，链接仍不可用；所有者待办才出现
	resp, out = postJSON(t, srv.URL+"/v1/shares/"+shareID+"/approve", approverTok,
		map[string]any{"approve": true})
	if resp.StatusCode != 200 {
		t.Fatalf("第一层审批失败 %d: %v", resp.StatusCode, out)
	}
	if dataMap(t, out)["ownerPending"] != true {
		t.Fatalf("第一层通过后应等待所有者，实际 %v", dataMap(t, out))
	}
	if resp, _ := getJSON(t, srv.URL+"/v1/public/shares/"+token, ""); resp.StatusCode == 200 {
		t.Fatal("两层未走完，链接不应可用")
	}
	_, list := getJSON(t, srv.URL+"/v1/shares/pending", approverTok)
	if n := len(dataMap(t, list)["items"].([]any)); n != 0 {
		t.Fatalf("第一层完成后，第一层审批人不应再有该待办，实际 %d", n)
	}
	_, list = getJSON(t, srv.URL+"/v1/shares/pending", owner)
	items := dataMap(t, list)["items"].([]any)
	if len(items) != 1 || items[0].(map[string]any)["stage"] != "owner" {
		t.Fatalf("所有者应看到第二层待办，实际 %v", items)
	}

	// 第一层审批人不能替所有者点通过
	resp, _ = postJSON(t, srv.URL+"/v1/shares/"+shareID+"/approve", approverTok,
		map[string]any{"approve": true})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("非指定所有者应 403，实际 %d", resp.StatusCode)
	}

	// 所有者通过后链接可用
	resp, out = postJSON(t, srv.URL+"/v1/shares/"+shareID+"/approve", owner,
		map[string]any{"approve": true})
	if resp.StatusCode != 200 {
		t.Fatalf("所有者审批失败 %d: %v", resp.StatusCode, out)
	}
	resp, rd := getJSON(t, srv.URL+"/v1/public/shares/"+token, "")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("两层通过后链接应可用，实际 %d: %v", resp.StatusCode, rd)
	}
}
