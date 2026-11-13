package httpapi

import (
	"context"
	"net/http"
	"testing"
)

// 外发审批的待办列表必须只包含「有处置权且不是发起人」的链接。
//
// 缺陷原状：审批只有 POST /shares/{id}/approve 一个接口，没有任何地方
// 能列出 pending 的链接。发起人看到"审批中"，而所有有权审批的人
// 根本不知道有这件事——审批功能事实上停摆，只能靠人手工调接口。
func TestPendingShareApprovalsOnlyForAuthorizedApprovers(t *testing.T) {
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

	resp, sh := postJSON(t, srv.URL+"/v1/shares", owner,
		map[string]any{"objectType": "node", "objectId": nodeID, "allowDownload": true})
	if resp.StatusCode != 200 {
		t.Fatalf("创建外链失败 %d: %v", resp.StatusCode, sh)
	}
	if got, _ := dataMap(t, sh)["approvalStatus"].(string); got != "pending" {
		t.Fatalf("密级 3 应自动进入待审批，实际 %q", got)
	}
	shareID := dataMap(t, sh)["shareId"].(string)
	token := dataMap(t, sh)["token"].(string)

	// 建链时就要告诉发起人"有没有人能批"：此时租户里只有他能管理该空间，
	// 所以是 0。少了这个字段，发起人会一直等一个永远不会发生的审批。
	if n, ok := dataMap(t, sh)["approverCount"]; !ok || n.(float64) != 0 {
		t.Fatalf("此时应汇报 0 个可审批人，实际 %v", dataMap(t, sh)["approverCount"])
	}

	// 1) 发起人自己的待办里不该出现自己的链接（他不能自批）
	_, list := getJSON(t, srv.URL+"/v1/shares/pending", owner)
	if n := len(dataMap(t, list)["items"].([]any)); n != 0 {
		t.Fatalf("发起人不应看到自己的待办，实际 %d 条", n)
	}

	// 2) 只有 display 的人看不到：列出却点不动比看不到更糟
	seedUser(t, srv.URL, slug, "only-viewer")
	grantBits(t, pool, tenantID, "node", nodeID, userIDByName(t, slug, "only-viewer"), 1<<0)
	viewerTok := loginAs(t, srv.URL, slug, "only-viewer")
	_, list = getJSON(t, srv.URL+"/v1/shares/pending", viewerTok)
	if n := len(dataMap(t, list)["items"].([]any)); n != 0 {
		t.Fatalf("无管理权限者不应看到待办，实际 %d 条", n)
	}

	// 3) 有 manage_acl 的人能看到
	seedUser(t, srv.URL, slug, "approver")
	grantBits(t, pool, tenantID, "node", nodeID, userIDByName(t, slug, "approver"), 1<<13)
	// 审批人还必须密级够高：密级先于权限，看不到的文件不可能审批
	if _, err := pool.Exec(ctx, `UPDATE app_user SET classification = 6 WHERE username = 'approver'`); err != nil {
		t.Fatal(err)
	}
	appTok := loginAs(t, srv.URL, slug, "approver")

	// 有了可审批人之后，新建的链接应汇报 1
	_, sh2 := postJSON(t, srv.URL+"/v1/shares", owner,
		map[string]any{"objectType": "node", "objectId": nodeID})
	if n := dataMap(t, sh2)["approverCount"]; n == nil || n.(float64) != 1 {
		t.Fatalf("授权后应汇报 1 个可审批人，实际 %v", n)
	}

	_, list = getJSON(t, srv.URL+"/v1/shares/pending", appTok)
	items := dataMap(t, list)["items"].([]any)
	if len(items) != 2 {
		t.Fatalf("有管理权限者应看到 2 条待办，实际 %d 条", len(items))
	}
	first := items[0].(map[string]any)
	if first["shareId"] != shareID || first["name"] != "需要审批的函.docx" || first["creator"] == "" {
		t.Fatalf("待办条目信息不完整：%v", first)
	}

	// 4) 审批通过后：待办清空，链接可用
	resp, out := postJSON(t, srv.URL+"/v1/shares/"+shareID+"/approve", appTok,
		map[string]any{"approve": true})
	if resp.StatusCode != 200 {
		t.Fatalf("审批失败 %d: %v", resp.StatusCode, out)
	}
	_, list = getJSON(t, srv.URL+"/v1/shares/pending", appTok)
	if n := len(dataMap(t, list)["items"].([]any)); n != 1 {
		t.Fatalf("审批一条后应剩 1 条待办，实际 %d 条", n)
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

	_, sh := postJSON(t, srv.URL+"/v1/shares", owner,
		map[string]any{"objectType": "node", "objectId": nodeID})
	shareID := dataMap(t, sh)["shareId"].(string)
	token := dataMap(t, sh)["token"].(string)

	seedUser(t, srv.URL, slug, "rejector")
	grantBits(t, pool, tenantID, "node", nodeID, userIDByName(t, slug, "rejector"), 1<<13)
	if _, err := pool.Exec(ctx, `UPDATE app_user SET classification = 6 WHERE username = 'rejector'`); err != nil {
		t.Fatal(err)
	}
	rejTok := loginAs(t, srv.URL, slug, "rejector")

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
