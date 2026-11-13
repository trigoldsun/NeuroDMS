package httpapi

// M2-C 密级体系用例。
//
// 这一组里有两条是"回归型"用例，价值最高：
//   - 密级门必须走 HTTP 路径生效（引擎级通过但 HTTP 没接 Class，是曾经的真实缺陷）
//   - 标签只能收紧权限，不能成为绕过 ACE 的第二条授权通道

import (
	"bytes"
	"context"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"testing"

	"docvault/internal/rbac"

	"github.com/jackc/pgx/v5/pgxpool"
)

// uploadClass 带密级字段上传。
func uploadClass(t *testing.T, url, token, filename, content string, class int) (*http.Response, map[string]any) {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, err := mw.CreateFormFile("file", filename)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = fw.Write([]byte(content))
	if class >= 0 {
		_ = mw.WriteField("classification", itoaSmall(class))
	}
	_ = mw.Close()

	req, _ := http.NewRequest(http.MethodPost, url, &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("上传请求失败: %v", err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp, out
}

func itoaSmall(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

func setUserClass(t *testing.T, pool *pgxpool.Pool, userID string, class int) {
	t.Helper()
	if _, err := pool.Exec(context.Background(),
		`UPDATE app_user SET classification = $2 WHERE id = $1`, userID, class); err != nil {
		t.Fatalf("设置用户密级失败: %v", err)
	}
}

// 密级门必须在 HTTP 路径上生效：连对象所有者拿着全部权限位也过不去。
func TestClassGateBlocksDownloadEvenForOwner(t *testing.T) {
	srv, pool, slug := setup(t)
	owner := login(t, srv.URL, slug)
	spaceID, nodeID := prepareFile(t, srv.URL, owner)

	// 文件定为 3 级，而所有者自身只有 1 级
	if _, err := pool.Exec(context.Background(),
		`UPDATE node SET classification = 3 WHERE id = $1`, nodeID); err != nil {
		t.Fatal(err)
	}
	setUserClass(t, pool, userIDByName(t, slug, "bob"), 1)

	resp, raw := getRaw(t, srv.URL+"/v1/nodes/"+nodeID+"/content", owner)
	if resp.StatusCode == 200 {
		t.Fatalf("密级不足时不应能下载，实际 200（说明密级未进入判定）")
	}
	assertNoLeak(t, raw, "敏感内容")

	// 提升到 3 级后应恢复（证明拒绝确实来自密级，而不是别的环节）
	setUserClass(t, pool, userIDByName(t, slug, "bob"), 3)
	if r, raw := getRaw(t, srv.URL+"/v1/nodes/"+nodeID+"/content", owner); r.StatusCode != 200 {
		t.Fatalf("密级满足后应可下载，实际 %d: %s", r.StatusCode, raw)
	}
	_ = spaceID
}

// AC-41：上传时自定密级不得高于自身密级，且被拒后不得留下文件。
func TestAC41UploadClassificationAboveSelfRejected(t *testing.T) {
	srv, pool, slug := setup(t)
	owner := login(t, srv.URL, slug)
	setUserClass(t, pool, userIDByName(t, slug, "bob"), 1)

	_, body := postJSON(t, srv.URL+"/v1/spaces", owner, map[string]any{"kind": "project", "name": "密级空间"})
	spaceID := dataMap(t, body)["spaceId"].(string)

	resp, out := uploadClass(t, srv.URL+"/v1/spaces/"+spaceID+"/files", owner, "secret.txt", "机密内容", 5)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("AC-41 密级高于自身应 403，实际 %d: %v", resp.StatusCode, out)
	}
	if out["code"] != "ABOVE_SELF" {
		t.Fatalf("AC-41 应返回 ABOVE_SELF: %v", out)
	}

	// 反向确认：列表里没有这个文件（不能"报错但已落盘"）
	_, list := getJSON(t, srv.URL+"/v1/spaces/"+spaceID+"/nodes", owner)
	items, _ := dataMap(t, list)["items"].([]any)
	if len(items) != 0 {
		t.Fatalf("AC-41 被拒后不应留下文件，实际 %d 个", len(items))
	}

	// 合法范围内的密级可以设置
	if r, o := uploadClass(t, srv.URL+"/v1/spaces/"+spaceID+"/files", owner, "ok.txt", "内部内容", 1); r.StatusCode != 200 {
		t.Fatalf("密级 1 应允许上传，实际 %d: %v", r.StatusCode, o)
	}
	var cls int
	if err := pool.QueryRow(context.Background(),
		`SELECT classification FROM node WHERE space_id=$1 AND name='ok.txt'`, spaceID).Scan(&cls); err != nil {
		t.Fatal(err)
	}
	if cls != 1 {
		t.Fatalf("上传密级未落库，实际 %d", cls)
	}
}

// AC-42：降密必须走申请审批，且申请人不能自批。
func TestAC42DemotionRequiresApproval(t *testing.T) {
	srv, pool, slug := setup(t)
	tenantID := tenantOf(t, pool, slug)
	owner := login(t, srv.URL, slug)
	bobID := userIDByName(t, slug, "bob")
	setUserClass(t, pool, bobID, 4)

	_, body := postJSON(t, srv.URL+"/v1/spaces", owner, map[string]any{"kind": "project", "name": "降密空间"})
	spaceID := dataMap(t, body)["spaceId"].(string)
	_, up := uploadClass(t, srv.URL+"/v1/spaces/"+spaceID+"/files", owner, "plan.txt", "计划内容", 4)
	nodeID := dataMap(t, up)["nodeId"].(string)

	// 直接降密 → 409，要求走申请
	resp, out := sendJSONMap(t, http.MethodPut, srv.URL+"/v1/nodes/"+nodeID+"/classification", owner,
		map[string]any{"level": 1})
	if resp.StatusCode != http.StatusConflict || out["code"] != "NEED_APPROVAL" {
		t.Fatalf("AC-42 直接降密应 409 NEED_APPROVAL，实际 %d: %v", resp.StatusCode, out)
	}

	// 提交申请
	resp, out = sendJSONMap(t, http.MethodPost, srv.URL+"/v1/nodes/"+nodeID+"/classification/requests", owner,
		map[string]any{"toLevel": 1, "reason": "项目已结项，需归档共享"})
	if resp.StatusCode != 200 {
		t.Fatalf("AC-42 提交申请失败 %d: %v", resp.StatusCode, out)
	}
	reqID := dataMap(t, out)["requestId"].(string)

	// 重复提交 → 409（不允许重复冲审批）
	resp, _ = sendJSONMap(t, http.MethodPost, srv.URL+"/v1/nodes/"+nodeID+"/classification/requests", owner,
		map[string]any{"toLevel": 1, "reason": "再提一次"})
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("AC-42 重复申请应 409，实际 %d", resp.StatusCode)
	}

	// 申请人自批 → 403（自审自批是最常见的流程失效）
	setUserClass(t, pool, bobID, 4) // 确保仍是同一人
	seedRole(t, pool, tenantID, bobID, rbac.SecAdmin)
	resp, out = sendJSONMap(t, http.MethodPost,
		srv.URL+"/v1/admin/classification/requests/"+reqID+"/decide", owner,
		map[string]any{"approve": true, "note": "自己批"})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("AC-42 申请人自批应 403，实际 %d: %v", resp.StatusCode, out)
	}

	// 另一名安全管理员审批通过
	approver := seedUser(t, srv.URL, slug, "sec42")
	approverID := userIDByName(t, slug, "sec42")
	seedRole(t, pool, tenantID, approverID, rbac.SecAdmin)
	resp, out = sendJSONMap(t, http.MethodPost,
		srv.URL+"/v1/admin/classification/requests/"+reqID+"/decide", approver,
		map[string]any{"approve": true, "note": "同意归档"})
	if resp.StatusCode != 200 {
		t.Fatalf("AC-42 审批通过失败 %d: %v", resp.StatusCode, out)
	}

	var cls int
	if err := pool.QueryRow(context.Background(),
		`SELECT classification FROM node WHERE id=$1`, nodeID).Scan(&cls); err != nil {
		t.Fatal(err)
	}
	if cls != 1 {
		t.Fatalf("AC-42 审批后密级应为 1，实际 %d", cls)
	}

	// 重复审批 → 409
	resp, _ = sendJSONMap(t, http.MethodPost,
		srv.URL+"/v1/admin/classification/requests/"+reqID+"/decide", approver,
		map[string]any{"approve": true})
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("AC-42 重复审批应 409，实际 %d", resp.StatusCode)
	}
}

// AC-40：只有安全管理员能改密级定义，且等级语义不可改。
func TestAC40OnlySecAdminChangesClassificationLabel(t *testing.T) {
	srv, pool, slug := setup(t)
	tenantID := tenantOf(t, pool, slug)
	bobToken := login(t, srv.URL, slug)
	bobID := userIDByName(t, slug, "bob")

	// 普通用户 → 403
	resp, out := sendJSONMap(t, http.MethodPut, srv.URL+"/v1/admin/classifications/3", bobToken,
		map[string]any{"name": "公开", "description": "试图把秘密改成公开"})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("AC-40 普通用户改密级定义应 403，实际 %d: %v", resp.StatusCode, out)
	}

	// 安全管理员 → 允许改显示名
	seedRole(t, pool, tenantID, bobID, rbac.SecAdmin)
	resp, out = sendJSONMap(t, http.MethodPut, srv.URL+"/v1/admin/classifications/3", bobToken,
		map[string]any{"name": "秘密级", "description": "含商业秘密"})
	if resp.StatusCode != 200 {
		t.Fatalf("AC-40 安全管理员改名失败 %d: %v", resp.StatusCode, out)
	}

	// 等级顺序必须不变：仍是 0..6 共 7 级，且下标与等级一致
	_, list := getJSON(t, srv.URL+"/v1/classifications", bobToken)
	items, _ := dataMap(t, list)["items"].([]any)
	if len(items) != 7 {
		t.Fatalf("AC-40 密级应恒为 7 级，实际 %d", len(items))
	}
	for i, it := range items {
		m := it.(map[string]any)
		if int(m["level"].(float64)) != i {
			t.Fatalf("AC-40 密级顺序被改动: %v", items)
		}
	}
	if items[3].(map[string]any)["name"] != "秘密级" {
		t.Fatalf("AC-40 改名未生效: %v", items[3])
	}
}

// AC-35：标签策略只能收紧密级，不能用来提权。
func TestAC35LabelPolicyOnlyTightens(t *testing.T) {
	srv, pool, slug := setup(t)
	tenantID := tenantOf(t, pool, slug)
	owner := login(t, srv.URL, slug)
	spaceID, nodeID := prepareFile(t, srv.URL, owner)

	// 安全管理员配置：带 restricted 标签的对象最低 4 级
	sec := seedUser(t, srv.URL, slug, "sec35")
	secID := userIDByName(t, slug, "sec35")
	seedRole(t, pool, tenantID, secID, rbac.SecAdmin)
	resp, out := sendJSONMap(t, http.MethodPut, srv.URL+"/v1/admin/label-policies/restricted", sec,
		map[string]any{"minLevel": 4})
	if resp.StatusCode != 200 {
		t.Fatalf("配置标签策略失败 %d: %v", resp.StatusCode, out)
	}

	// 所有者（密级 1）给文件打标签
	setUserClass(t, pool, userIDByName(t, slug, "bob"), 1)
	resp, out = sendJSONMap(t, http.MethodPut, srv.URL+"/v1/nodes/"+nodeID+"/classification", owner,
		map[string]any{"labels": []string{"restricted"}})
	if resp.StatusCode != 200 {
		t.Fatalf("打标签失败 %d: %v", resp.StatusCode, out)
	}

	// 打完标签后连所有者自己都读不到正文：标签只收紧，不放大
	if r, raw := getRaw(t, srv.URL+"/v1/nodes/"+nodeID+"/content", owner); r.StatusCode == 200 {
		t.Fatalf("AC-35 标签收紧后不应能下载: %s", raw)
	}

	// 密级提升到 4 后恢复
	setUserClass(t, pool, userIDByName(t, slug, "bob"), 4)
	if r, raw := getRaw(t, srv.URL+"/v1/nodes/"+nodeID+"/content", owner); r.StatusCode != 200 {
		t.Fatalf("AC-35 密级满足后应可下载，实际 %d: %s", r.StatusCode, raw)
	}
	_ = spaceID
}

// AC-43：达到阈值的对象创建外发链接必须进审批，且审批前不可用。
func TestAC43ShareOfClassifiedObjectRequiresApproval(t *testing.T) {
	srv, pool, slug := setup(t)
	owner := login(t, srv.URL, slug)
	bobID := userIDByName(t, slug, "bob")
	setUserClass(t, pool, bobID, 4)

	_, body := postJSON(t, srv.URL+"/v1/spaces", owner, map[string]any{"kind": "project", "name": "外发空间"})
	spaceID := dataMap(t, body)["spaceId"].(string)
	_, up := uploadClass(t, srv.URL+"/v1/spaces/"+spaceID+"/files", owner, "contract.txt", "合同正文", 3)
	nodeID := dataMap(t, up)["nodeId"].(string)

	// 创建分享：没有显式要求审批，但密级 3 达到默认阈值
	resp, out := postJSON(t, srv.URL+"/v1/shares", owner, map[string]any{
		"objectType": "node", "objectId": nodeID, "allowDownload": true,
	})
	if resp.StatusCode != 200 {
		t.Fatalf("创建分享失败 %d: %v", resp.StatusCode, out)
	}
	d := dataMap(t, out)
	if d["approvalStatus"] != "pending" {
		t.Fatalf("AC-43 密级对象的外发必须进审批，实际 %v", d["approvalStatus"])
	}

	// 审批前兑换不可用
	token, _ := d["token"].(string)
	if token == "" {
		t.Fatalf("未返回 token: %v", d)
	}
	if r, raw := getRaw(t, srv.URL+"/v1/public/shares/"+token, ""); r.StatusCode == 200 {
		t.Fatalf("AC-43 审批未通过前链接不应可用: %s", raw)
	}
}
