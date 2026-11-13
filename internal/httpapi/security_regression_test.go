package httpapi

import (
	"context"
	"net/http"
	"testing"
	"time"
)

// loginAs 以指定用户名登录（setup 里的 login 固定用 bob）。
func loginAs(t *testing.T, srvURL, slug, username string) string {
	t.Helper()
	resp, body := postJSON(t, srvURL+"/v1/auth/login", "", map[string]any{
		"tenantSlug": slug, "username": username, "password": pwd,
	})
	if resp.StatusCode != 200 {
		t.Fatalf("以 %s 登录失败 %d: %v", username, resp.StatusCode, body)
	}
	return dataMap(t, body)["accessToken"].(string)
}

// deleteAs 带令牌发一个 DELETE。
func deleteAs(t *testing.T, url, token string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodDelete, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

// 本文件是安全审计（docs/28）的回归用例。
//
// 每个用例对应一个"曾经真实存在"的缺陷，注释里写明**为什么**要这样断言，
// 而不只是断言状态码——否则后来的人只看到一串数字，不知道删掉会退化成什么。

// 外发审批不能自批。
//
// 缺陷原状：handleApproveShare 只校验"对该对象有 manage_acl"，
// 而空间所有者对自己创建的外链恰好就有这个权限，于是同一人可以先发起再审批，
// 审批记录齐全但控制完全失效。
func TestShareApprovalCannotSelfApprove(t *testing.T) {
	srv, pool, slug := setup(t)
	owner := login(t, srv.URL, slug)
	_, nodeID := prepareFile(t, srv.URL, owner)

	resp, body := postJSON(t, srv.URL+"/v1/shares", owner, map[string]any{
		"objectType": "node", "objectId": nodeID,
		"requireApproval": true, "allowDownload": true,
	})
	if resp.StatusCode != 200 {
		t.Fatalf("创建待审批分享失败 %d: %v", resp.StatusCode, body)
	}
	d := dataMap(t, body)
	shareID := d["shareId"].(string)
	if d["approvalStatus"] != "pending" {
		t.Fatalf("应进入待审批，实际 %v", d)
	}

	// 同一账号自我审批：必须被拒
	resp, body = postJSON(t, srv.URL+"/v1/shares/"+shareID+"/approve", owner,
		map[string]any{"approve": true})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("自批应 403，实际 %d: %v", resp.StatusCode, body)
	}
	// 错误响应没有 data 段，直接读顶层 code
	if code, _ := body["code"].(string); code != "SELF_APPROVAL_DENIED" {
		t.Fatalf("应返回 SELF_APPROVAL_DENIED，实际 %q", code)
	}

	// 状态必须仍是 pending：被拒不能顺手把它变成 approved
	var status string
	if err := pool.QueryRow(context.Background(),
		`SELECT approval_status FROM share WHERE id = $1`, shareID).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "pending" {
		t.Fatalf("自批被拒后状态应仍为 pending，实际 %s", status)
	}
}

// 撤销外链必须具备对该对象的处置权。
//
// 缺陷原状：Revoke 只按 tenant_id 过滤，任何同租户用户拿到 share id
// 就能撤销别人的外链——既能让业务中断，也能用来掩盖外泄。
func TestShareRevokeRequiresObjectPermission(t *testing.T) {
	srv, pool, slug := setup(t)
	owner := login(t, srv.URL, slug)
	_, nodeID := prepareFile(t, srv.URL, owner)

	_, body := postJSON(t, srv.URL+"/v1/shares", owner, map[string]any{
		"objectType": "node", "objectId": nodeID, "allowDownload": true,
	})
	shareID := dataMap(t, body)["shareId"].(string)

	// 同租户的普通用户：看得见空间也看得见文件，但没有 manage_acl
	seedUser(t, srv.URL, slug, "eve-revoke")
	tenantID := tenantOf(t, pool, slug)
	grantBits(t, pool, tenantID, "node", nodeID, userIDByName(t, slug, "eve-revoke"), 1<<0) // display only

	eveTok := loginAs(t, srv.URL, slug, "eve-revoke")
	resp, respBody := postJSON(t, srv.URL+"/v1/shares/"+shareID+"/revoke", eveTok, map[string]any{})
	if resp.StatusCode != http.StatusForbidden && resp.StatusCode != http.StatusNotFound {
		t.Fatalf("他人撤销应被拒，实际 %d: %v", resp.StatusCode, respBody)
	}

	// 链接必须仍然可用（没被误撤）
	var revoked *string
	if err := pool.QueryRow(context.Background(),
		`SELECT revoked_at::text FROM share WHERE id = $1`, shareID).Scan(&revoked); err != nil {
		t.Fatal(err)
	}
	if revoked != nil {
		t.Fatalf("越权撤销不应生效，revoked_at=%v", *revoked)
	}

	// 创建者本人可以撤销
	resp, respBody = postJSON(t, srv.URL+"/v1/shares/"+shareID+"/revoke", owner, map[string]any{})
	if resp.StatusCode != 200 {
		t.Fatalf("创建者撤销应成功，实际 %d: %v", resp.StatusCode, respBody)
	}
}

// 撤销 ACL 在"对象已不存在"时必须中止，不能跳过权限判定继续删。
//
// 缺陷原状：`if err == nil { 判定 }` 的写法，一旦对象解析失败就跳过 manage_acl
// 直接执行删除——任何登录用户拿到 ACE id 就能删掉已删除对象的授权条目。
func TestRevokeACLFailsClosedWhenObjectGone(t *testing.T) {
	srv, pool, slug := setup(t)
	owner := login(t, srv.URL, slug)
	_, nodeID := prepareFile(t, srv.URL, owner)
	tenantID := tenantOf(t, pool, slug)

	seedUser(t, srv.URL, slug, "victim-ace")
	grantBits(t, pool, tenantID, "node", nodeID, userIDByName(t, slug, "victim-ace"), 1<<1)

	var aceID string
	if err := pool.QueryRow(context.Background(),
		`SELECT id::text FROM ace WHERE object_type='node' AND object_id=$1 AND subject_type='user'`,
		nodeID).Scan(&aceID); err != nil {
		t.Fatalf("读取 ACE 失败: %v", err)
	}

	// 删除节点（软删）→ 之后 aclTarget 会解析失败
	if resp := deleteAs(t, srv.URL+"/v1/nodes/"+nodeID, owner); resp.StatusCode != 200 {
		t.Fatalf("删除节点失败 %d", resp.StatusCode)
	}

	seedUser(t, srv.URL, slug, "attacker-ace")
	atkTok := loginAs(t, srv.URL, slug, "attacker-ace")

	res := deleteAs(t, srv.URL+"/v1/acl/"+aceID, atkTok)
	defer func() { _ = res.Body.Close() }()

	if res.StatusCode == 200 {
		t.Fatalf("对象不存在时撤销 ACL 竟然成功（fail-open）")
	}
	// ACE 必须还在
	var cnt int
	if err := pool.QueryRow(context.Background(),
		`SELECT COUNT(*) FROM ace WHERE id = $1`, aceID).Scan(&cnt); err != nil {
		t.Fatal(err)
	}
	if cnt != 1 {
		t.Fatalf("越权撤销后 ACE 应仍存在，实际行数 %d", cnt)
	}
}

// 空间级外链不得把发起人也看不到的内容一起交出去。
//
// 缺陷原状：创建时只判空间根的 share_external，读取时不看节点密级，
// 于是"空间根可外发"等于"空间内所有密级都可外发"。
func TestSpaceExternalShareRejectsHiddenContent(t *testing.T) {
	srv, pool, slug := setup(t)
	owner := login(t, srv.URL, slug)
	spaceID, nodeID := prepareFile(t, srv.URL, owner)

	// 把文件密级抬高到发起人之上
	if _, err := pool.Exec(context.Background(),
		`UPDATE node SET classification = 3 WHERE id = $1`, nodeID); err != nil {
		t.Fatal(err)
	}

	resp, body := postJSON(t, srv.URL+"/v1/shares", owner, map[string]any{
		"objectType": "space", "objectId": spaceID, "allowDownload": true,
	})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("空间内含高密文件时应拒绝整体外发，实际 %d: %v", resp.StatusCode, body)
	}
	if code, _ := body["code"].(string); code != "SPACE_NOT_SHAREABLE" {
		t.Fatalf("应返回 SPACE_NOT_SHAREABLE，实际 %q", code)
	}
}

// 密级上界是快照：分享创建后把节点密级抬高，已发出的票据也必须失效于该内容。
//
// 这条防的是"先分享再提密"——如果只在创建时判一次，提密之后就绕过了。
func TestTicketContentRespectsMaxClass(t *testing.T) {
	srv, pool, slug := setup(t)
	owner := login(t, srv.URL, slug)
	_, nodeID := prepareFile(t, srv.URL, owner)

	_, body := postJSON(t, srv.URL+"/v1/shares", owner, map[string]any{
		"objectType": "node", "objectId": nodeID, "allowDownload": true,
	})
	token := dataMap(t, body)["token"].(string)

	// 兑换拿票据
	tresp, tbody := getJSON(t, srv.URL+"/v1/public/shares/"+token, "")
	if tresp.StatusCode != 200 {
		t.Fatalf("兑换失败 %d: %v", tresp.StatusCode, tbody)
	}
	ticket := dataMap(t, tbody)["ticket"].(string)

	// 创建后抬高密级
	if _, err := pool.Exec(context.Background(),
		`UPDATE node SET classification = 4 WHERE id = $1`, nodeID); err != nil {
		t.Fatal(err)
	}

	resp, _ := getJSON(t, srv.URL+"/v1/public/tickets/"+ticket+"/content", "")
	if resp.StatusCode != http.StatusGone {
		t.Fatalf("超出密级上界的内容应不可取（410），实际 %d", resp.StatusCode)
	}
}

// 刷新令牌被重放（超出宽限窗口）时必须吊销整条会话，而不是只报"登录过期"。
//
// 缺陷原状：旋转了刷新令牌，但分不清"旧令牌被重放"与"随便编的串"，
// 两者都只是 401。攻击者窃取令牌后抢先使用，合法用户只会以为登录过期，
// 系统零告警、不吊销——凭证泄露被伪装成一次正常过期。
func TestRefreshReplayRevokesSession(t *testing.T) {
	srv, pool, slug := setup(t)
	ctx := context.Background()

	_, body := postJSON(t, srv.URL+"/v1/auth/login", "", map[string]any{
		"tenantSlug": slug, "username": "bob", "password": pwd,
	})
	r0 := dataMap(t, body)["refreshToken"].(string)

	resp, body := postJSON(t, srv.URL+"/v1/auth/refresh", "", map[string]any{"refreshToken": r0})
	if resp.StatusCode != 200 {
		t.Fatalf("首次刷新失败 %d: %v", resp.StatusCode, body)
	}
	r1 := dataMap(t, body)["refreshToken"].(string)

	// 把旋转时刻推到宽限窗口之外：模拟"过了一段时间后旧令牌才再次出现"
	if _, err := pool.Exec(ctx,
		`UPDATE session SET refresh_rotated_at = now() - interval '2 minutes'`); err != nil {
		t.Fatal(err)
	}

	resp, body = postJSON(t, srv.URL+"/v1/auth/refresh", "", map[string]any{"refreshToken": r0})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("重放应 401，实际 %d: %v", resp.StatusCode, body)
	}
	if code, _ := body["code"].(string); code != "REFRESH_REPLAY" {
		t.Fatalf("应返回 REFRESH_REPLAY（可被前端区分处理），实际 %q", code)
	}

	// 会话必须已吊销：防御的价值在于"攻击者那条链也一起断"
	var revoked *time.Time
	if err := pool.QueryRow(ctx,
		`SELECT revoked_at FROM session ORDER BY created_at DESC LIMIT 1`).Scan(&revoked); err != nil {
		t.Fatal(err)
	}
	if revoked == nil {
		t.Fatal("检测到重放后会话必须被吊销，实际 revoked_at 为空")
	}

	// 合法用户手里的新令牌也应一并失效——这正是"宁可让用户重登"的取舍
	resp, _ = postJSON(t, srv.URL+"/v1/auth/refresh", "", map[string]any{"refreshToken": r1})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("吊销后新令牌也应失效，实际 %d", resp.StatusCode)
	}
}

// 宽限窗口内的重复刷新是多标签页/重试，不该把用户踢下线。
//
// 这一条与上一条成对：只有"该拦的拦、该放的放"，检测才敢开。
func TestRefreshReplayWithinGraceKeepsSession(t *testing.T) {
	srv, _, slug := setup(t)

	_, body := postJSON(t, srv.URL+"/v1/auth/login", "", map[string]any{
		"tenantSlug": slug, "username": "bob", "password": pwd,
	})
	r0 := dataMap(t, body)["refreshToken"].(string)

	_, body = postJSON(t, srv.URL+"/v1/auth/refresh", "", map[string]any{"refreshToken": r0})
	r1 := dataMap(t, body)["refreshToken"].(string)

	// 立刻重放旧令牌：落在宽限内 → 只让这个请求失败
	resp, _ := postJSON(t, srv.URL+"/v1/auth/refresh", "", map[string]any{"refreshToken": r0})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("宽限内重放也应被拒，实际 %d", resp.StatusCode)
	}

	// 关键断言：会话还活着，新令牌仍然可用（否则一次双击就下线）
	resp, body = postJSON(t, srv.URL+"/v1/auth/refresh", "", map[string]any{"refreshToken": r1})
	if resp.StatusCode != 200 {
		t.Fatalf("宽限内重放不应吊销会话，后续刷新实际 %d: %v", resp.StatusCode, body)
	}
}
