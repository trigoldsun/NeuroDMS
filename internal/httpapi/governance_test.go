package httpapi

// M2-A 权限治理用例：继承断点、权限解释、ACE 改档、版本定版。
//
// 这一组用例的共同点：它们验证的都是"改一条权限"这类**低可见度、高影响**的操作。
// 界面点错一次，整棵子树的访问权就会变，因此每条都必须有负向断言。

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"docvault/internal/authz"

	"github.com/jackc/pgx/v5/pgxpool"
)

// sendJSONMap 发请求并解析为通用 map，省掉各用例重复的 unmarshal。
func sendJSONMap(t *testing.T, method, url, token string, body any) (*http.Response, map[string]any) {
	t.Helper()
	resp, raw := sendJSON(t, method, url, token, body)
	var out map[string]any
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatalf("解析响应失败: %v (%s)", err, raw)
		}
	}
	return resp, out
}

// denyBitOn 给某对象上的某主体加一个显式拒绝位。
func denyBitOn(t *testing.T, pool *pgxpool.Pool, objectType, objectID, userID string, bit authz.Bit) {
	t.Helper()
	tag, err := pool.Exec(context.Background(), `
		UPDATE ace SET deny_bits = deny_bits | $4
		 WHERE object_type = $1 AND object_id = $2 AND subject_type = 'user' AND subject_id = $3`,
		objectType, objectID, userID, int64(bit))
	if err != nil {
		t.Fatalf("写入拒绝位失败: %v", err)
	}
	if tag.RowsAffected() == 0 {
		t.Fatalf("没有可加拒绝位的 ACE（对象 %s/%s）", objectType, objectID)
	}
}

// AC-37：断开继承不能成为绕过上层 deny 的提权路径。
//
// 语义：断开时把祖先 ACE（含 deny）复制成本对象的 inherited 快照，
// 且快照不允许单独删除——否则"断开 → 删掉 deny"就能把上层拒绝抹掉。
func TestAC37BreakInheritanceCannotBypassDeny(t *testing.T) {
	srv, pool, slug := setup(t)
	owner := login(t, srv.URL, slug)
	spaceID, nodeID := prepareFile(t, srv.URL, owner)

	eve := seedUser(t, srv.URL, slug, "eve37")
	eveID := userIDByName(t, slug, "eve37")

	// 空间上给 eve 只读，并显式 deny download（模拟"可浏览不可取走"）
	resp, body := postJSON(t, srv.URL+"/v1/acl", owner, map[string]any{
		"objectType": "space", "objectId": spaceID,
		"subjectType": "user", "subjectId": eveID, "preset": "viewer",
	})
	if resp.StatusCode != 200 {
		t.Fatalf("授予 viewer 失败 %d: %v", resp.StatusCode, body)
	}
	denyBitOn(t, pool, "space", spaceID, eveID, authz.Download)

	// 断前：下载被空间级 deny 拦住
	if r, raw := getRaw(t, srv.URL+"/v1/nodes/"+nodeID+"/content", eve); r.StatusCode != http.StatusForbidden {
		t.Fatalf("AC-37 断前应 403，实际 %d: %s", r.StatusCode, raw)
	}

	// 无 manage_acl 的人不能断开继承
	if r, raw := sendJSON(t, http.MethodPost, srv.URL+"/v1/nodes/"+nodeID+"/inheritance", eve,
		map[string]any{"broken": true}); r.StatusCode != http.StatusForbidden {
		t.Fatalf("AC-37 继承操作需要 manage_acl，期望 403，实际 %d: %s", r.StatusCode, raw)
	}

	// 所有者断开继承：快照必须连 deny 一起复制
	brkResp, brkBody := sendJSONMap(t, http.MethodPost, srv.URL+"/v1/nodes/"+nodeID+"/inheritance", owner,
		map[string]any{"broken": true})
	if brkResp.StatusCode != 200 {
		t.Fatalf("断开继承失败 %d: %v", brkResp.StatusCode, brkBody)
	}
	d := dataMap(t, brkBody)
	if d["broken"] != true {
		t.Fatalf("断后 broken 应为 true: %v", d)
	}
	if n, _ := d["inheritedAces"].(float64); n < 1 {
		t.Fatalf("断后应存在继承快照，实际 %v", d["inheritedAces"])
	}

	// 断后：deny 仍在（来自快照），不能被绕过
	if r, raw := getRaw(t, srv.URL+"/v1/nodes/"+nodeID+"/content", eve); r.StatusCode != http.StatusForbidden {
		t.Fatalf("AC-37 断后仍然 403，实际 %d: %s", r.StatusCode, raw)
	}

	// 快照条目不允许单独删除
	var inheritedAceID string
	if err := pool.QueryRow(context.Background(), `
		SELECT id::text FROM ace
		 WHERE object_type='node' AND object_id=$1 AND origin='inherited' LIMIT 1`, nodeID).
		Scan(&inheritedAceID); err != nil {
		t.Fatalf("未找到继承快照: %v", err)
	}
	r, raw := delJSONRaw(t, srv.URL+"/v1/acl/"+inheritedAceID, owner)
	if r.StatusCode != http.StatusConflict {
		t.Fatalf("AC-37 快照不可单删，期望 409，实际 %d: %s", r.StatusCode, raw)
	}
}

// 恢复继承：快照整批移除，判定回到"向上取"。
func TestRestoreInheritanceRemovesSnapshot(t *testing.T) {
	srv, pool, slug := setup(t)
	owner := login(t, srv.URL, slug)
	spaceID, nodeID := prepareFile(t, srv.URL, owner)

	eve := seedUser(t, srv.URL, slug, "eve37b")
	eveID := userIDByName(t, slug, "eve37b")
	postJSON(t, srv.URL+"/v1/acl", owner, map[string]any{
		"objectType": "space", "objectId": spaceID,
		"subjectType": "user", "subjectId": eveID, "preset": "viewer",
	})

	if r, raw := sendJSON(t, http.MethodPost, srv.URL+"/v1/nodes/"+nodeID+"/inheritance", owner,
		map[string]any{"broken": true}); r.StatusCode != 200 {
		t.Fatalf("断开失败 %d: %s", r.StatusCode, raw)
	}
	resp, body := sendJSONMap(t, http.MethodPost, srv.URL+"/v1/nodes/"+nodeID+"/inheritance", owner,
		map[string]any{"broken": false})
	if resp.StatusCode != 200 {
		t.Fatalf("恢复失败 %d: %v", resp.StatusCode, body)
	}
	d := dataMap(t, body)
	if d["broken"] != false || d["inheritedAces"].(float64) != 0 {
		t.Fatalf("恢复后应无快照且 broken=false: %v", d)
	}
	var left int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM ace WHERE object_type='node' AND object_id=$1 AND origin='inherited'`,
		nodeID).Scan(&left); err != nil {
		t.Fatal(err)
	}
	if left != 0 {
		t.Fatalf("恢复后仍有 %d 条继承快照", left)
	}
	// 恢复后空间级授权仍然生效
	if r, raw := getJSON(t, srv.URL+"/v1/nodes/"+nodeID, eve); r.StatusCode != 200 {
		t.Fatalf("恢复继承后应仍可看到对象，实际 %d: %s", r.StatusCode, raw)
	}
}

// AC-30：权限解释只允许查自己；查他人必须有 manage_acl。
func TestAC30ExplainRestrictedToSelfOrManager(t *testing.T) {
	srv, _, slug := setup(t)
	owner := login(t, srv.URL, slug)
	spaceID, nodeID := prepareFile(t, srv.URL, owner)

	eve := seedUser(t, srv.URL, slug, "eve30")
	eveID := userIDByName(t, slug, "eve30")
	seedUser(t, srv.URL, slug, "bob30")
	bobID := userIDByName(t, slug, "bob30")

	postJSON(t, srv.URL+"/v1/acl", owner, map[string]any{
		"objectType": "space", "objectId": spaceID,
		"subjectType": "user", "subjectId": eveID, "preset": "viewer",
	})

	// 自查：允许
	resp, body := getJSON(t, srv.URL+"/v1/nodes/"+nodeID+"/permissions/explain?action=download", eve)
	if resp.StatusCode != 200 {
		t.Fatalf("AC-30 自查解释应 200，实际 %d: %v", resp.StatusCode, body)
	}
	d := dataMap(t, body)
	if d["allowed"] != false || d["reason"] != authz.ReasonNoAllow {
		t.Fatalf("AC-30 viewer 查 download 应拒且原因为 NO_ALLOW: %v", d)
	}
	if steps, ok := d["steps"].([]any); !ok || len(steps) < 5 {
		t.Fatalf("AC-30 解释必须给出分步轨迹: %v", d["steps"])
	}

	// 查他人（自己无 manage_acl）：拒绝
	if r, raw := getRaw(t, srv.URL+"/v1/nodes/"+nodeID+"/permissions/explain?subjectId="+bobID, eve); r.StatusCode != http.StatusForbidden {
		t.Fatalf("AC-30 无 manage_acl 查他人解释应 403，实际 %d: %s", r.StatusCode, raw)
	}

	// 所有者查他人：允许，且能看到对方为何被拒
	resp, body = getJSON(t, srv.URL+"/v1/nodes/"+nodeID+"/permissions/explain?subjectId="+bobID, owner)
	if resp.StatusCode != 200 {
		t.Fatalf("AC-30 所有者查他人解释应 200，实际 %d: %v", resp.StatusCode, body)
	}
	if dataMap(t, body)["allowed"] != false {
		t.Fatalf("AC-30 bob 无授权，解释应为 false: %v", body)
	}
}

// 解释接口必须如实反映密级门：这是"排障时最容易被误判成 ACL 问题"的一类。
func TestExplainShowsClassificationGate(t *testing.T) {
	srv, pool, slug := setup(t)
	owner := login(t, srv.URL, slug)
	spaceID, nodeID := prepareFile(t, srv.URL, owner)

	eve := seedUser(t, srv.URL, slug, "eve39b")
	eveID := userIDByName(t, slug, "eve39b")
	postJSON(t, srv.URL+"/v1/acl", owner, map[string]any{
		"objectType": "space", "objectId": spaceID,
		"subjectType": "user", "subjectId": eveID, "preset": "editor",
	})
	// 文件密级提到 3，eve 用户密级仍为 0
	if _, err := pool.Exec(context.Background(),
		`UPDATE node SET classification = 3 WHERE id = $1`, nodeID); err != nil {
		t.Fatal(err)
	}

	resp, body := getJSON(t, srv.URL+"/v1/nodes/"+nodeID+"/permissions/explain?action=download", eve)
	if resp.StatusCode != 200 {
		t.Fatalf("解释接口应 200，实际 %d: %v", resp.StatusCode, body)
	}
	d := dataMap(t, body)
	if d["allowed"] != false || d["reason"] != authz.ReasonClassification {
		t.Fatalf("密级不足应返回 CLASSIFICATION_DENIED: %v", d)
	}
	if obj, ok := d["object"].(map[string]any); !ok || obj["classification"].(float64) != 3 {
		t.Fatalf("解释应带上对象密级: %v", d["object"])
	}
}

// AC-33：修改 ACE（改档位/取消有效期）需要 manage_acl，且受封顶约束。
func TestAC33PatchACERequiresManageACLAndCeiling(t *testing.T) {
	srv, pool, slug := setup(t)
	owner := login(t, srv.URL, slug)
	spaceID, _ := prepareFile(t, srv.URL, owner)

	eve := seedUser(t, srv.URL, slug, "eve33")
	eveID := userIDByName(t, slug, "eve33")
	resp, body := postJSON(t, srv.URL+"/v1/acl", owner, map[string]any{
		"objectType": "space", "objectId": spaceID,
		"subjectType": "user", "subjectId": eveID, "preset": "viewer", "expiresInHours": 1,
	})
	if resp.StatusCode != 200 {
		t.Fatalf("授予失败 %d: %v", resp.StatusCode, body)
	}
	aceID := dataMap(t, body)["aceId"].(string)

	// 无 manage_acl 的人改自己的有效期 → 403
	if r, raw := sendJSON(t, http.MethodPatch, srv.URL+"/v1/acl/"+aceID, eve,
		map[string]any{"preset": "owner", "clearExpiry": true}); r.StatusCode != http.StatusForbidden {
		t.Fatalf("AC-33 无 manage_acl 改档应 403，实际 %d: %s", r.StatusCode, raw)
	}

	// 所有者改档：允许，且结果里 allow 位已更新
	resp, body = sendJSONMap(t, http.MethodPatch, srv.URL+"/v1/acl/"+aceID, owner,
		map[string]any{"preset": "editor", "clearExpiry": true})
	if resp.StatusCode != 200 {
		t.Fatalf("AC-33 所有者改档失败 %d: %v", resp.StatusCode, body)
	}
	var expiresNull bool
	if err := pool.QueryRow(context.Background(),
		`SELECT expires_at IS NULL FROM ace WHERE id = $1`, aceID).Scan(&expiresNull); err != nil {
		t.Fatal(err)
	}
	if !expiresNull {
		t.Fatal("AC-33 clearExpiry 未生效：有效期仍存在")
	}

	// 改档也确实写入了位图
	var bits int64
	if err := pool.QueryRow(context.Background(),
		`SELECT allow_bits FROM ace WHERE id = $1`, aceID).Scan(&bits); err != nil {
		t.Fatal(err)
	}
	if authz.Bit(bits) != authz.PresetEditor.Bits() {
		t.Fatalf("AC-33 改档后位图不符: %v", authz.Bit(bits).Names())
	}
}

// AC-32：授出 manager 档位同样受封顶约束（与 owner 走同一分支，但需要专项断言）。
func TestAC32GrantManagerRejectedByCeiling(t *testing.T) {
	srv, pool, slug := setup(t)
	owner := login(t, srv.URL, slug)
	spaceID, _ := prepareFile(t, srv.URL, owner)

	alice := seedUser(t, srv.URL, slug, "alice32")
	aliceID := userIDByName(t, slug, "alice32")
	seedUser(t, srv.URL, slug, "eve32")
	eveID := userIDByName(t, slug, "eve32")

	// alice 拿到空间 owner（拥有 manage_acl），但自身 ceiling 降到 3
	//
	// 注意：manage_acl 只存在于 owner 档。manager 档刻意不含授权能力——
	// "能管理文件"与"能改变谁能看"是两件事，混在一起会让授权链迅速失控。
	resp, body := postJSON(t, srv.URL+"/v1/acl", owner, map[string]any{
		"objectType": "space", "objectId": spaceID,
		"subjectType": "user", "subjectId": aliceID, "preset": "owner",
	})
	if resp.StatusCode != 200 {
		t.Fatalf("授予 owner 失败 %d: %v", resp.StatusCode, body)
	}
	if _, err := pool.Exec(context.Background(),
		`UPDATE app_user SET ceiling = 3 WHERE id = $1`, aliceID); err != nil {
		t.Fatal(err)
	}

	resp, body = postJSON(t, srv.URL+"/v1/acl", alice, map[string]any{
		"objectType": "space", "objectId": spaceID,
		"subjectType": "user", "subjectId": eveID, "preset": "manager",
	})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("AC-32 ceiling=3 授 manager 应 403，实际 %d: %v", resp.StatusCode, body)
	}
	if body["code"] != "CEILING_EXCEEDED" {
		t.Fatalf("AC-32 应返回 CEILING_EXCEEDED: %v", body)
	}
}

// AC-34：删除他人授权条目需 manage_acl（撤销与授权是同一判定的两个方向）。
func TestAC34CannotRevokeOthersACEWithoutManageACL(t *testing.T) {
	srv, pool, slug := setup(t)
	owner := login(t, srv.URL, slug)
	spaceID, _ := prepareFile(t, srv.URL, owner)

	eve := seedUser(t, srv.URL, slug, "eve34")
	eveID := userIDByName(t, slug, "eve34")
	bob2 := seedUser(t, srv.URL, slug, "bob34")
	bobID := userIDByName(t, slug, "bob34")

	// 两者都是 viewer：eve 不能撤销 bob 的条目
	postJSON(t, srv.URL+"/v1/acl", owner, map[string]any{
		"objectType": "space", "objectId": spaceID,
		"subjectType": "user", "subjectId": eveID, "preset": "viewer",
	})
	resp, body := postJSON(t, srv.URL+"/v1/acl", owner, map[string]any{
		"objectType": "space", "objectId": spaceID,
		"subjectType": "user", "subjectId": bobID, "preset": "viewer",
	})
	if resp.StatusCode != 200 {
		t.Fatalf("授予失败 %d: %v", resp.StatusCode, body)
	}
	bobAce := dataMap(t, body)["aceId"].(string)

	if r, raw := delJSONRaw(t, srv.URL+"/v1/acl/"+bobAce, eve); r.StatusCode != http.StatusForbidden {
		t.Fatalf("AC-34 无 manage_acl 撤销他人授权应 403，实际 %d: %s", r.StatusCode, raw)
	}
	// 反向确认：条目还在
	var still int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM ace WHERE id = $1`, bobAce).Scan(&still); err != nil {
		t.Fatal(err)
	}
	if still != 1 {
		t.Fatal("AC-34 拒绝后条目被删除了")
	}
	_ = bob2
}

// AC-22：设定生效版需要 manage_version，且生效版唯一。
func TestAC22SetEffectiveRequiresManageVersion(t *testing.T) {
	srv, pool, slug := setup(t)
	owner := login(t, srv.URL, slug)
	spaceID, nodeID := prepareFile(t, srv.URL, owner)
	// 再上传一次同名文件 → 产生版本 2
	upload(t, srv.URL+"/v1/spaces/"+spaceID+"/files", owner, "report.txt", "第二版内容")

	eve := seedUser(t, srv.URL, slug, "eve22")
	eveID := userIDByName(t, slug, "eve22")
	postJSON(t, srv.URL+"/v1/acl", owner, map[string]any{
		"objectType": "space", "objectId": spaceID,
		"subjectType": "user", "subjectId": eveID, "preset": "editor",
	})

	// editor 有 edit 但没有 manage_version
	if r, raw := sendJSON(t, http.MethodPost, srv.URL+"/v1/nodes/"+nodeID+"/versions/1/restore", eve,
		map[string]any{}); r.StatusCode != http.StatusForbidden {
		t.Fatalf("AC-22 缺 manage_version 应 403，实际 %d: %s", r.StatusCode, raw)
	}

	// 所有者回退到 v1：语义是"追加新版本"，不是切换指针
	resp, body := sendJSONMap(t, http.MethodPost, srv.URL+"/v1/nodes/"+nodeID+"/versions/1/restore", owner,
		map[string]any{})
	if resp.StatusCode != 200 {
		t.Fatalf("AC-22 回退失败 %d: %v", resp.StatusCode, body)
	}

	// 生效版唯一：库里恰好一条 effective
	var effective int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM version WHERE node_id = $1 AND state = 'effective'`, nodeID).
		Scan(&effective); err != nil {
		t.Fatal(err)
	}
	if effective != 1 {
		t.Fatalf("AC-22 生效版必须唯一，实际 %d 条", effective)
	}

	// 版本列表：回退生成的新版本是当前版本，且记录来源版本号
	resp, body = getJSON(t, srv.URL+"/v1/nodes/"+nodeID+"/versions", owner)
	if resp.StatusCode != 200 {
		t.Fatalf("版本列表失败 %d: %v", resp.StatusCode, body)
	}
	items, _ := dataMap(t, body)["items"].([]any)
	if len(items) < 3 {
		t.Fatalf("回退后应至少 3 个版本: %v", items)
	}
	var currentNo float64
	var foundRestore bool
	for _, it := range items {
		m := it.(map[string]any)
		if m["isEffective"] != true {
			continue
		}
		currentNo = m["versionNo"].(float64)
		if m["origin"] == "restore" && m["restoredFromNo"] == float64(1) {
			foundRestore = true
		}
	}
	if currentNo != 3 || !foundRestore {
		t.Fatalf("回退后 v3 应为当前版本且来源为 v1，实际 %v", items)
	}

	// 旧路径已下线：必须返回 410 并指出替代接口，
	// 而不是 404——那会让人以为文件本身没了，去查存储。
	if r, raw := sendJSON(t, http.MethodPost, srv.URL+"/v1/nodes/"+nodeID+"/versions/2/effective", owner,
		map[string]any{}); r.StatusCode != http.StatusGone {
		t.Fatalf("旧 /effective 应 410，实际 %d: %s", r.StatusCode, raw)
	}

	// 不存在的版本号 → 404
	if r, raw := sendJSON(t, http.MethodPost, srv.URL+"/v1/nodes/"+nodeID+"/versions/99/restore", owner,
		map[string]any{}); r.StatusCode != http.StatusNotFound {
		t.Fatalf("不存在的版本应 404，实际 %d: %s", r.StatusCode, raw)
	}
}

// delJSONRaw 发起 DELETE 并返回原始响应体（用于断言错误码而非结构）。
func delJSONRaw(t *testing.T, url, token string) (*http.Response, []byte) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodDelete, url, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("请求失败: %v", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("读取响应失败: %v", err)
	}
	return resp, raw
}
