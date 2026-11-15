package httpapi

import (
	"context"
	"net/http"
	"testing"
	"time"
)

// 部门管理（E2E 验收 F-03）。
//
// 这一组锁住五件事，任何一条破了都会让"按部门授权"变成摆设：
//  1. 能建子部门，路径按上级拼接（ACL 靠路径前缀命中子树）；
//  2. 同级重名被拒（两个"财务"在授权界面上无法区分，选错就是给错人权限）；
//  3. 有成员/子部门时不允许删除（不级联改别人的归属）；
//  4. 不能把部门移动到自己的下级（成环会让路径无限嵌套）；
//  5. 目录同步来的部门本地不能改名/删除（下次同步会打架）。

func deptList(t *testing.T, base, token string) map[string]any {
	t.Helper()
	resp, body := getJSON(t, base+"/v1/admin/depts", token)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("读部门失败 %d: %v", resp.StatusCode, body)
	}
	return dataMap(t, body)
}

func findDept(t *testing.T, d map[string]any, name string) map[string]any {
	t.Helper()
	items, _ := d["items"].([]any)
	for _, it := range items {
		m := it.(map[string]any)
		if m["name"] == name {
			return m
		}
	}
	t.Fatalf("没找到部门 %q（现有 %v）", name, names(items))
	return nil
}

func names(items []any) []string {
	out := make([]string, 0, len(items))
	for _, it := range items {
		out = append(out, it.(map[string]any)["name"].(string))
	}
	return out
}

func TestDeptCreateRenameMoveDelete(t *testing.T) {
	srv, pool, _ := setup(t)
	ct := createTenant(t, pool, srv.URL, "dept")

	d := deptList(t, srv.URL, ct.token)
	// 开通即有根部门，且它是顶层
	root := findDept(t, d, "总部")
	if root["parentId"] != nil {
		t.Fatalf("「总部」应是顶层，实际 parentId=%v", root["parentId"])
	}
	rootID := root["id"].(string)

	// 1) 建子部门：路径应是 root.<label>
	resp, body := postJSON(t, srv.URL+"/v1/admin/depts", ct.token, map[string]any{
		"name": "财务部", "parentId": rootID,
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("建部门失败 %d: %v", resp.StatusCode, body)
	}
	fin := dataMap(t, body)
	finID := fin["id"].(string)
	if fin["depth"] != float64(2) {
		t.Fatalf("子部门深度应为 2，实际 %v", fin["depth"])
	}
	if path := fin["path"].(string); path == "" || path == "root" {
		t.Fatalf("子部门路径异常: %q", path)
	}

	// 2) 同级重名 → 409
	resp, body = postJSON(t, srv.URL+"/v1/admin/depts", ct.token, map[string]any{
		"name": "财务部", "parentId": rootID,
	})
	if resp.StatusCode != http.StatusConflict || body["code"] != "DEPT_NAME_TAKEN" {
		t.Fatalf("同级重名应 409 DEPT_NAME_TAKEN，实际 %d: %v", resp.StatusCode, body)
	}

	// 3) 建孙部门，然后试着把父部门移到孙部门下 → 409 DEPT_CYCLE
	resp, body = postJSON(t, srv.URL+"/v1/admin/depts", ct.token, map[string]any{
		"name": "会计组", "parentId": finID,
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("建孙部门失败 %d: %v", resp.StatusCode, body)
	}
	subID := dataMap(t, body)["id"].(string)

	resp, body = sendJSONMap(t, http.MethodPost, srv.URL+"/v1/admin/depts/"+finID+"/move",
		ct.token, map[string]any{"parentId": subID})
	if resp.StatusCode != http.StatusConflict || body["code"] != "DEPT_CYCLE" {
		t.Fatalf("移到自己下级应 409 DEPT_CYCLE，实际 %d: %v", resp.StatusCode, body)
	}

	// 4) 改名：只改 name，路径不变（ACL 靠路径，不能改）
	before := findDept(t, deptList(t, srv.URL, ct.token), "财务部")
	resp, body = sendJSONMap(t, http.MethodPatch, srv.URL+"/v1/admin/depts/"+finID,
		ct.token, map[string]any{"name": "财务中心"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("改名失败 %d: %v", resp.StatusCode, body)
	}
	after := dataMap(t, body)
	if after["path"] != before["path"] {
		t.Fatalf("改名不应改变路径：%v → %v", before["path"], after["path"])
	}

	// 5) 有子部门/成员时不能删
	resp, body = sendJSONMap(t, http.MethodDelete, srv.URL+"/v1/admin/depts/"+finID, ct.token, nil)
	if resp.StatusCode != http.StatusConflict || body["code"] != "DEPT_NOT_EMPTY" {
		t.Fatalf("有子部门时删除应 409 DEPT_NOT_EMPTY，实际 %d: %v", resp.StatusCode, body)
	}

	// 6) 把一个人挂到「会计组」上，删该部门要因为"有成员"被拒
	resp, body = postJSON(t, srv.URL+"/v1/admin/members", ct.token, map[string]any{
		"username": "fin_user", "displayName": "会计", "password": "member-pass-1",
		"deptId": subID,
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("建成员失败 %d: %v", resp.StatusCode, body)
	}
	resp, body = sendJSONMap(t, http.MethodDelete, srv.URL+"/v1/admin/depts/"+subID, ct.token, nil)
	if resp.StatusCode != http.StatusConflict || body["code"] != "DEPT_NOT_EMPTY" {
		t.Fatalf("有成员时删除应 409 DEPT_NOT_EMPTY，实际 %d: %v", resp.StatusCode, body)
	}

	// 7) 空部门可以删
	resp, body = postJSON(t, srv.URL+"/v1/admin/depts", ct.token, map[string]any{
		"name": "临时组", "parentId": rootID,
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("建临时部门失败 %d: %v", resp.StatusCode, body)
	}
	tmpID := dataMap(t, body)["id"].(string)
	resp, body = sendJSONMap(t, http.MethodDelete, srv.URL+"/v1/admin/depts/"+tmpID, ct.token, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("空部门删除应成功，实际 %d: %v", resp.StatusCode, body)
	}
	if _, exists := findDeptOrNil(t, deptList(t, srv.URL, ct.token), "临时组"); exists {
		t.Fatal("删除后不应再出现在列表里")
	}

	// 8) 根部门不能删
	resp, body = sendJSONMap(t, http.MethodDelete, srv.URL+"/v1/admin/depts/"+rootID, ct.token, nil)
	if resp.StatusCode != http.StatusConflict || body["code"] != "DEPT_IS_ROOT" {
		t.Fatalf("删根部门应 409 DEPT_IS_ROOT，实际 %d: %v", resp.StatusCode, body)
	}
}

// 移动整棵子树：路径前缀要整体改写，否则子部门会从父的子树里"掉出去"，
// 表现为「按财务部授权之后，会计组的人反而看不到」。
func TestDeptMoveRewritesSubtreePaths(t *testing.T) {
	srv, pool, _ := setup(t)
	ct := createTenant(t, pool, srv.URL, "deptmove")

	root := findDept(t, deptList(t, srv.URL, ct.token), "总部")
	rootID := root["id"].(string)

	mk := func(name, parent string) map[string]any {
		t.Helper()
		resp, body := postJSON(t, srv.URL+"/v1/admin/depts", ct.token,
			map[string]any{"name": name, "parentId": parent})
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("建 %s 失败 %d: %v", name, resp.StatusCode, body)
		}
		return dataMap(t, body)
	}
	a := mk("研发部", rootID)
	b := mk("后端组", a["id"].(string))
	c := mk("前端组", a["id"].(string))
	// 另一个分支作为新家
	d := mk("事业部", rootID)
	oldPrefix := a["path"].(string)

	resp, body := sendJSONMap(t, http.MethodPost, srv.URL+"/v1/admin/depts/"+a["id"].(string)+"/move",
		ct.token, map[string]any{"parentId": d["id"].(string)})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("移动失败 %d: %v", resp.StatusCode, body)
	}
	moved := dataMap(t, body)
	newPrefix := moved["path"].(string)
	if newPrefix == oldPrefix {
		t.Fatalf("移动后路径应变化：%s", newPrefix)
	}

	list := deptList(t, srv.URL, ct.token)
	for _, name := range []string{"后端组", "前端组"} {
		got := findDept(t, list, name)
		p := got["path"].(string)
		if len(p) <= len(newPrefix) || p[:len(newPrefix)] != newPrefix {
			t.Fatalf("%s 的路径 %q 应以新前缀 %q 开头（子树没跟着走）", name, p, newPrefix)
		}
	}
	// 深度仍然是 3（root → 事业部 → 研发部 → 后端组）
	if b["depth"] != float64(3) || c["depth"] != float64(3) {
		t.Fatalf("子部门深度应为 3，实际 %v/%v", b["depth"], c["depth"])
	}
}

// 目录同步来的部门不允许本地改：改了下次同步会打架。
func TestDeptDirectoryManagedIsReadOnly(t *testing.T) {
	srv, pool, _ := setup(t)
	ct := createTenant(t, pool, srv.URL, "deptdir")

	// 直接插一条带 ldap_dn 的部门（模拟同步产物）
	var dirID, dirPath string
	if err := pool.QueryRow(context.Background(), `
		INSERT INTO dept (id, tenant_id, parent_id, path, name, ldap_dn)
		VALUES (gen_random_uuid(), $1, NULL, text2ltree('SyncedRoot'), '同步根', 'OU=SyncedRoot,DC=corp')
		RETURNING id::text, path::text`, ct.tenantID).Scan(&dirID, &dirPath); err != nil {
		t.Fatalf("准备目录部门失败: %v", err)
	}

	list := deptList(t, srv.URL, ct.token)
	synced := findDept(t, list, "同步根")
	if synced["directory"] != true {
		t.Fatalf("应标记为目录同步来源，实际 %v", synced["directory"])
	}

	resp, body := sendJSONMap(t, http.MethodPatch, srv.URL+"/v1/admin/depts/"+dirID,
		ct.token, map[string]any{"name": "改个名"})
	if resp.StatusCode != http.StatusConflict || body["code"] != "DEPT_DIRECTORY_MANAGED" {
		t.Fatalf("目录部门改名应 409 DEPT_DIRECTORY_MANAGED，实际 %d: %v", resp.StatusCode, body)
	}
	resp, body = sendJSONMap(t, http.MethodDelete, srv.URL+"/v1/admin/depts/"+dirID, ct.token, nil)
	if resp.StatusCode != http.StatusConflict || body["code"] != "DEPT_DIRECTORY_MANAGED" {
		t.Fatalf("目录部门删除应 409，实际 %d: %v", resp.StatusCode, body)
	}
}

// 部门接口只给系统管理员：安全管理员能按部门授权，但不该能造部门。
func TestDeptWriteRequiresSysAdmin(t *testing.T) {
	srv, pool, _ := setup(t)
	ct := createTenant(t, pool, srv.URL, "deptrbac")

	// 建一个安全管理员并登录
	resp, body := postJSON(t, srv.URL+"/v1/admin/members", ct.token, map[string]any{
		"username": "sec_only", "displayName": "安全员", "password": "sec-pass-1234",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("建成员失败 %d: %v", resp.StatusCode, body)
	}
	id := dataMap(t, body)["id"].(string)
	if r, b := postJSON(t, srv.URL+"/v1/admin/members/"+id+"/roles", ct.token,
		map[string]any{"code": "secadmin"}); r.StatusCode != http.StatusOK {
		t.Fatalf("授安全管理员失败 %d: %v", r.StatusCode, b)
	}
	secTok := loginWith(t, srv.URL, ct.slug, "sec_only", "sec-pass-1234")

	resp, body = postJSON(t, srv.URL+"/v1/admin/depts", secTok, map[string]any{"name": "越权部门"})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("安全管理员建部门应 403，实际 %d: %v", resp.StatusCode, body)
	}
	// 读也要求系统管理员（部门树含成员数，属于管理面数据）
	resp, body = getJSON(t, srv.URL+"/v1/admin/depts", secTok)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("安全管理员读部门应 403，实际 %d: %v", resp.StatusCode, body)
	}
}

// 部门改动必须留下审计（"谁把研发部挪到了事业部下面"要能查）。
func TestDeptChangesAreAudited(t *testing.T) {
	srv, pool, _ := setup(t)
	ct := createTenant(t, pool, srv.URL, "deptaudit")

	root := findDept(t, deptList(t, srv.URL, ct.token), "总部")
	resp, body := postJSON(t, srv.URL+"/v1/admin/depts", ct.token,
		map[string]any{"name": "审计部", "parentId": root["id"].(string)})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("建部门失败 %d: %v", resp.StatusCode, body)
	}
	id := dataMap(t, body)["id"].(string)
	if _, b := sendJSONMap(t, http.MethodPatch, srv.URL+"/v1/admin/depts/"+id,
		ct.token, map[string]any{"name": "审计与合规部"}); b["code"] != "OK" {
		t.Fatalf("改名失败: %v", b)
	}

	// 直接查库：审计是异步写的（OnAudit），给一点时间
	var n int
	for i := 0; i < 40; i++ {
		_ = pool.QueryRow(context.Background(), `
			SELECT count(*) FROM audit_event
			 WHERE tenant_id = $1 AND action IN ('admin.dept.create','admin.dept.rename')`,
			ct.tenantID).Scan(&n)
		if n >= 2 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if n < 2 {
		t.Fatalf("部门新增/改名应各留一条审计，实际 %d 条", n)
	}
}

func findDeptOrNil(t *testing.T, d map[string]any, name string) (map[string]any, bool) {
	t.Helper()
	items, _ := d["items"].([]any)
	for _, it := range items {
		m := it.(map[string]any)
		if m["name"] == name {
			return m, true
		}
	}
	return nil, false
}
