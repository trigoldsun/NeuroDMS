package httpapi

// AC-27 / AC-28 批量操作：任何一个对象无权，整批不执行。

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"docvault/internal/authz"
)

// AC-27：批量下载里混入一个无下载权的对象 → 整批拒绝，且不返回任何内容。
func TestAC27BatchDownloadRejectsWholeBatch(t *testing.T) {
	srv, pool, slug := setup(t)
	owner := login(t, srv.URL, slug)
	_, body := postJSON(t, srv.URL+"/v1/spaces", owner, map[string]any{"kind": "project", "name": "批量空间"})
	spaceID := dataMap(t, body)["spaceId"].(string)

	var ids []string
	for _, name := range []string{"a.txt", "b.txt", "c.txt"} {
		_, up := upload(t, srv.URL+"/v1/spaces/"+spaceID+"/files", owner, name, "内容-"+name)
		ids = append(ids, dataMap(t, up)["nodeId"].(string))
	}

	eve := seedUser(t, srv.URL, slug, "eve27")
	eveID := userIDByName(t, slug, "eve27")
	tenantID := tenantOf(t, pool, slug)

	// 前两个给完整下载权，第三个只给 display
	grantBits(t, pool, tenantID, "node", ids[0], eveID, int64(authz.PresetEditor.Bits()))
	grantBits(t, pool, tenantID, "node", ids[1], eveID, int64(authz.PresetEditor.Bits()))
	grantBits(t, pool, tenantID, "node", ids[2], eveID, int64(authz.Display))

	resp, raw := sendJSON(t, http.MethodPost, srv.URL+"/v1/batch/download", eve,
		map[string]any{"nodeIds": ids})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("AC-27 混入无权对象应整体 403，实际 %d: %s", resp.StatusCode, raw)
	}
	// 必须是错误 JSON，不能是 zip（zip 里就是泄露）
	if ct := resp.Header.Get("Content-Type"); strings.Contains(ct, "zip") {
		t.Fatalf("AC-27 拒绝时不应返回 zip: %s", ct)
	}
	assertNoLeak(t, raw, "内容-a.txt")

	// 反向确认：把第三个也授权后可以拿到 zip
	grantBits(t, pool, tenantID, "node", ids[2], eveID, int64(authz.PresetEditor.Bits()))
	resp, raw = sendJSON(t, http.MethodPost, srv.URL+"/v1/batch/download", eve,
		map[string]any{"nodeIds": ids})
	if resp.StatusCode != 200 {
		t.Fatalf("AC-27 全部有权时应成功，实际 %d: %s", resp.StatusCode, raw)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "zip") {
		t.Fatalf("AC-27 应返回 zip，实际 %s", ct)
	}
	if len(raw) < 100 {
		t.Fatalf("zip 内容过小，可能没写入: %d 字节", len(raw))
	}
}

// AC-28：批量移动里混入一个无删除权的对象 → 整批不移动。
func TestAC28BatchMoveRejectsWholeBatch(t *testing.T) {
	srv, pool, slug := setup(t)
	owner := login(t, srv.URL, slug)
	_, body := postJSON(t, srv.URL+"/v1/spaces", owner, map[string]any{"kind": "project", "name": "移动空间"})
	spaceID := dataMap(t, body)["spaceId"].(string)
	_, f1 := postJSON(t, srv.URL+"/v1/spaces/"+spaceID+"/folders", owner, map[string]any{"name": "目标目录"})
	targetID := dataMap(t, f1)["folderId"].(string)

	var ids []string
	for _, name := range []string{"m1.txt", "m2.txt"} {
		_, up := upload(t, srv.URL+"/v1/spaces/"+spaceID+"/files", owner, name, "x")
		ids = append(ids, dataMap(t, up)["nodeId"].(string))
	}

	eve := seedUser(t, srv.URL, slug, "eve28")
	eveID := userIDByName(t, slug, "eve28")
	tenantID := tenantOf(t, pool, slug)

	// 对目标目录给 create；对 m1 给完整权限（含 delete）；m2 只给 display
	grantBits(t, pool, tenantID, "node", targetID, eveID, int64(authz.PresetContributor.Bits()))
	grantBits(t, pool, tenantID, "node", ids[0], eveID, int64(authz.PresetEditor.Bits()|authz.Delete))
	grantBits(t, pool, tenantID, "node", ids[1], eveID, int64(authz.Display))

	resp, raw := sendJSON(t, http.MethodPost, srv.URL+"/v1/batch/move", eve,
		map[string]any{"nodeIds": ids, "targetParentId": targetID})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("AC-28 混入无权对象应整体 403，实际 %d: %s", resp.StatusCode, raw)
	}

	// 关键断言：m1 也不能被"顺手移走"（整体拒绝）
	var parent1 *string
	if err := pool.QueryRow(context.Background(),
		`SELECT parent_id::text FROM node WHERE id = $1`, ids[0]).Scan(&parent1); err != nil {
		t.Fatal(err)
	}
	if parent1 != nil {
		t.Fatalf("AC-28 整批拒绝时 m1 不应被移动，实际 parent=%v", *parent1)
	}
}

// 批量接口的数量上限必须存在，否则一次请求就能把服务拖死。
func TestBatchLimitEnforced(t *testing.T) {
	srv, _, slug := setup(t)
	owner := login(t, srv.URL, slug)
	ids := make([]string, 101)
	for i := range ids {
		ids[i] = "00000000-0000-0000-0000-000000000000"
	}
	resp, raw := sendJSON(t, http.MethodPost, srv.URL+"/v1/batch/download", owner,
		map[string]any{"nodeIds": ids})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("超过 100 项应 400，实际 %d: %s", resp.StatusCode, raw)
	}
}
