package httpapi

// AC-24 内部分享：与内链/外链的两条位分离必须成立。

import (
	"net/http"
	"testing"

	"docvault/internal/authz"
)

// AC-24：内部分享要求 share_internal；没有该位的人不能"给别人授权"来曲线拿到分享能力。
func TestAC24InternalShareRequiresShareInternalBit(t *testing.T) {
	srv, pool, slug := setup(t)
	owner := login(t, srv.URL, slug)
	_, nodeID := prepareFile(t, srv.URL, owner)
	tenantID := tenantOf(t, pool, slug)

	eve := seedUser(t, srv.URL, slug, "eve24")
	eveID := userIDByName(t, slug, "eve24")
	target := seedUser(t, srv.URL, slug, "target24")
	targetID := userIDByName(t, slug, "target24")

	// eve 只有 editor（含 copy/edit/rename，但**不含** share_internal）
	grantBits(t, pool, tenantID, "node", nodeID, eveID, int64(authz.PresetEditor.Bits()))

	resp, out := sendJSONMap(t, http.MethodPost, srv.URL+"/v1/shares", eve, map[string]any{
		"kind": "internal", "objectType": "node", "objectId": nodeID,
		"subjectType": "user", "subjectIds": []string{targetID}, "preset": "viewer",
	})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("AC-24 缺 share_internal 应 403，实际 %d: %v", resp.StatusCode, out)
	}

	// 反向确认目标用户仍看不到
	if r, _ := getJSON(t, srv.URL+"/v1/nodes/"+nodeID, target); r.StatusCode != 404 {
		t.Fatalf("AC-24 被拒后不应产生授权，实际 %d", r.StatusCode)
	}

	// 补上 share_internal 后可创建，且目标用户立即可见
	grantBits(t, pool, tenantID, "node", nodeID, eveID,
		int64(authz.PresetEditor.Bits()|authz.ShareInternal))
	resp, out = sendJSONMap(t, http.MethodPost, srv.URL+"/v1/shares", eve, map[string]any{
		"kind": "internal", "objectType": "node", "objectId": nodeID,
		"subjectType": "user", "subjectIds": []string{targetID}, "preset": "viewer",
	})
	if resp.StatusCode != 200 {
		t.Fatalf("AC-24 有 share_internal 应成功，实际 %d: %v", resp.StatusCode, out)
	}
	if dataMap(t, out)["count"].(float64) != 1 {
		t.Fatalf("AC-24 应返回 1 条授权: %v", out)
	}
	if r, raw := getJSON(t, srv.URL+"/v1/nodes/"+nodeID, target); r.StatusCode != 200 {
		t.Fatalf("AC-24 内部分享后目标用户应可见，实际 %d: %s", r.StatusCode, raw)
	}
}

// 只有 share_internal 的人不能创建外链：两个位必须分离，不能互相代替。
func TestInternalShareDoesNotImplyExternal(t *testing.T) {
	srv, pool, slug := setup(t)
	owner := login(t, srv.URL, slug)
	_, nodeID := prepareFile(t, srv.URL, owner)
	tenantID := tenantOf(t, pool, slug)

	eve := seedUser(t, srv.URL, slug, "eve24b")
	eveID := userIDByName(t, slug, "eve24b")
	// 只给 display + share_internal（不含 share_external）
	grantBits(t, pool, tenantID, "node", nodeID, eveID,
		int64(authz.Display|authz.ShareInternal))

	resp, out := sendJSONMap(t, http.MethodPost, srv.URL+"/v1/shares", eve, map[string]any{
		"objectType": "node", "objectId": nodeID, "allowDownload": false,
	})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("只有 share_internal 不应能创建外链，实际 %d: %v", resp.StatusCode, out)
	}
	// 但内部分享可以
	resp, out = sendJSONMap(t, http.MethodPost, srv.URL+"/v1/shares", eve, map[string]any{
		"kind": "internal", "objectType": "node", "objectId": nodeID,
		"subjectType": "user", "subjectIds": []string{eveID}, "preset": "viewer",
	})
	if resp.StatusCode != 200 {
		t.Fatalf("内部分享应成功，实际 %d: %v", resp.StatusCode, out)
	}
}

// 内部分享不能突破封顶：给他人授比自己高的档位必须拒（否则它是提权通道）。
func TestInternalShareRespectsCeiling(t *testing.T) {
	srv, pool, slug := setup(t)
	owner := login(t, srv.URL, slug)
	_, nodeID := prepareFile(t, srv.URL, owner)
	tenantID := tenantOf(t, pool, slug)

	eve := seedUser(t, srv.URL, slug, "eve24c")
	eveID := userIDByName(t, slug, "eve24c")
	seedUser(t, srv.URL, slug, "target24c")
	targetID := userIDByName(t, slug, "target24c")

	// eve 拿到该对象的 owner（可授权），但自身 ceiling 降到 2
	grantBits(t, pool, tenantID, "node", nodeID, eveID, int64(authz.AllBits))
	if _, err := pool.Exec(t.Context(), `UPDATE app_user SET ceiling = 2 WHERE id = $1`, eveID); err != nil {
		t.Fatal(err)
	}

	resp, out := sendJSONMap(t, http.MethodPost, srv.URL+"/v1/shares", eve, map[string]any{
		"kind": "internal", "objectType": "node", "objectId": nodeID,
		"subjectType": "user", "subjectIds": []string{targetID}, "preset": "manager",
	})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("内部分享授出超封顶档位应 403，实际 %d: %v", resp.StatusCode, out)
	}
	if out["code"] != "CEILING_EXCEEDED" {
		t.Fatalf("应返回 CEILING_EXCEEDED: %v", out)
	}
}
