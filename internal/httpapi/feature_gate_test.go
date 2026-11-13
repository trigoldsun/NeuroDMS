package httpapi

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

// 外发开关的完整闭环：全局暂停 → 租户覆盖开通 → 租户覆盖关闭。
//
// 这个用例对应一次现场问题：平台把 share.external 的放量从 100 调到 0
// （总开关仍是"开启"），运营台显示"已开启"，而所有租户创建外链都收到
// "未开启对外分享能力，请联系平台运营"；运营打开控制台找不到任何关闭动作。
//
// 三件事必须同时成立：
//  1. 放量 0% 等于关闭（求值正确）；
//  2. 拒绝文案说清是"放量"导致（否则运营不知道去改哪个格子）；
//  3. 能只给单个租户开通/关闭（覆盖优先，且双向成立）。
func TestExternalShareFeatureGateAndTenantOverride(t *testing.T) {
	var apiRef *API
	srv, pool, slug := setupWith(t, func(a *API) { apiRef = a })
	tok := login(t, srv.URL, slug)
	tenantID := tenantOf(t, pool, slug)
	ctx := context.Background()

	// feature_flag 是全局表，用例之间共享；无论成败都复原。
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx,
			`UPDATE feature_flag SET default_enabled = true, rollout_percent = 100 WHERE code = 'share.external'`)
		_, _ = pool.Exec(ctx, `DELETE FROM tenant_feature WHERE tenant_id = $1`, tenantID)
		apiRef.Features.Invalidate()
	})

	node := uploadToSpace(t, srv.URL, tok, "gate.txt", "share-gate")
	nodeID := node["nodeId"].(string)
	shareReq := map[string]any{"objectType": "node", "objectId": nodeID, "allowDownload": true}

	// 1) 总开关开启 + 放量 0%：这是"暂停"形态，必须拒绝，并点名放量
	if _, err := pool.Exec(ctx,
		`UPDATE feature_flag SET default_enabled = true, rollout_percent = 0 WHERE code = 'share.external'`); err != nil {
		t.Fatal(err)
	}
	apiRef.Features.Invalidate()

	resp, body := postJSON(t, srv.URL+"/v1/shares", tok, shareReq)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("放量 0%% 应拒绝创建外链，实际 %d: %v", resp.StatusCode, body)
	}
	if code, _ := body["code"].(string); code != "FEATURE_DISABLED" {
		t.Fatalf("错误码应为 FEATURE_DISABLED，实际 %v", body["code"])
	}
	if msg, _ := body["message"].(string); !strings.Contains(msg, "放量 0%") {
		t.Fatalf("提示必须说清是放量导致（运营才知道去哪改），实际 %q", msg)
	}

	// 2) 只给该租户加覆盖：不改全局放量，个体开通
	if _, err := pool.Exec(ctx, `
		INSERT INTO tenant_feature (tenant_id, code, enabled) VALUES ($1, 'share.external', true)
		ON CONFLICT (tenant_id, code) DO UPDATE SET enabled = true`, tenantID); err != nil {
		t.Fatal(err)
	}
	apiRef.Features.Invalidate()

	resp, body = postJSON(t, srv.URL+"/v1/shares", tok, shareReq)
	if resp.StatusCode != 200 {
		t.Fatalf("租户覆盖后应可创建外链，实际 %d: %v", resp.StatusCode, body)
	}

	// 3) 覆盖关闭时即使全局满量也拒绝：覆盖的优先级必须双向成立，
	//    否则"给某客户单独关掉外发"（合规常见）是无效配置。
	if _, err := pool.Exec(ctx,
		`UPDATE feature_flag SET default_enabled = true, rollout_percent = 100 WHERE code = 'share.external'`); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(ctx,
		`UPDATE tenant_feature SET enabled = false WHERE tenant_id = $1 AND code = 'share.external'`, tenantID); err != nil {
		t.Fatal(err)
	}
	apiRef.Features.Invalidate()

	resp, body = postJSON(t, srv.URL+"/v1/shares", tok, shareReq)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("租户级关闭应压过全局开启，实际 %d: %v", resp.StatusCode, body)
	}
	if msg, _ := body["message"].(string); !strings.Contains(msg, "单独关闭") {
		t.Fatalf("覆盖关闭时提示应说明是租户级设置，实际 %q", msg)
	}
}
