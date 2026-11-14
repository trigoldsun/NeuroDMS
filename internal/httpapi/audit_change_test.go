package httpapi

// 审计里的"改前 / 改后"。
//
// 这组用例锁三件事：
//  1. 只记发生变化的字段（全量快照会把"改了哪一项"埋掉）；
//  2. 没有变化时明确为空，而不是伪造一条"变更"；
//  3. 真正的配置接口落库的 detail 里能读到 before/after——
//     单测 helper 通过不代表接口接上了。

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"docvault/internal/rbac"
)

func TestAuditDiffKeepsOnlyChangedFields(t *testing.T) {
	d := auditDiff(
		map[string]any{"maxUploadMB": 100, "auditRetentionDays": 730},
		map[string]any{"maxUploadMB": 200, "auditRetentionDays": 730},
	)
	changed, _ := d["changed"].([]string)
	if len(changed) != 1 || changed[0] != "maxUploadMB" {
		t.Fatalf("changed 应只含 maxUploadMB，实际 %v", d["changed"])
	}
	before, _ := d["before"].(map[string]any)
	after, _ := d["after"].(map[string]any)
	if before["maxUploadMB"] != 100 || after["maxUploadMB"] != 200 {
		t.Fatalf("前后值不对: before=%v after=%v", before, after)
	}
	if _, ok := before["auditRetentionDays"]; ok {
		t.Fatal("未变化的字段不应出现在 before 里")
	}
}

func TestAuditDiffNoChangeIsExplicit(t *testing.T) {
	d := auditDiff(map[string]any{"maxUploadMB": 100}, map[string]any{"maxUploadMB": 100})
	changed, _ := d["changed"].([]string)
	if len(changed) != 0 {
		t.Fatalf("没有变化时 changed 应为空，实际 %v", changed)
	}
	if _, ok := d["before"]; ok {
		t.Fatal("没有变化时不应输出 before")
	}
}

func TestAuditDiffMissingBeforeMeansUnknown(t *testing.T) {
	// 读不到旧值时必须留空，让界面显示"— → 新值"；
	// 编一个 0 当旧值，事后看审计会以为"原来设的是 0"。
	d := auditDiff(nil, map[string]any{"maxUploadMB": 200})
	changed, _ := d["changed"].([]string)
	if len(changed) != 1 {
		t.Fatalf("应把全部字段视为变更，实际 %v", changed)
	}
	before, _ := d["before"].(map[string]any)
	if _, ok := before["maxUploadMB"]; ok {
		t.Fatal("旧值未知时不应编造 before")
	}
}

// TestPolicyChangeRecordsBeforeAfter 走真实接口：改策略 → 库里 detail 有前后值。
func TestPolicyChangeRecordsBeforeAfter(t *testing.T) {
	srv, pool, slug := setupWith(t, nil)
	tenantID := tenantOf(t, pool, slug)
	seedRole(t, pool, tenantID, userIDByName(t, slug, "bob"), rbac.SysAdmin)
	tok := login(t, srv.URL, slug)

	_, body := getJSON(t, srv.URL+"/v1/admin/policy", tok)
	cur := dataMap(t, body)
	oldMax := int(cur["maxUploadMB"].(float64))
	if oldMax == 300 {
		oldMax = 100
	}

	resp, out := sendJSONMap(t, http.MethodPut, srv.URL+"/v1/admin/policy", tok, map[string]any{
		"maxUploadMB": 300,
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("保存策略失败 %d: %v", resp.StatusCode, out)
	}

	var raw []byte
	if err := pool.QueryRow(context.Background(), `
		SELECT detail FROM audit_event
		 WHERE tenant_id = $1 AND action = 'tenant.policy.update'
		 ORDER BY seq DESC LIMIT 1`, tenantID).Scan(&raw); err != nil {
		t.Fatalf("读取审计失败: %v", err)
	}
	var detail map[string]any
	if err := json.Unmarshal(raw, &detail); err != nil {
		t.Fatalf("解析 detail 失败: %v", err)
	}
	if detail["before"] == nil || detail["after"] == nil {
		t.Fatalf("detail 缺少 before/after: %s", raw)
	}
	bef := detail["before"].(map[string]any)
	aft := detail["after"].(map[string]any)
	if bef["maxUploadMB"] != float64(oldMax) {
		t.Fatalf("改前值应为 %d，实际 %v", oldMax, bef["maxUploadMB"])
	}
	if aft["maxUploadMB"] != float64(300) {
		t.Fatalf("改后值应为 300，实际 %v", aft["maxUploadMB"])
	}
	// 只改了一项：其他参数不该出现在对照里（否则界面上看不出改了哪一项）
	for k := range bef {
		if k != "maxUploadMB" {
			t.Fatalf("未变化的字段不应进入对照: %s", k)
		}
	}

	// 再原样保存一次：应记成"没有变化"，而不是又一条变更
	resp, out = sendJSONMap(t, http.MethodPut, srv.URL+"/v1/admin/policy", tok, map[string]any{
		"maxUploadMB": 300,
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("二次保存失败 %d: %v", resp.StatusCode, out)
	}
	if err := pool.QueryRow(context.Background(), `
		SELECT detail FROM audit_event
		 WHERE tenant_id = $1 AND action = 'tenant.policy.update'
		 ORDER BY seq DESC LIMIT 1`, tenantID).Scan(&raw); err != nil {
		t.Fatalf("读取审计失败: %v", err)
	}
	if err := json.Unmarshal(raw, &detail); err != nil {
		t.Fatalf("解析 detail 失败: %v", err)
	}
	if ch, _ := detail["changed"].([]any); len(ch) != 0 {
		t.Fatalf("原样保存不应记成变更，changed=%v", detail["changed"])
	}
}
