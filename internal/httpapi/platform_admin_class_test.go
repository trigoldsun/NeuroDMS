package httpapi

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"
)

// 平台侧"调整系统管理员密级"：既是运营能力，也是密级死锁的唯一出口。
//
// 约束必须同时成立：
//  1. 只能改系统管理员（不是"平台能改任何成员"）；
//  2. 受租户档位约束（基础版只能 0）；
//  3. 改密级要有审计（平台侧 + 租户侧），且幂等不产生噪音。
func TestPlatformAdjustAdminClassification(t *testing.T) {
	srv, pool, _ := setup(t)
	slug := fmt.Sprintf("pcls-%d", time.Now().UnixNano())
	resp, body := platJSON(t, http.MethodPost, srv.URL+"/v1/platform/tenants", map[string]any{
		"slug": slug, "name": "平台调密级", "edition": "business",
		"adminUsername": "admin", "adminPassword": "pcls-password-1",
	})
	if resp.StatusCode != 200 {
		t.Fatalf("开通失败 %d: %v", resp.StatusCode, body)
	}
	tid := dataMap(t, body)["tenantId"].(string)
	t.Cleanup(func() { dbtestCleanup(t, pool, tid) })

	// 档位允许集合与管理员列表由服务端给出，前端不再复制规则
	resp, body = platJSON(t, http.MethodGet, srv.URL+"/v1/platform/tenants/"+slug+"/admins", nil)
	if resp.StatusCode != 200 {
		t.Fatalf("读管理员失败 %d: %v", resp.StatusCode, body)
	}
	d := dataMap(t, body)
	items, _ := d["items"].([]any)
	if len(items) != 1 {
		t.Fatalf("应有 1 个系统管理员，实际 %d", len(items))
	}
	admin := items[0].(map[string]any)
	adminID := admin["id"].(string)
	if admin["classification"] != float64(6) {
		t.Fatalf("旗舰版首管理员应为 6 级，实际 %v", admin["classification"])
	}
	if lv, _ := d["classificationLevels"].([]any); len(lv) != 7 {
		t.Fatalf("旗舰版应返回 7 个可选密级，实际 %v", d["classificationLevels"])
	}

	// 1) 降到 4 级 → 成功，且能读回
	resp, body = platJSON(t, http.MethodPut,
		srv.URL+"/v1/platform/tenants/"+slug+"/admins/"+adminID+"/classification",
		map[string]any{"classification": 4, "reason": "单元测试"})
	if resp.StatusCode != 200 {
		t.Fatalf("调密级失败 %d: %v", resp.StatusCode, body)
	}
	resp, body = platJSON(t, http.MethodGet, srv.URL+"/v1/platform/tenants/"+slug+"/admins", nil)
	if resp.StatusCode != 200 {
		t.Fatalf("复读失败 %d", resp.StatusCode)
	}
	if got := dataMap(t, body)["items"].([]any)[0].(map[string]any)["classification"]; got != float64(4) {
		t.Fatalf("密级应已改为 4，实际 %v", got)
	}

	// 2) 租户侧审计要留痕（客户能看到"谁在什么时候改了谁的密级"）
	var n int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM audit_event
		  WHERE tenant_id = $1 AND action = 'admin.member.classification'`, tid).Scan(&n); err != nil {
		t.Fatalf("查审计失败: %v", err)
	}
	if n == 0 {
		t.Fatal("改密级没有写入租户审计")
	}

	// 3) 非系统管理员不得被平台改密级
	resp, body = postJSON(t, srv.URL+"/v1/admin/members", loginWith(t, srv.URL, slug, "admin", "pcls-password-1"),
		map[string]any{"username": "u", "displayName": "普通", "password": "member-pass-1"})
	if resp.StatusCode != 200 {
		t.Fatalf("建普通成员失败 %d: %v", resp.StatusCode, body)
	}
	uid := dataMap(t, body)["id"].(string)
	resp, body = platJSON(t, http.MethodPut,
		srv.URL+"/v1/platform/tenants/"+slug+"/admins/"+uid+"/classification",
		map[string]any{"classification": 6})
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("改普通成员密级应 404，实际 %d: %v", resp.StatusCode, body)
	}

	// 4) 越界值 → 400
	resp, body = platJSON(t, http.MethodPut,
		srv.URL+"/v1/platform/tenants/"+slug+"/admins/"+adminID+"/classification",
		map[string]any{"classification": 9})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("9 级应 400，实际 %d: %v", resp.StatusCode, body)
	}
}

// 基础版：平台也不能把管理员设成非 0 密级（档位不支持）。
func TestPlatformAdjustAdminClassRespectsEdition(t *testing.T) {
	srv, pool, _ := setup(t)
	slug := fmt.Sprintf("pcls-basic-%d", time.Now().UnixNano())
	resp, body := platJSON(t, http.MethodPost, srv.URL+"/v1/platform/tenants", map[string]any{
		"slug": slug, "name": "基础版调密级", "edition": "basic",
		"adminUsername": "admin", "adminPassword": "pcls-password-1",
	})
	if resp.StatusCode != 200 {
		t.Fatalf("开通失败 %d: %v", resp.StatusCode, body)
	}
	tid := dataMap(t, body)["tenantId"].(string)
	t.Cleanup(func() { dbtestCleanup(t, pool, tid) })

	resp, body = platJSON(t, http.MethodGet, srv.URL+"/v1/platform/tenants/"+slug+"/admins", nil)
	if resp.StatusCode != 200 {
		t.Fatalf("读管理员失败 %d", resp.StatusCode)
	}
	adminID := dataMap(t, body)["items"].([]any)[0].(map[string]any)["id"].(string)

	resp, body = platJSON(t, http.MethodPut,
		srv.URL+"/v1/platform/tenants/"+slug+"/admins/"+adminID+"/classification",
		map[string]any{"classification": 3})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("基础版设 3 级应 403，实际 %d: %v", resp.StatusCode, body)
	}
	if code := body["code"]; code != "FEATURE_NOT_ENABLED" {
		t.Fatalf("错误码应为 FEATURE_NOT_ENABLED，实际 %v", code)
	}
}
