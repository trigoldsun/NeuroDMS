package httpapi

// AC-14 平台运营跨租户读：必须只读、必须有独立凭据、必须留痕。

import (
	"context"
	"net/http"
	"testing"
)

// AC-14：平台运营的跨租户访问只认独立令牌，且每次访问都在目标租户留下痕迹。
func TestAC14PlatformCrossTenantIsReadOnlyAndAudited(t *testing.T) {
	srv, pool, slug := setupWith(t, func(a *API) {
		a.PlatformToken = "plat-token-for-test"
	})
	tenantID := tenantOf(t, pool, slug)

	// 1) 未配置/未携带令牌 → 401（fail-closed，不能因为"忘了配"就公开）
	if r, raw := getRaw(t, srv.URL+"/v1/platform/stats", ""); r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("AC-14 无令牌应 401，实际 %d: %s", r.StatusCode, raw)
	}

	// 2) 用户令牌不能当平台令牌用（两套凭据必须互不通用）
	userToken := login(t, srv.URL, slug)
	if r, raw := getRaw(t, srv.URL+"/v1/platform/stats", userToken); r.StatusCode != http.StatusUnauthorized {
		t.Fatalf("AC-14 用户令牌不应通过平台鉴权，实际 %d: %s", r.StatusCode, raw)
	}

	// 3) 正确令牌 → 只返回汇总数字
	resp, body := getJSON(t, srv.URL+"/v1/platform/stats", "plat-token-for-test")
	if resp.StatusCode != 200 {
		t.Fatalf("AC-14 平台统计应 200，实际 %d: %v", resp.StatusCode, body)
	}
	d := dataMap(t, body)
	if d["tenants"] == nil || d["users"] == nil || d["files"] == nil {
		t.Fatalf("AC-14 统计字段缺失: %v", d)
	}
	// 汇总里不得出现任何租户名/slug 等明细
	for _, k := range []string{"items", "tenantList", "details"} {
		if _, ok := d[k]; ok {
			t.Fatalf("AC-14 平台统计不应返回明细字段 %s: %v", k, d)
		}
	}

	// 4) 跨租户读审计 → 允许，且在目标租户写入 platform.access
	if r, raw := getRaw(t, srv.URL+"/v1/platform/tenants/"+slug+"/audit/events", "plat-token-for-test"); r.StatusCode != 200 {
		t.Fatalf("AC-14 平台读审计应 200，实际 %d: %s", r.StatusCode, raw)
	}
	var n int
	if err := pool.QueryRow(context.Background(), `
		SELECT count(*) FROM audit_event WHERE tenant_id=$1 AND action='platform.access'`,
		tenantID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n < 1 {
		t.Fatal("AC-14 平台访问必须在目标租户留痕")
	}

	// 5) 平台端点只读：写方法不应被注册（405/404 都算正确拒绝）
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/v1/platform/stats", nil)
	req.Header.Set("Authorization", "Bearer plat-token-for-test")
	w, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Body.Close()
	if w.StatusCode == 200 {
		t.Fatalf("AC-14 平台端点不应接受写方法，实际 %d", w.StatusCode)
	}

	// 6) 不存在的租户 → 404，不泄露是否为合法 slug
	if r, _ := getRaw(t, srv.URL+"/v1/platform/tenants/no-such-tenant/audit/events", "plat-token-for-test"); r.StatusCode != http.StatusNotFound {
		t.Fatalf("AC-14 不存在的租户应 404，实际 %d", r.StatusCode)
	}
}
