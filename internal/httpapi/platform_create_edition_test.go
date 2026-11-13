package httpapi

// 开通时指定档位（docs/23 §5 的补口）。
//
// 改动前：开通接口没有档位参数，新租户恒为 basic；运营必须再进详情页改档。
// 漏做一步就是"客户拿专业版合同用基础版"，而且后台看不出来——
// 列表里显示的 plan 是个没人读的自由文本，写着 standard，看起来像设过了。
//
// 所以这里除了验证"档位被写进去"，还要验证三件更容易漏的事：
//   - plan 与 edition 恒等（历史字段不再单独撒谎）；
//   - 变更历史有一条来源为"开通时指定"的记录；
//   - 客户侧能力**立刻**按新档位生效（不是等下次改档）。

import (
	"context"
	"fmt"
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

// AC-EDITION-CREATE：开通时直接授予专业版，一路贯通到客户侧能力。
func TestCreateTenantWithEdition(t *testing.T) {
	srv, pool, _ := setup(t)
	ctx := context.Background()
	slug := fmt.Sprintf("ed-create-%d", atomic.AddInt64(&tenantSeq, 1))

	resp, body := platJSON(t, http.MethodPost, srv.URL+"/v1/platform/tenants", map[string]any{
		"slug": slug, "name": "专业版客户",
		"edition":          "professional",
		"editionExpiresAt": "2027-12-31",
		"adminUsername":    "admin", "adminPassword": "edition-test-pass-1",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("开通失败 %d: %v", resp.StatusCode, body)
	}
	tenantID := dataMap(t, body)["tenantId"].(string)
	t.Cleanup(func() { dbtestCleanup(t, pool, tenantID) })

	// 1. 库里：档位、到期日、plan 镜像
	var ed, plan string
	var expires *time.Time
	if err := pool.QueryRow(ctx,
		`SELECT edition, plan, edition_expires_at FROM tenant WHERE id = $1`, tenantID).
		Scan(&ed, &plan, &expires); err != nil {
		t.Fatal(err)
	}
	if ed != "professional" {
		t.Fatalf("开通后档位应为 professional，实际 %q", ed)
	}
	if plan != ed {
		t.Fatalf("plan 必须是 edition 的镜像（触发器保证），实际 plan=%q edition=%q", plan, ed)
	}
	if expires == nil {
		t.Fatal("到期日未写入")
	}
	// 日期形式按当日结束解释：用零点会让客户提前一天失效，且很难解释
	if got := expires.In(time.Local).Format("2006-01-02"); got != "2027-12-31" {
		t.Fatalf("到期日应为 2027-12-31，实际 %s", got)
	}
	if h, m, s := expires.In(time.Local).Clock(); h != 23 || m != 59 || s != 59 {
		t.Fatalf("到期日应取当日 23:59:59，实际 %02d:%02d:%02d", h, m, s)
	}

	// 2. 变更历史：与改档共用一张表，"什么时候变成专业版"只有一处答案
	var changes int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM tenant_edition_change
		  WHERE tenant_id = $1 AND to_edition = 'professional' AND from_edition IS NULL`,
		tenantID).Scan(&changes); err != nil {
		t.Fatal(err)
	}
	if changes != 1 {
		t.Fatalf("应记录 1 条开通时的档位变更，实际 %d", changes)
	}

	// 3. 平台详情接口要返回真实档位（列表/详情此前只有那个没人读的 plan）
	r, b := getJSON(t, srv.URL+"/v1/platform/tenants/"+slug, platTok)
	if r.StatusCode != http.StatusOK {
		t.Fatalf("读取租户失败 %d: %v", r.StatusCode, b)
	}
	if got := dataMap(t, b)["edition"]; got != "professional" {
		t.Fatalf("详情接口 edition 应为 professional，实际 %v", got)
	}

	// 4. 客户侧：能力立刻按专业版，不需要"再改一次档"
	tok := loginWith(t, srv.URL, slug, "admin", "edition-test-pass-1")
	r, b = getJSON(t, srv.URL+"/v1/me/capabilities", tok)
	if r.StatusCode != http.StatusOK {
		t.Fatalf("能力接口失败 %d: %v", r.StatusCode, b)
	}
	caps := dataMap(t, b)
	if caps["edition"] != "professional" || caps["editionName"] != "专业版" {
		t.Fatalf("能力接口档位应为专业版，实际 %v / %v", caps["edition"], caps["editionName"])
	}
	limits, _ := caps["limits"].(map[string]any)
	if limits["versionKeep"] != float64(10) {
		t.Fatalf("专业版版本保留应为 10，实际 %v", limits["versionKeep"])
	}
	if limits["maxUploadMB"] != float64(5120) {
		t.Fatalf("专业版单文件上限应为 5120MB，实际 %v", limits["maxUploadMB"])
	}
}

// 不传档位时按基础版开通：默认值必须与列默认一致，不能出现第三种默认。
func TestCreateTenantDefaultsToBasic(t *testing.T) {
	srv, pool, _ := setup(t)
	slug := fmt.Sprintf("ed-default-%d", atomic.AddInt64(&tenantSeq, 1))

	resp, body := platJSON(t, http.MethodPost, srv.URL+"/v1/platform/tenants", map[string]any{
		"slug": slug, "name": "未指定档位",
		"adminUsername": "admin", "adminPassword": "edition-test-pass-1",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("开通失败 %d: %v", resp.StatusCode, body)
	}
	tenantID := dataMap(t, body)["tenantId"].(string)
	t.Cleanup(func() { dbtestCleanup(t, pool, tenantID) })

	var ed, plan string
	var expires *time.Time
	if err := pool.QueryRow(context.Background(),
		`SELECT edition, plan, edition_expires_at FROM tenant WHERE id = $1`, tenantID).
		Scan(&ed, &plan, &expires); err != nil {
		t.Fatal(err)
	}
	if ed != "basic" || plan != "basic" {
		t.Fatalf("默认档位应为 basic，实际 edition=%q plan=%q", ed, plan)
	}
	if expires != nil {
		t.Fatalf("未填到期日应为不限期，实际 %v", expires)
	}
}

// 未知档位必须报错，不能像读取路径那样静默收敛为基础版。
//
// 收敛在读取侧是对的（脏数据不该让租户不可用），在写入侧是灾难：
// 运营把 professional 打成 pro，会得到"开通成功"和"客户是基础版"。
func TestCreateTenantRejectsUnknownEdition(t *testing.T) {
	srv, pool, _ := setup(t)
	slug := fmt.Sprintf("ed-bad-%d", atomic.AddInt64(&tenantSeq, 1))

	resp, body := platJSON(t, http.MethodPost, srv.URL+"/v1/platform/tenants", map[string]any{
		"slug": slug, "name": "错误档位", "edition": "pro",
		"adminUsername": "admin", "adminPassword": "edition-test-pass-1",
	})
	if resp.StatusCode != http.StatusBadRequest || body["code"] != "INVALID_ARGUMENT" {
		t.Fatalf("未知档位应 400 INVALID_ARGUMENT，实际 %d: %v", resp.StatusCode, body)
	}

	// 校验发生在建行之前：不该留下半个租户
	var n int
	if err := pool.QueryRow(context.Background(),
		`SELECT count(*) FROM tenant WHERE slug = $1`, slug).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("校验失败时不应创建租户，实际存在 %d 条", n)
	}
}

// 到期日格式错误同样要拒绝，而不是悄悄当成不限期。
func TestCreateTenantRejectsBadExpiry(t *testing.T) {
	srv, _, _ := setup(t)
	resp, body := platJSON(t, http.MethodPost, srv.URL+"/v1/platform/tenants", map[string]any{
		"slug": fmt.Sprintf("ed-baddate-%d", atomic.AddInt64(&tenantSeq, 1)),
		"name": "错误日期", "edition": "basic", "editionExpiresAt": "2027/12/31",
		"adminUsername": "admin", "adminPassword": "edition-test-pass-1",
	})
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("错误日期格式应 400，实际 %d: %v", resp.StatusCode, body)
	}
}
