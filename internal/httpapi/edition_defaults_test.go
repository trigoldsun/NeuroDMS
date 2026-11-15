package httpapi

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"docvault/internal/rbac"
)

// 增值功能的"默认停用"必须在**写入口**成立，而不只是界面不显示。
//
// 这一组用例锁住三件事：
//  1. 基础版不允许写非 0 的成员密级（历史上能写，界面还列了 7 档）；
//  2. 专业版只允许 {0,3,4}，其余档位拒绝；
//  3. 降档要把成员密级一起校验——否则降档后账号上残留的高密级会"冬眠"，
//     再升档时又复活，客户无法解释。

func TestBasicTenantRejectsMemberClassification(t *testing.T) {
	srv, pool, _ := setup(t)
	ct := createTenant(t, pool, srv.URL, "clsb")
	// 开通时是 business，切成 basic（首管理员密级为 0，降档校验应通过）。
	if _, err := pool.Exec(context.Background(),
		`UPDATE tenant SET edition = 'basic' WHERE id = $1`, ct.tenantID); err != nil {
		t.Fatalf("切换档位失败: %v", err)
	}

	// 1) 显式指定 6 级 → 403 FEATURE_NOT_ENABLED
	resp, body := postJSON(t, srv.URL+"/v1/admin/members", ct.token, map[string]any{
		"username": "u_secret", "displayName": "越级", "password": "member-pass-1",
		"classification": 6,
	})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("基础版写入 6 级应 403，实际 %d: %v", resp.StatusCode, body)
	}
	// 错误响应是顶层的 code/message（没有 data 包裹），别用 dataMap
	if code := body["code"]; code != "FEATURE_NOT_ENABLED" {
		t.Fatalf("错误码应为 FEATURE_NOT_ENABLED，实际 %v", code)
	}

	// 2) 不传密级 → 成功，且落库为 0（不能因为默认值写出一个不存在的档位）
	resp, body = postJSON(t, srv.URL+"/v1/admin/members", ct.token, map[string]any{
		"username": "u_plain", "displayName": "普通", "password": "member-pass-1",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("基础版建号（不传密级）应成功，实际 %d: %v", resp.StatusCode, body)
	}
	if got := dataMap(t, body)["classification"]; got != float64(0) {
		t.Fatalf("基础版成员密级应为 0，实际 %v", got)
	}

	// 3) 编辑已有成员提到 4 级 → 同样拒绝
	memberID := dataMap(t, body)["id"].(string)
	resp, body = sendJSONMap(t, http.MethodPatch, srv.URL+"/v1/admin/members/"+memberID,
		ct.token, map[string]any{"classification": 4})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("基础版改成员密级应 403，实际 %d: %v", resp.StatusCode, body)
	}

	// 4) 密级定义也不该能改：客户能改的每一项都应当真的生效
	resp, body = sendJSONMap(t, http.MethodPut, srv.URL+"/v1/admin/classifications/3",
		ct.token, map[string]any{"name": "秘密", "description": ""})
	// 该接口要求 secadmin；admin 只有 sysadmin → 403。这里只断言"不是 200"，
	// 真正的能力判定在下一步用 secadmin 账号验证。
	if resp.StatusCode == http.StatusOK {
		t.Fatalf("基础版不应能改密级定义，实际 %d: %v", resp.StatusCode, body)
	}
}

func TestProfessionalTenantClassRange(t *testing.T) {
	srv, pool, _ := setup(t)
	ct := createTenant(t, pool, srv.URL, "clsp")
	if _, err := pool.Exec(context.Background(),
		`UPDATE tenant SET edition = 'professional' WHERE id = $1`, ct.tenantID); err != nil {
		t.Fatalf("切换档位失败: %v", err)
	}
	// 操作者密级要够：专业版允许 3/4，先把 admin 提到 4（直接改库，绕过写入口）
	if _, err := pool.Exec(context.Background(),
		`UPDATE app_user SET classification = 4 WHERE tenant_id = $1 AND username = 'admin'`,
		ct.tenantID); err != nil {
		t.Fatalf("准备操作者密级失败: %v", err)
	}

	// 3 级允许
	resp, body := postJSON(t, srv.URL+"/v1/admin/members", ct.token, map[string]any{
		"username": "p_sec", "displayName": "秘密", "password": "member-pass-1",
		"classification": 3,
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("专业版 3 级应允许，实际 %d: %v", resp.StatusCode, body)
	}

	// 5 级拒绝（专业版只有 0/3/4）
	resp, body = postJSON(t, srv.URL+"/v1/admin/members", ct.token, map[string]any{
		"username": "p_top", "displayName": "绝密", "password": "member-pass-1",
		"classification": 5,
	})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("专业版 5 级应 403，实际 %d: %v", resp.StatusCode, body)
	}
}

func TestBusinessTenantAllowsFullRange(t *testing.T) {
	srv, pool, _ := setup(t)
	ct := createTenant(t, pool, srv.URL, "clsf") // createTenant 已升到 business
	if _, err := pool.Exec(context.Background(),
		`UPDATE app_user SET classification = 6 WHERE tenant_id = $1 AND username = 'admin'`,
		ct.tenantID); err != nil {
		t.Fatalf("准备操作者密级失败: %v", err)
	}
	resp, body := postJSON(t, srv.URL+"/v1/admin/members", ct.token, map[string]any{
		"username": "f_top", "displayName": "核心", "password": "member-pass-1",
		"classification": 6,
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("旗舰版 6 级应允许，实际 %d: %v", resp.StatusCode, body)
	}
}

// 开通租户时首个管理员必须是 0 级：否则基础版租户一诞生就带着"档位不允许"的数据。
func TestProvisionedAdminStartsAtLevelZero(t *testing.T) {
	srv, pool, _ := setup(t)
	ct := createTenant(t, pool, srv.URL, "clsz")
	var level int
	if err := pool.QueryRow(context.Background(), `
		SELECT classification FROM app_user
		 WHERE tenant_id = $1 AND username = 'admin' AND deleted_at IS NULL`,
		ct.tenantID).Scan(&level); err != nil {
		t.Fatalf("读取首管理员密级失败: %v", err)
	}
	if level != 0 {
		t.Fatalf("首管理员密级应为 0，实际 %d", level)
	}
}

// 降档校验必须把成员密级算进来：只看对象会让"账号上的高密级"逃过检查。
func TestDowngradeBlockedByMemberClassification(t *testing.T) {
	srv, pool, _ := setup(t)
	ct := createTenant(t, pool, srv.URL, "down")
	if _, err := pool.Exec(context.Background(),
		`UPDATE app_user SET classification = 4 WHERE tenant_id = $1 AND username = 'admin'`,
		ct.tenantID); err != nil {
		t.Fatalf("准备成员密级失败: %v", err)
	}

	resp, body := platJSON(t, http.MethodPut, srv.URL+"/v1/platform/tenants/"+ct.slug+"/edition",
		map[string]any{"edition": "basic"})
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("存在 4 级成员时降基础版应 409，实际 %d: %v", resp.StatusCode, body)
	}
	if body["code"] != "EDITION_DOWNGRADE_BLOCKED" {
		t.Fatalf("错误码应为 EDITION_DOWNGRADE_BLOCKED，实际 %v", body["code"])
	}
	samples, _ := dataMap(t, body)["samples"].([]any)
	joined := fmt.Sprint(samples)
	if !strings.Contains(joined, "成员") {
		t.Fatalf("样本里应提示是成员被挡: %v", samples)
	}

	// 清零后可降
	if _, err := pool.Exec(context.Background(),
		`UPDATE app_user SET classification = 0 WHERE tenant_id = $1`, ct.tenantID); err != nil {
		t.Fatalf("清理密级失败: %v", err)
	}
	resp, body = platJSON(t, http.MethodPut, srv.URL+"/v1/platform/tenants/"+ct.slug+"/edition",
		map[string]any{"edition": "basic"})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("清零后应能降档，实际 %d: %v", resp.StatusCode, body)
	}
}

// 专业版只允许 {0,3,4}：降档时 1/2/5/6 都要挡（不只是 >0）。
func TestDowngradeToProfessionalBlocksOddLevels(t *testing.T) {
	srv, pool, _ := setup(t)
	ct := createTenant(t, pool, srv.URL, "downp")
	// 造一个 2 级成员（旗舰版合法，专业版不合法）
	if _, err := pool.Exec(context.Background(), `
		INSERT INTO app_user (id, tenant_id, username, display_name, password_hash,
		                      status, classification)
		VALUES (gen_random_uuid(), $1, 'lvl2', '二级', 'x', 'active', 2)`, ct.tenantID); err != nil {
		t.Fatalf("造 2 级成员失败: %v", err)
	}
	resp, body := platJSON(t, http.MethodPut, srv.URL+"/v1/platform/tenants/"+ct.slug+"/edition",
		map[string]any{"edition": "professional"})
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("存在 2 级成员时降专业版应 409，实际 %d: %v", resp.StatusCode, body)
	}
}

// 密级定义与标签策略：没有密级能力的租户不该能改（改了也不生效）。
func TestClassLabelRequiresCapability(t *testing.T) {
	srv, pool, _ := setup(t)
	ct := createTenant(t, pool, srv.URL, "clsl")
	if _, err := pool.Exec(context.Background(),
		`UPDATE tenant SET edition = 'basic' WHERE id = $1`, ct.tenantID); err != nil {
		t.Fatalf("切换档位失败: %v", err)
	}
	// 需要一个 secadmin 才能走到能力判定（否则先被角色拦掉）
	sec := seedUser(t, srv.URL, ct.slug, "sec-cls")
	seedRole(t, pool, ct.tenantID, userIDByName(t, ct.slug, "sec-cls"), rbac.SecAdmin)

	resp, body := sendJSONMap(t, http.MethodPut, srv.URL+"/v1/admin/classifications/3",
		sec, map[string]any{"name": "秘密", "description": ""})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("基础版改密级定义应 403，实际 %d: %v", resp.StatusCode, body)
	}
	if code := body["code"]; code != "FEATURE_NOT_ENABLED" {
		t.Fatalf("错误码应为 FEATURE_NOT_ENABLED，实际 %v", code)
	}

	resp, body = sendJSONMap(t, http.MethodPut, srv.URL+"/v1/admin/label-policies/L3",
		sec, map[string]any{"minLevel": 3})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("基础版改标签策略应 403，实际 %d: %v", resp.StatusCode, body)
	}
}

// 开通时首个管理员的密级 = 该档位允许的最高值（基础版为 0）。
//
// 回归背景：1.5.0 把首管理员密级写死成 0，结果专业版/旗舰版的管理员
// 一上来就建不出任何有密级的账号，也升不了自己（"定密不超自身"同样管自己），
// 客户只能找运维改库。开通是平台的显式授权动作，应当把这份信任一次性给足。
func TestProvisionedAdminClassFollowsEdition(t *testing.T) {
	srv, pool, _ := setup(t)
	for _, tc := range []struct {
		ed   string
		want float64
	}{
		{"basic", 0},
		{"professional", 4},
		{"business", 6},
	} {
		slug := fmt.Sprintf("cls-%s-%d", tc.ed, time.Now().UnixNano())
		resp, body := platJSON(t, http.MethodPost, srv.URL+"/v1/platform/tenants", map[string]any{
			"slug": slug, "name": "密级默认值 " + tc.ed,
			"edition":       tc.ed,
			"adminUsername": "admin", "adminPassword": "cls-test-password-1",
		})
		if resp.StatusCode != 200 {
			t.Fatalf("[%s] 开通失败 %d: %v", tc.ed, resp.StatusCode, body)
		}
		tid := dataMap(t, body)["tenantId"].(string)
		t.Cleanup(func() { dbtestCleanup(t, pool, tid) })

		token := loginWith(t, srv.URL, slug, "admin", "cls-test-password-1")
		resp, body = getJSON(t, srv.URL+"/v1/me", token)
		if resp.StatusCode != 200 {
			t.Fatalf("[%s] 读 /v1/me 失败 %d", tc.ed, resp.StatusCode)
		}
		if got := dataMap(t, body)["classification"]; got != tc.want {
			t.Fatalf("[%s] 首管理员密级应为 %v，实际 %v", tc.ed, tc.want, got)
		}
	}
}

// 管理员不得造出比自己密级更高的账号，也不得改口令接管这类账号。
//
// 两条是同一个问题的两个入口：只拦建号，低密级管理员仍可重置高密级用户的口令、
// 用对方身份登录读到核心文件——那样"定密不超自身"等于没设。
func TestAdminCannotMintOrTakeOverHigherClass(t *testing.T) {
	srv, pool, _ := setup(t)
	slug := fmt.Sprintf("cls-guard-%d", time.Now().UnixNano())
	// 用旗舰版（0–6 全开），这样"被拒"只可能来自密级比较，
	// 不会被档位裁剪混进来（专业版只允许 {0,3,4}，造不出"档位允许但高于自己"的情况）。
	resp, body := platJSON(t, http.MethodPost, srv.URL+"/v1/platform/tenants", map[string]any{
		"slug": slug, "name": "密级越权验证",
		"edition":       "business",
		"adminUsername": "admin", "adminPassword": "cls-guard-password-1",
	})
	if resp.StatusCode != 200 {
		t.Fatalf("开通失败 %d: %v", resp.StatusCode, body)
	}
	tid := dataMap(t, body)["tenantId"].(string)
	t.Cleanup(func() { dbtestCleanup(t, pool, tid) })
	// 把管理员压到 4 级，模拟"低密级管理员"（首管理员默认是档位上限 6）。
	if _, err := pool.Exec(context.Background(),
		`UPDATE app_user SET classification = 4 WHERE tenant_id = $1 AND username = 'admin'`, tid); err != nil {
		t.Fatalf("准备低密级管理员失败: %v", err)
	}
	token := loginWith(t, srv.URL, slug, "admin", "cls-guard-password-1")

	// 1) 建 6 级（高于自己 4 级）→ 403
	resp, body = postJSON(t, srv.URL+"/v1/admin/members", token, map[string]any{
		"username": "u6", "displayName": "越级", "password": "member-pass-1",
		"classification": 6,
	})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("建 6 级账号应 403，实际 %d: %v", resp.StatusCode, body)
	}
	if code := body["code"]; code != "CEILING_EXCEEDED" {
		t.Fatalf("错误码应为 CEILING_EXCEEDED，实际 %v", code)
	}

	// 2) 建 4 级（等于自己）→ 成功
	resp, body = postJSON(t, srv.URL+"/v1/admin/members", token, map[string]any{
		"username": "u4", "displayName": "同级", "password": "member-pass-1",
		"classification": 4,
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("建 4 级账号应成功，实际 %d: %v", resp.StatusCode, body)
	}
	u4 := dataMap(t, body)["id"].(string)

	// 3) 把该成员改到 6 级 → 403
	resp, body = sendJSONMap(t, http.MethodPatch, srv.URL+"/v1/admin/members/"+u4,
		token, map[string]any{"classification": 6})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("改到 6 级应 403，实际 %d: %v", resp.StatusCode, body)
	}

	// 4) 借库把他抬到 6 级（模拟"由更高密级管理员创建"的账号），
	//    再用 4 级管理员重置其口令 → 必须 403（否则等于绕过第 1 步）
	if _, err := pool.Exec(context.Background(),
		`UPDATE app_user SET classification = 6, ceiling = 6 WHERE id = $1`, u4); err != nil {
		t.Fatalf("准备高密级账号失败: %v", err)
	}
	resp, body = postJSON(t, srv.URL+"/v1/admin/members/"+u4+"/password", token, map[string]any{
		"password": "hijack-pass-1",
	})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("重置高密级账号口令应 403，实际 %d: %v", resp.StatusCode, body)
	}

	// 5) 同密级账号的口令仍可重置（不能把"防提权"做成"管理员什么都不能干"）
	if _, err := pool.Exec(context.Background(),
		`UPDATE app_user SET classification = 4 WHERE id = $1`, u4); err != nil {
		t.Fatalf("恢复密级失败: %v", err)
	}
	resp, body = postJSON(t, srv.URL+"/v1/admin/members/"+u4+"/password", token, map[string]any{
		"password": "rotate-pass-1",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("重置同密级账号口令应成功，实际 %d: %v", resp.StatusCode, body)
	}
}
