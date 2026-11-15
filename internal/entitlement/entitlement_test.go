package entitlement

// 授权层的集成测试（docs/47 §6 的 P1 验收）。
//
// 覆盖四件事，缺一不可：
//  1. 档位默认：基础版没有密级、有外链；旗舰版全有；
//  2. 三态：on / off / inherit（删行回默认）；
//  3. 过期：特批到期后回落档位默认，且来源标 expired（能解释"为什么没了"）；
//  4. 强制关：平台 lock 覆盖一切，包括 on 的特批。

import (
	"context"
	"os"
	"testing"
	"time"

	"docvault/internal/db"
	"docvault/internal/dbtest"
	"docvault/internal/edition"
	"docvault/migrations"

	"github.com/jackc/pgx/v5/pgxpool"
)

func setup(t *testing.T) (*pgxpool.Pool, *Service, string) {
	t.Helper()
	dsn := os.Getenv("DOCVAULT_TEST_DSN")
	if dsn == "" {
		t.Skip("未设置 DOCVAULT_TEST_DSN，跳过授权集成测试")
	}
	ctx := context.Background()
	pool, err := db.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("连接失败: %v", err)
	}
	t.Cleanup(pool.Close)
	if _, err := db.Migrate(ctx, pool, migrations.Files); err != nil {
		t.Fatalf("迁移失败: %v", err)
	}

	var id string
	slug := "ent-" + time.Now().Format("150405-000000")
	if err := pool.QueryRow(ctx,
		`INSERT INTO tenant (id, slug, name, edition) VALUES (gen_random_uuid(), $1, $2, 'business')
		 RETURNING id::text`, slug, "授权测试租户").Scan(&id); err != nil {
		t.Fatalf("建租户失败: %v", err)
	}
	t.Cleanup(func() { dbtest.CleanupTenant(t, pool, id) })
	return pool, New(pool), id
}

// 基础版的默认值必须与 edition.Spec 一致，否则上线当天就有客户能力变化。
func TestPlanDefaultsMatchEditionMatrix(t *testing.T) {
	_, svc, tenantID := setup(t)
	ctx := context.Background()

	vals, err := svc.Resolve(ctx, tenantID, edition.Business)
	if err != nil {
		t.Fatalf("旗舰版解算失败: %v", err)
	}
	if len(vals) < 14 {
		t.Fatalf("能力定义少于 14 项，迁移 0052 的种子是否完整？实际 %d", len(vals))
	}
	for _, code := range []string{ShareExternal, Classification, DirAuth, MailOutbound,
		UploadFolder, SMSLogin, CollabExternal, CustomDomain, SSO, AuditExport} {
		v, ok := vals[code]
		if !ok {
			t.Fatalf("缺少能力 %s", code)
		}
		if !v.Entitled {
			t.Fatalf("旗舰版应包含 %s", code)
		}
		if v.Source != SourcePlan {
			t.Fatalf("%s 的来源应为 plan，实际 %s", code, v.Source)
		}
	}

	basic, err := svc.Resolve(ctx, tenantID, edition.Basic)
	if err != nil {
		t.Fatalf("基础版解算失败: %v", err)
	}
	if !basic[ShareExternal].Entitled {
		t.Fatal("基础版应包含外链分享（核心能力）")
	}
	if basic[Classification].Entitled {
		t.Fatal("基础版不应包含密级管控")
	}
	if basic[CustomDomain].Entitled {
		t.Fatal("基础版不应包含自定义域名")
	}
}

// 三态：on 覆盖默认、off 覆盖默认、inherit 删行回默认。
func TestOverrideThreeStates(t *testing.T) {
	_, svc, tenantID := setup(t)
	ctx := context.Background()

	// 基础版默认没有密级 → 特批开通
	if _, err := svc.Set(ctx, slugOf(t, svc, tenantID), Classification, "on",
		"POC 试用", nil, "test@example.com"); err != nil {
		t.Fatalf("特批开通失败: %v", err)
	}
	// 用"基础版视角"解算：这三个断言要验证的是覆盖，不是档位
	v := oneAs(t, svc, tenantID, Classification, edition.Basic)
	if !v.Entitled || v.Source != SourceGrant {
		t.Fatalf("特批后应为 grant/true，实际 %s/%v", v.Source, v.Entitled)
	}

	// 改成强制关
	if _, err := svc.Set(ctx, slugOf(t, svc, tenantID), Classification, "off",
		"客户要求关闭", nil, "test@example.com"); err != nil {
		t.Fatalf("强制关失败: %v", err)
	}
	v = oneAs(t, svc, tenantID, Classification, edition.Basic)
	if v.Entitled || v.Source != SourceGrant {
		t.Fatalf("off 后应为 grant/false，实际 %s/%v", v.Source, v.Entitled)
	}

	// inherit：删行，回到档位默认（基础版 = false）
	if _, err := svc.Set(ctx, slugOf(t, svc, tenantID), Classification, "inherit",
		"", nil, "test@example.com"); err != nil {
		t.Fatalf("回归默认失败: %v", err)
	}
	v = oneAs(t, svc, tenantID, Classification, edition.Basic)
	if v.Entitled || v.Source != SourcePlan {
		t.Fatalf("inherit 后应为 plan/false，实际 %s/%v", v.Source, v.Entitled)
	}
}

// 过期的特批按"没有特批"处理，但来源要能解释，否则客服答不了"合同里明明买了"。
func TestExpiredGrantFallsBack(t *testing.T) {
	_, svc, tenantID := setup(t)
	ctx := context.Background()

	past := time.Now().Add(-time.Hour)
	if _, err := svc.Set(ctx, slugOf(t, svc, tenantID), CustomDomain, "on",
		"上季度加购", &past, "test@example.com"); err != nil {
		t.Fatalf("写入过期授权失败: %v", err)
	}
	// 基础版视角：档位本没有域名，特批到期后必须真的失去
	v := oneAs(t, svc, tenantID, CustomDomain, edition.Basic)
	if v.Entitled {
		t.Fatal("基础版 + 已过期特批，不应再有自定义域名")
	}
	if v.Source != SourceExpired {
		t.Fatalf("来源应为 expired，实际 %s", v.Source)
	}
}

// 平台强制关必须压过一切，包括有效期内的特批。
func TestLockBeatsGrant(t *testing.T) {
	_, svc, tenantID := setup(t)
	ctx := context.Background()

	if _, err := svc.Set(ctx, slugOf(t, svc, tenantID), ShareExternal, "on",
		"", nil, "test@example.com"); err != nil {
		t.Fatalf("特批失败: %v", err)
	}
	prev, cur, err := svc.Lock(ctx, ShareExternal, true, "合规下线")
	if err != nil {
		t.Fatalf("全局关闭失败: %v", err)
	}
	if prev || !cur {
		t.Fatalf("前后值不对: prev=%v cur=%v", prev, cur)
	}
	v := one(t, svc, tenantID, ShareExternal)
	if v.Entitled {
		t.Fatal("平台强制关后仍为已开通")
	}
	if v.Source != SourceLocked || v.Reason != "合规下线" {
		t.Fatalf("来源/原因不对: %s / %s", v.Source, v.Reason)
	}

	// 解锁后应恢复特批的 on
	if _, _, err := svc.Lock(ctx, ShareExternal, false, ""); err != nil {
		t.Fatalf("解除关闭失败: %v", err)
	}
	if v := one(t, svc, tenantID, ShareExternal); !v.Entitled {
		t.Fatal("解除关闭后应恢复")
	}
	t.Cleanup(func() { _, _, _ = svc.Lock(context.Background(), ShareExternal, false, "") })
}

// 未知编码不能静默当成"没有"：拼错一个字母应当报错，否则判定点永远不生效。
func TestUnknownCodeIsError(t *testing.T) {
	_, svc, tenantID := setup(t)
	ctx := context.Background()

	if _, err := svc.Entitled(ctx, tenantID, "sms.lgoin", edition.Business); err == nil {
		t.Fatal("拼错的能力编码应报错")
	}
	if _, err := svc.Set(ctx, slugOf(t, svc, tenantID), "not.a.code", "on", "", nil, "x"); err == nil {
		t.Fatal("未知编码的写入应报错")
	}
}

// ---------- 辅助 ----------

func one(t *testing.T, svc *Service, tenantID, code string) Value {
	t.Helper()
	return oneAs(t, svc, tenantID, code, edition.Business)
}

func oneAs(t *testing.T, svc *Service, tenantID, code string, ed edition.Edition) Value {
	t.Helper()
	vals, err := svc.Resolve(context.Background(), tenantID, ed)
	if err != nil {
		t.Fatalf("解算失败: %v", err)
	}
	v, ok := vals[code]
	if !ok {
		t.Fatalf("缺少能力 %s", code)
	}
	return v
}

// slugOf 从 tenant 表取 slug：平台侧接口按 slug 定位，测试里不想再造一份映射。
func slugOf(t *testing.T, svc *Service, tenantID string) string {
	t.Helper()
	var slug string
	if err := svc.pool.QueryRow(context.Background(),
		`SELECT slug FROM tenant WHERE id = $1`, tenantID).Scan(&slug); err != nil {
		t.Fatalf("读取 slug 失败: %v", err)
	}
	return slug
}
