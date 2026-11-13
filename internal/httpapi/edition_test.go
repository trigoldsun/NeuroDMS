package httpapi

// 档位差异的集成测试。
//
// 重点不是"接口返回了什么"，而是"不该写进去的数据有没有被拦住"：
// 基础版传高密文件、专业版传 1/2/5/6、降档时已有数据无法表达目标档位。

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func setEdition(t *testing.T, pool *pgxpool.Pool, slug, ed string, expires *time.Time) {
	t.Helper()
	if _, err := pool.Exec(context.Background(),
		`UPDATE tenant SET edition = $1, edition_expires_at = $2 WHERE slug = $3`,
		ed, expires, slug); err != nil {
		t.Fatalf("设置档位失败: %v", err)
	}
}

// 基础版没有密级：带密级的上传必须被拒，但不带密级的上传要正常。
func TestEditionBasicRejectsClassification(t *testing.T) {
	srv, pool, slug := setup(t)
	owner := login(t, srv.URL, slug)
	setEdition(t, pool, slug, "basic", nil)

	_, body := postJSON(t, srv.URL+"/v1/spaces", owner, map[string]any{"kind": "project", "name": "档位空间"})
	spaceID := dataMap(t, body)["spaceId"].(string)
	url := srv.URL + "/v1/spaces/" + spaceID + "/files"

	resp, out := uploadClass(t, url, owner, "secret.txt", "机密内容", 3)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("基础版上传密级 3 应 403，实际 %d: %v", resp.StatusCode, out)
	}
	if code, _ := out["code"].(string); code != "FEATURE_NOT_ENABLED" {
		t.Fatalf("错误码应为 FEATURE_NOT_ENABLED，实际 %v", out["code"])
	}

	// 不带密级的上传必须放行，否则基础版连文件都传不上去
	resp, out = uploadClass(t, url, owner, "plain.txt", "普通内容", 0)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("基础版普通上传应成功，实际 %d: %v", resp.StatusCode, out)
	}
}

// 专业版只允许 0/3/4，跳过 1/2。
func TestEditionProfessionalClassRange(t *testing.T) {
	srv, pool, slug := setup(t)
	owner := login(t, srv.URL, slug)
	setEdition(t, pool, slug, "professional", nil)

	_, body := postJSON(t, srv.URL+"/v1/spaces", owner, map[string]any{"kind": "project", "name": "档位空间"})
	spaceID := dataMap(t, body)["spaceId"].(string)
	url := srv.URL + "/v1/spaces/" + spaceID + "/files"

	// 上传者密级足够高，确保拦截原因是"档位不允许"而不是"高于自身"
	var userID string
	if err := pool.QueryRow(context.Background(),
		`SELECT id::text FROM app_user WHERE tenant_id = (SELECT id FROM tenant WHERE slug=$1) LIMIT 1`,
		slug).Scan(&userID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(context.Background(),
		`UPDATE app_user SET classification = 6 WHERE id = $1`, userID); err != nil {
		t.Fatal(err)
	}

	for _, lv := range []int{3, 4} {
		resp, out := uploadClass(t, url, owner, "ok"+itoaSmall(lv)+".txt", "内容", lv)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("专业版应允许密级 %d，实际 %d: %v", lv, resp.StatusCode, out)
		}
	}
	for _, lv := range []int{1, 2, 5, 6} {
		resp, out := uploadClass(t, url, owner, "no"+itoaSmall(lv)+".txt", "内容", lv)
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("专业版不应允许密级 %d，实际 %d: %v", lv, resp.StatusCode, out)
		}
	}
}

// 能力接口要如实反映档位，前端据此隐藏按钮。
func TestMyCapabilitiesReflectsEdition(t *testing.T) {
	srv, pool, slug := setup(t)
	owner := login(t, srv.URL, slug)

	setEdition(t, pool, slug, "basic", nil)
	resp, body := getJSON(t, srv.URL+"/v1/me/capabilities", owner)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("查询能力失败 %d: %v", resp.StatusCode, body)
	}
	data := dataMap(t, body)
	if data["edition"] != "basic" {
		t.Fatalf("档位应为 basic，实际 %v", data["edition"])
	}
	caps, _ := data["capabilities"].(map[string]any)
	if caps["classification"] != false || caps["ad"] != false || caps["shareMail"] != false {
		t.Fatalf("基础版不应有密级/AD/邮件能力: %v", caps)
	}
	limits, _ := data["limits"].(map[string]any)
	if limits["versionKeep"].(float64) != 3 {
		t.Fatalf("基础版版本保留应为 3，实际 %v", limits["versionKeep"])
	}
	if limits["maxUploadMB"].(float64) != 1024 {
		t.Fatalf("基础版单文件上限应为 1024MB，实际 %v", limits["maxUploadMB"])
	}

	setEdition(t, pool, slug, "professional", nil)
	_, body = getJSON(t, srv.URL+"/v1/me/capabilities", owner)
	data = dataMap(t, body)
	levels, _ := data["classificationLevels"].([]any)
	if len(levels) != 3 || levels[0].(float64) != 0 || levels[1].(float64) != 3 || levels[2].(float64) != 4 {
		t.Fatalf("专业版密级可选集应为 [0,3,4]，实际 %v", data["classificationLevels"])
	}
}

// 降档必须先处理存量密级数据，函数层不能放行。
func TestEditionDowngradeBlockedByClassification(t *testing.T) {
	srv, pool, slug := setup(t)
	owner := login(t, srv.URL, slug)
	_, nodeID := prepareFile(t, srv.URL, owner)
	ctx := context.Background()

	// 造一个"专业版表达不了"的对象：1 = 内部
	if _, err := pool.Exec(ctx, `UPDATE node SET classification = 1 WHERE id = $1`, nodeID); err != nil {
		t.Fatal(err)
	}

	var blocked int64
	if err := pool.QueryRow(ctx, `
		SELECT blocked_count FROM platform_tenant_set_edition($1, 'professional', NULL, '测试降档', 'tester')`,
		slug).Scan(&blocked); err != nil {
		t.Fatal(err)
	}
	if blocked == 0 {
		t.Fatal("存在密级 1 的对象时必须拒绝降到专业版")
	}

	var ed string
	if err := pool.QueryRow(ctx, `SELECT edition FROM tenant WHERE slug = $1`, slug).Scan(&ed); err != nil {
		t.Fatal(err)
	}
	if ed != "business" {
		t.Fatalf("被拒绝的降档不应改变档位，实际 %s", ed)
	}

	// 把对象降到专业版能表达的 3，再降档应成功
	if _, err := pool.Exec(ctx, `UPDATE node SET classification = 3 WHERE id = $1`, nodeID); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx, `
		SELECT blocked_count FROM platform_tenant_set_edition($1, 'professional', NULL, '测试降档', 'tester')`,
		slug).Scan(&blocked); err != nil {
		t.Fatal(err)
	}
	if blocked != 0 {
		t.Fatalf("密级 3 可被专业版表达，实际 blocked=%d", blocked)
	}
	if err := pool.QueryRow(ctx, `SELECT edition FROM tenant WHERE slug = $1`, slug).Scan(&ed); err != nil {
		t.Fatal(err)
	}
	if ed != "professional" {
		t.Fatalf("应降为专业版，实际 %s", ed)
	}
}

// 到期后先宽限、过宽限才降级；降级是运行时判定，不需要定时任务。
func TestEditionExpiryGraceAndDowngrade(t *testing.T) {
	srv, pool, slug := setup(t)
	owner := login(t, srv.URL, slug)

	// 到期 1 小时：宽限期内仍按专业版
	justExpired := time.Now().Add(-time.Hour)
	setEdition(t, pool, slug, "professional", &justExpired)

	_, body := getJSON(t, srv.URL+"/v1/me/capabilities", owner)
	data := dataMap(t, body)
	if data["grace"] != true || data["edition"] != "professional" {
		t.Fatalf("宽限期内应保持专业版并标记 grace，实际 %v", data)
	}
	if caps, _ := data["capabilities"].(map[string]any); caps["classification"] != true {
		t.Fatal("宽限期内不应提前收回能力")
	}

	// 到期 31 天：已过宽限，能力按基础版
	longAgo := time.Now().AddDate(0, 0, -31)
	setEdition(t, pool, slug, "professional", &longAgo)

	_, body = getJSON(t, srv.URL+"/v1/me/capabilities", owner)
	data = dataMap(t, body)
	if data["edition"] != "basic" || data["expired"] != true || data["declaredEdition"] != "professional" {
		t.Fatalf("过宽限应降为基础版且保留声明值，实际 %v", data)
	}
	if caps, _ := data["capabilities"].(map[string]any); caps["classification"] != false {
		t.Fatal("过宽限后不应再有密级能力")
	}
}
