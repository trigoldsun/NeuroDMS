package httpapi

// AC-11 搜索：跨租户不可见 + 只返回有可见性的条目 + 通配符必须转义。
// AC-57：文件名里的脚本片段在 JSON 响应中不能以可执行形式出现。

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"
	"testing"

	"docvault/internal/authz"
	"docvault/internal/dbtest"
)

// AC-11：搜索不能命中他租户的文件，也不能返回自己无权看到的文件名。
func TestAC11SearchRespectsTenantAndVisibility(t *testing.T) {
	srv, pool, slug := setup(t)
	owner := login(t, srv.URL, slug)
	spaceID, ownNode := prepareFile(t, srv.URL, owner)
	tenantID := tenantOf(t, pool, slug)

	// 同租户、另一个人建的文件：owner 看不到，搜索也不应出现
	eve := seedUser(t, srv.URL, slug, "eve11")
	_, eveBody := postJSON(t, srv.URL+"/v1/spaces", eve, map[string]any{"kind": "personal", "name": "Eve 私有"})
	eveSpace := dataMap(t, eveBody)["spaceId"].(string)
	upload(t, srv.URL+"/v1/spaces/"+eveSpace+"/files", eve, "secret-plan-eve.txt", "别人看不到")

	// 另一个租户的文件（直接写库，模拟多租户共存）
	otherTenant := uuidT(t)
	if _, err := pool.Exec(context.Background(),
		`INSERT INTO tenant (id, slug, name) VALUES ($1,$2,'另一个租户')`,
		otherTenant, "other-"+otherTenant[:8]); err != nil {
		t.Fatal(err)
	}
	// 必须走统一的清理顺序：裸 DELETE tenant 会被外键挡住，
	// 而错误被忽略就会在库里越堆越多（这正是上一轮残留租户的来源）。
	t.Cleanup(func() { dbtest.CleanupTenant(t, pool, otherTenant) })
	var otherUser string
	if err := pool.QueryRow(context.Background(), `
		INSERT INTO app_user (id, tenant_id, username, display_name, status)
		VALUES (gen_random_uuid(), $1, 'otheruser', 'Other', 'active') RETURNING id::text`,
		otherTenant).Scan(&otherUser); err != nil {
		t.Fatal(err)
	}
	var otherSpace string
	if err := pool.QueryRow(context.Background(), `
		INSERT INTO space (id, tenant_id, kind, name, owner_id)
		VALUES (gen_random_uuid(), $1, 'project', '外部空间', $2) RETURNING id::text`,
		otherTenant, otherUser).Scan(&otherSpace); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(context.Background(), `
		INSERT INTO node (id, tenant_id, space_id, kind, name, owner_id)
		VALUES (gen_random_uuid(), $1, $2, 'file', '跨租户机密-aaa.txt', $3)`,
		otherTenant, otherSpace, otherUser); err != nil {
		t.Fatal(err)
	}

	// 搜自己能看到的名字 → 命中
	resp, body := getJSON(t, srv.URL+"/v1/search?q=report", owner)
	if resp.StatusCode != 200 {
		t.Fatalf("搜索失败 %d: %v", resp.StatusCode, body)
	}
	items, _ := dataMap(t, body)["items"].([]any)
	if len(items) != 1 || items[0].(map[string]any)["nodeId"] != ownNode {
		t.Fatalf("AC-11 应只命中自己的文件，实际 %v", items)
	}

	// 搜别人同租户的文件 → 不命中（可见性）
	_, body = getJSON(t, srv.URL+"/v1/search?q=eve", owner)
	if n := dataMap(t, body)["count"].(float64); n != 0 {
		t.Fatalf("AC-11 不应返回自己无权看到的文件名，实际 %v 条", n)
	}

	// 搜他租户的文件 → 不命中（租户隔离）
	_, body = getJSON(t, srv.URL+"/v1/search?q=跨租户机密", owner)
	if n := dataMap(t, body)["count"].(float64); n != 0 {
		t.Fatalf("AC-11 跨租户搜索必须为空，实际 %v 条", n)
	}

	// 授权后应能搜到
	grantBits(t, pool, tenantID, "space", eveSpace, userIDByName(t, slug, "bob"),
		int64(authz.PresetViewer.Bits()))
	_, body = getJSON(t, srv.URL+"/v1/search?q=secret-plan", owner)
	if n := dataMap(t, body)["count"].(float64); n != 1 {
		t.Fatalf("AC-11 授权后应能搜到，实际 %v 条", n)
	}
	_ = spaceID
}

// 通配符必须转义：否则输入一个 % 就能把全库文件名捞出来。
func TestSearchEscapesWildcards(t *testing.T) {
	srv, _, slug := setup(t)
	owner := login(t, srv.URL, slug)
	_, _ = prepareFile(t, srv.URL, owner)

	for _, q := range []string{"%", "_", "%%"} {
		// % 在 URL 里是转义字符，必须 QueryEscape 才能真的送出字面量
		_, body := getJSON(t, srv.URL+"/v1/search?q="+url.QueryEscape(q), owner)
		if n := dataMap(t, body)["count"].(float64); n != 0 {
			t.Fatalf("搜索 %q 不应匹配任何文件（通配符未转义），实际 %v 条", q, n)
		}
	}
}

// AC-57：文件名中的脚本片段不得以可执行形式出现在 JSON 响应里。
//
// Go 的 encoding/json 默认把 < > & 转义为 \u003c 等，这是 HTML 安全的；
// 但"默认安全"必须有断言守着——一旦有人换成自定义序列化器或关闭编码器转义，
// 这条就静默失效了。
func TestAC57FilenameScriptIsEscapedInJSON(t *testing.T) {
	srv, _, slug := setup(t)
	owner := login(t, srv.URL, slug)
	_, body := postJSON(t, srv.URL+"/v1/spaces", owner, map[string]any{"kind": "project", "name": "XSS 空间"})
	spaceID := dataMap(t, body)["spaceId"].(string)

	// 注意：文件名不能含 `/`（会被 multipart 当路径分隔符截断），
	// 所以这里用不含斜杠的脚本型文件名。
	name := `x<svg onload=alert(1)>.txt`
	resp, out := upload(t, srv.URL+"/v1/spaces/"+spaceID+"/files", owner, name, "content")
	if resp.StatusCode != 200 {
		t.Fatalf("上传失败 %d: %v", resp.StatusCode, out)
	}

	// 列表接口的原始字节里不能出现未转义的 <script>
	_, raw := getRaw(t, srv.URL+"/v1/spaces/"+spaceID+"/nodes", owner)
	if strings.Contains(string(raw), "<svg") {
		t.Fatalf("AC-57 响应中出现未转义的脚本标签: %s", raw)
	}
	// 但语义上名字必须完整（转义不等于丢字符）
	var parsed struct {
		Data struct {
			Items []struct {
				Name string `json:"name"`
			} `json:"items"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &parsed); err != nil {
		t.Fatalf("响应不是合法 JSON: %v", err)
	}
	if len(parsed.Data.Items) != 1 || parsed.Data.Items[0].Name != name {
		t.Fatalf("AC-57 文件名被破坏: %v", parsed.Data.Items)
	}
}

// uuidT 生成测试用 uuid（复用包内 testUUID 风格）。
func uuidT(t *testing.T) string {
	t.Helper()
	return uuid(t)
}
