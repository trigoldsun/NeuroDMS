package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"mime/multipart"
	"net/http"
	"testing"

	"docvault/internal/auth"
)

func login(t *testing.T, srvURL, slug string) string {
	t.Helper()
	resp, body := postJSON(t, srvURL+"/v1/auth/login", "", map[string]any{
		"tenantSlug": slug, "username": "bob", "password": pwd,
	})
	if resp.StatusCode != 200 {
		t.Fatalf("登录失败 %d: %v", resp.StatusCode, body)
	}
	return dataMap(t, body)["accessToken"].(string)
}

func upload(t *testing.T, url, token, filename, content string) (*http.Response, map[string]any) {
	t.Helper()
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, err := mw.CreateFormFile("file", filename)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = fw.Write([]byte(content))
	_ = mw.Close()

	req, _ := http.NewRequest(http.MethodPost, url, &buf)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("上传请求失败: %v", err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp, out
}

// 完整链路：登录 → 建空间 → 上传 → 列目录 → 下载内容一致。
func TestContentLifecycleOverHTTP(t *testing.T) {
	srv, _, slug := setup(t)
	token := login(t, srv.URL, slug)

	// 建空间
	resp, body := postJSON(t, srv.URL+"/v1/spaces", token, map[string]any{
		"kind": "project", "name": "投标资料",
	})
	if resp.StatusCode != 200 {
		t.Fatalf("建空间失败 %d: %v", resp.StatusCode, body)
	}
	spaceID := dataMap(t, body)["spaceId"].(string)

	// 上传文件
	const payload = "hello docvault 中文内容"
	resp, body = upload(t, srv.URL+"/v1/spaces/"+spaceID+"/files", token, "报价单.txt", payload)
	if resp.StatusCode != 200 {
		t.Fatalf("上传失败 %d: %v", resp.StatusCode, body)
	}
	nodeID := dataMap(t, body)["nodeId"].(string)

	// 列目录应能看到
	resp, body = getJSON(t, srv.URL+"/v1/spaces/"+spaceID+"/nodes", token)
	if resp.StatusCode != 200 {
		t.Fatalf("列目录失败 %d", resp.StatusCode)
	}
	items, _ := dataMap(t, body)["items"].([]any)
	if len(items) != 1 {
		t.Fatalf("应有 1 个文件，实际 %d", len(items))
	}

	// 下载内容必须一致
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/v1/nodes/"+nodeID+"/content", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	dresp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer dresp.Body.Close()
	if dresp.StatusCode != 200 {
		t.Fatalf("下载失败 %d", dresp.StatusCode)
	}
	got, _ := io.ReadAll(dresp.Body)
	if string(got) != payload {
		t.Fatalf("内容不一致: %q", string(got))
	}
}

// 幂等/去重：同名文件重复上传应成为新版本，而不是新节点。
func TestUploadSameNameCreatesNewVersion(t *testing.T) {
	srv, pool, slug := setup(t)
	token := login(t, srv.URL, slug)

	_, body := postJSON(t, srv.URL+"/v1/spaces", token, map[string]any{"kind": "project", "name": "版本测试"})
	spaceID := dataMap(t, body)["spaceId"].(string)

	_, b1 := upload(t, srv.URL+"/v1/spaces/"+spaceID+"/files", token, "doc.txt", "v1")
	n1 := dataMap(t, b1)["nodeId"].(string)
	_, b2 := upload(t, srv.URL+"/v1/spaces/"+spaceID+"/files", token, "doc.txt", "v2")
	n2 := dataMap(t, b2)["nodeId"].(string)

	if n1 != n2 {
		t.Fatalf("同名文件应复用同一节点，实际 %s vs %s", n1, n2)
	}

	var n int
	ctx := context.Background()
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM version WHERE node_id=$1`, n1).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("应有 2 个版本，实际 %d", n)
	}

	// 列目录不应出现两条同名文件
	_, body = getJSON(t, srv.URL+"/v1/spaces/"+spaceID+"/nodes", token)
	items, _ := dataMap(t, body)["items"].([]any)
	if len(items) != 1 {
		t.Fatalf("目录中应只有 1 个文件，实际 %d", len(items))
	}
}

// 没有 ACE 的其他用户必须看不到、下不到（对象级授权）。
func TestOtherUserDeniedWithoutACE(t *testing.T) {
	srv, pool, slug := setup(t)
	token := login(t, srv.URL, slug)

	_, body := postJSON(t, srv.URL+"/v1/spaces", token, map[string]any{"kind": "project", "name": "私有空间"})
	spaceID := dataMap(t, body)["spaceId"].(string)
	_, b := upload(t, srv.URL+"/v1/spaces/"+spaceID+"/files", token, "secret.txt", "top secret")
	nodeID := dataMap(t, b)["nodeId"].(string)

	// 同租户再建一个用户（无任何 ACE）
	intruderID := uuid(t)
	hash, _ := auth.HashPassword(pwd)
	var tenantID string
	if err := pool.QueryRow(context.Background(),
		`SELECT id::text FROM tenant WHERE slug=$1`, slug).Scan(&tenantID); err != nil {
		t.Fatal(err)
	}
	if _, err := pool.Exec(context.Background(), `
		INSERT INTO app_user (id, tenant_id, username, display_name, password_hash, status, ceiling)
		VALUES ($1,$2,'eve','Eve',$3,'active',4)`, intruderID, tenantID, hash); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM app_user WHERE id=$1`, intruderID)
	})

	// 用 eve 登录（同租户、同口令）
	resp, lb := postJSON(t, srv.URL+"/v1/auth/login", "", map[string]any{
		"tenantSlug": slug, "username": "eve", "password": pwd,
	})
	if resp.StatusCode != 200 {
		t.Fatalf("eve 登录失败: %v", lb)
	}
	eveToken := dataMap(t, lb)["accessToken"].(string)

	// 列目录：应 404（不泄漏存在性）
	resp, _ = getJSON(t, srv.URL+"/v1/spaces/"+spaceID+"/nodes", eveToken)
	if resp.StatusCode != 404 {
		t.Fatalf("越权列目录应 404，实际 %d", resp.StatusCode)
	}

	// 下载：应 404
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/v1/nodes/"+nodeID+"/content", nil)
	req.Header.Set("Authorization", "Bearer "+eveToken)
	dresp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer dresp.Body.Close()
	if dresp.StatusCode != 404 {
		t.Fatalf("越权下载应 404，实际 %d", dresp.StatusCode)
	}
}
