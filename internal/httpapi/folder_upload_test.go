package httpapi

// 整目录上传：预检规则与开关闸门。
//
// 这组用例锁四件事：
//  1. 默认关闭——升级后不会"悄悄多出一个批量入口"；
//  2. 三类拒绝原因（类型不允许 / 危险扩展名 / 超过单文件上限）各自独立成立；
//  3. 档位不含该能力时，即使租户打开开关也不能用（否则改配置就等于升级）；
//  4. 开关在**写入口**生效：脚本直接调 /v1/uploads 带 folderUpload 也要被拒。

import (
	"context"
	"net/http"
	"testing"

	"docvault/internal/rbac"
)

func TestFolderUploadDisabledByDefault(t *testing.T) {
	srv, _, slug := setup(t)
	tok := login(t, srv.URL, slug)

	// 能力接口：档位允许（测试租户是商业版），但租户没开 → folderUpload=false
	_, body := getJSON(t, srv.URL+"/v1/me/capabilities", tok)
	d := dataMap(t, body)
	capMap, _ := d["capabilities"].(map[string]any)
	if capMap["folderUpload"] != false {
		t.Fatalf("默认应关闭，实际 %v", capMap["folderUpload"])
	}
	if d["folderUploadAllowed"] != true {
		t.Fatalf("测试租户为商业版，档位应允许，实际 %v", d["folderUploadAllowed"])
	}

	// 预检被拒
	resp, out := postJSON(t, srv.URL+"/v1/uploads/preflight", tok, map[string]any{
		"spaceId": "00000000-0000-4000-8000-000000000000",
		"files":   []map[string]any{{"name": "a.pdf", "size": 1, "path": "组/a.pdf"}},
	})
	if resp.StatusCode != http.StatusForbidden || out["code"] != "FEATURE_NOT_ENABLED" {
		t.Fatalf("未开启时应 403 FEATURE_NOT_ENABLED，实际 %d %v", resp.StatusCode, out)
	}

	// 写入口同样被拒（小文件走一次性上传，见 handlers_content.go）
	resp, out = postJSON(t, srv.URL+"/v1/uploads", tok, map[string]any{
		"spaceId": "00000000-0000-4000-8000-000000000000", "name": "a.pdf",
		"sizeBytes": 10, "folderUpload": true,
	})
	if resp.StatusCode != http.StatusForbidden || out["code"] != "FEATURE_NOT_ENABLED" {
		t.Fatalf("写入口应 403，实际 %d %v", resp.StatusCode, out)
	}
}

func TestFolderUploadPreflightRules(t *testing.T) {
	srv, pool, slug := setup(t)
	tenantID := tenantOf(t, pool, slug)
	seedRole(t, pool, tenantID, userIDByName(t, slug, "bob"), rbac.SysAdmin)
	tok := login(t, srv.URL, slug)

	// 打开功能，并把白名单收窄到 pdf/docx、上限压到 5MB，便于构造用例
	resp, out := sendJSONMap(t, http.MethodPut, srv.URL+"/v1/admin/policy", tok, map[string]any{
		"folderUpload": true, "allowedExts": []string{".pdf", ".docx"}, "maxUploadMB": 5,
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("保存策略失败 %d: %v", resp.StatusCode, out)
	}

	// 建一个空间，预检需要真实对象做权限判定
	_, sp := postJSON(t, srv.URL+"/v1/spaces", tok, map[string]any{"kind": "project", "name": "文件夹验收"})
	spaceID, _ := dataMap(t, sp)["spaceId"].(string)
	if spaceID == "" {
		t.Fatalf("创建空间失败: %v", sp)
	}

	files := []map[string]any{
		{"name": "协议.pdf", "size": 1024, "path": "合同/2026/协议.pdf"},
		{"name": "清单.docx", "size": 2048, "path": "合同/清单.docx"},
		{"name": "装个助手.exe", "size": 10, "path": "合同/工具/装个助手.exe"},
		{"name": "shell.php.jpg", "size": 10, "path": "合同/shell.php.jpg"},
		{"name": "超大扫描.pdf", "size": 6 << 20, "path": "合同/超大扫描.pdf"},
		{"name": "无扩展名", "size": 10, "path": "合同/无扩展名"},
	}
	resp, out = postJSON(t, srv.URL+"/v1/uploads/preflight", tok, map[string]any{
		"spaceId": spaceID, "files": files,
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("预检失败 %d: %v", resp.StatusCode, out)
	}
	d := dataMap(t, out)
	if d["total"] != float64(len(files)) {
		t.Fatalf("total 应为 %d，实际 %v", len(files), d["total"])
	}
	if d["allowed"] != float64(2) {
		t.Fatalf("应只有 2 个通过，实际 %v（%v）", d["allowed"], d["unsupported"])
	}

	// 逐条核对原因，避免"只统计不分类"
	byPath := map[string]string{}
	for _, it := range d["unsupported"].([]any) {
		m := it.(map[string]any)
		byPath[m["path"].(string)] = m["code"].(string)
	}
	want := map[string]string{
		"合同/工具/装个助手.exe":   "ext",
		"合同/shell.php.jpg": "dangerous",
		"合同/超大扫描.pdf":      "size",
		"合同/无扩展名":          "ext",
	}
	for p, code := range want {
		if byPath[p] != code {
			t.Fatalf("%s 应被判为 %s，实际 %q（全量 %v）", p, code, byPath[p], byPath)
		}
	}
}

func TestFolderUploadBlockedByBasicEdition(t *testing.T) {
	srv, pool, slug := setup(t)
	tenantID := tenantOf(t, pool, slug)
	seedRole(t, pool, tenantID, userIDByName(t, slug, "bob"), rbac.SysAdmin)
	tok := login(t, srv.URL, slug)

	if _, err := pool.Exec(context.Background(),
		`UPDATE tenant SET edition = 'basic' WHERE id = $1`, tenantID); err != nil {
		t.Fatal(err)
	}
	resp, out := sendJSONMap(t, http.MethodPut, srv.URL+"/v1/admin/policy", tok, map[string]any{
		"folderUpload": true,
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("保存策略失败 %d: %v", resp.StatusCode, out)
	}

	_, sp := postJSON(t, srv.URL+"/v1/spaces", tok, map[string]any{"kind": "project", "name": "基础版验收"})
	spaceID, _ := dataMap(t, sp)["spaceId"].(string)

	// 开关打开了，但档位不含该能力：必须在写入口被拒，而不是"配置生效了"
	resp, out = postJSON(t, srv.URL+"/v1/uploads/preflight", tok, map[string]any{
		"spaceId": spaceID,
		"files":   []map[string]any{{"name": "a.pdf", "size": 10, "path": "组/a.pdf"}},
	})
	if resp.StatusCode != http.StatusForbidden || out["code"] != "FEATURE_NOT_ENABLED" {
		t.Fatalf("基础版应 403 FEATURE_NOT_ENABLED，实际 %d %v", resp.StatusCode, out)
	}
}

func TestFolderUploadRejectsTooManyFiles(t *testing.T) {
	srv, pool, slug := setup(t)
	tenantID := tenantOf(t, pool, slug)
	seedRole(t, pool, tenantID, userIDByName(t, slug, "bob"), rbac.SysAdmin)
	tok := login(t, srv.URL, slug)
	if resp, out := sendJSONMap(t, http.MethodPut, srv.URL+"/v1/admin/policy", tok, map[string]any{
		"folderUpload": true,
	}); resp.StatusCode != http.StatusOK {
		t.Fatalf("保存策略失败 %d: %v", resp.StatusCode, out)
	}
	_, sp := postJSON(t, srv.URL+"/v1/spaces", tok, map[string]any{"kind": "project", "name": "上限验收"})
	spaceID, _ := dataMap(t, sp)["spaceId"].(string)

	files := make([]map[string]any, maxPreflightEntries+1)
	for i := range files {
		files[i] = map[string]any{"name": "a.pdf", "size": 1, "path": "组/a.pdf"}
	}
	resp, out := postJSON(t, srv.URL+"/v1/uploads/preflight", tok, map[string]any{
		"spaceId": spaceID, "files": files,
	})
	if resp.StatusCode != http.StatusBadRequest || out["code"] != "TOO_MANY_FILES" {
		t.Fatalf("超过上限应 400 TOO_MANY_FILES，实际 %d %v", resp.StatusCode, out)
	}
}
