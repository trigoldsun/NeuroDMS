package audit

import (
	"strings"
	"testing"
	"time"
)

// 角色收敛是这套日志的核心安全属性：给错一个模式，
// secadmin 就能看到"谁重置了谁的口令"这类人事动作。
func TestManagementPatternsFor(t *testing.T) {
	cases := []struct {
		name      string
		held      []string
		violation string
		wantAll   bool // 是否为全量管理动作
		wantNone  bool
	}{
		{"系统管理员看全量", []string{"sysadmin"}, "", true, false},
		{"审计管理员看全量", []string{"auditor"}, "", true, false},
		{"安全管理员只看安全子集", []string{"secadmin"}, "", false, false},
		{"普通成员无权", []string{"member"}, "", false, true},
		{"无角色无权", nil, "", false, true},
		{"三权分立违规一律拒绝", []string{"auditor", "sysadmin"}, "auditor 与其他管理角色互斥", false, true},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := ManagementPatternsFor(c.held, c.violation)
			if c.wantNone {
				if got != nil {
					t.Fatalf("应拒绝，实际 %v", got)
				}
				return
			}
			if got == nil {
				t.Fatal("不应拒绝")
			}
			hasAdmin := false
			for _, p := range got {
				if p == "admin.%" {
					hasAdmin = true
				}
			}
			if hasAdmin != c.wantAll {
				t.Fatalf("admin.%% 可见性 = %v, 期望 %v（模式 %v）", hasAdmin, c.wantAll, got)
			}
			// secadmin 必须保留密级与授权
			if !c.wantAll {
				joined := strings.Join(got, ",")
				for _, must := range []string{"classification.%", "acl.%"} {
					if !strings.Contains(joined, must) {
						t.Fatalf("安全管理员应能看到 %s，实际 %v", must, got)
					}
				}
			}
		})
	}
}

// 脱敏在读取侧兜底：任何埋点只要把口令写进 detail，日志页就会变成泄露渠道。
func TestRedactDetail(t *testing.T) {
	raw := []byte(`{
		"username":"alice",
		"password":"P@ssw0rd",
		"newPassword":"另一个",
		"refreshToken":"rt-123",
		"nested":{"clientSecret":"s3","visible":"ok"},
		"list":[{"passwordHash":"h"},{"name":"keep"}]
	}`)
	m, ok := RedactDetail(raw)
	if !ok {
		t.Fatal("解析失败")
	}
	if m["password"] != "[已脱敏]" || m["newPassword"] != "[已脱敏]" || m["refreshToken"] != "[已脱敏]" {
		t.Fatalf("顶层敏感字段未脱敏: %v", m)
	}
	if m["username"] != "alice" {
		t.Fatalf("普通字段被误伤: %v", m["username"])
	}
	nested := m["nested"].(map[string]any)
	if nested["clientSecret"] != "[已脱敏]" || nested["visible"] != "ok" {
		t.Fatalf("嵌套脱敏不正确: %v", nested)
	}
	list := m["list"].([]any)
	if list[0].(map[string]any)["passwordHash"] != "[已脱敏]" {
		t.Fatalf("数组内脱敏不正确: %v", list[0])
	}
	if list[1].(map[string]any)["name"] != "keep" {
		t.Fatalf("数组内普通字段被误伤: %v", list[1])
	}
}

// CSV 必须能安全地用 Excel 打开：BOM、公式注入、引号/换行转义。
func TestWriteCSV(t *testing.T) {
	rows := []EventRow{
		{
			Seq: 1, ActorID: "u-1", ActorType: "user", Action: "node.rename",
			ObjectID: "n-1", Result: "ok", IP: "203.0.113.9", RequestID: "=cmd|' /C calc'!A0",
			CreatedAt: time.Date(2026, 11, 9, 10, 30, 0, 0, time.UTC),
			Detail:    []byte(`{"name":"=HYPERLINK(\"http://evil\")","password":"x"}`),
		},
	}
	out := string(WriteCSV(rows))
	if !strings.HasPrefix(out, "\uFEFF") {
		t.Fatal("缺少 BOM，Excel 打开会是乱码")
	}
	// 公式注入只在"单元格以 = 开头"时成立：requestId 这类字段可能来自外部输入
	if !strings.Contains(out, `,'=cmd`) {
		t.Fatalf("公式注入未中和（应以单引号开头）: %s", out)
	}
	// 详情是 JSON，整体以 { 开头，不能被加前缀，否则 JSON 就坏了
	if !strings.Contains(out, `"{""name""`) {
		t.Fatalf("详情 JSON 被破坏: %s", out)
	}
	if !strings.Contains(out, "已脱敏") || strings.Contains(out, `""password"":""x""`) {
		t.Fatalf("导出内容未脱敏: %s", out)
	}
	// 引号必须成对转义，否则整行错列
	if !strings.Contains(out, `""`) {
		t.Fatalf("引号未转义: %s", out)
	}
	if got := strings.Count(out, "\r\n"); got != 2 {
		t.Fatalf("行数应为表头+1（实际 %d 个 CRLF）", got)
	}
}

// 分类前缀必须覆盖现有埋点——漏一个，那一类动作就永远查不到。
func TestCategoryPatternsCoverKnownActions(t *testing.T) {
	user := strings.Join(CategoryPatterns(CategoryUser), ",")
	for _, a := range []string{"auth.login", "node.preview", "node.download", "share.create", "office.save", "account.self_delete"} {
		matched := false
		for _, p := range CategoryPatterns(CategoryUser) {
			prefix := strings.TrimSuffix(p, "%")
			if strings.HasPrefix(a, prefix) {
				matched = true
			}
		}
		if !matched {
			t.Errorf("%s 未落入用户日志分类（%s）", a, user)
		}
	}
	for _, a := range []string{"admin.member.create", "acl.grant", "classification.set", "share.approve"} {
		matched := false
		for _, p := range CategoryPatterns(CategoryManagement) {
			if a == p || strings.HasPrefix(a, strings.TrimSuffix(p, "%")) {
				matched = true
			}
		}
		if !matched {
			t.Errorf("%s 未落入管理日志分类", a)
		}
	}
}

// 分组筛选不能放大权限：secadmin 选"成员"分组必须得到空集，
// 而不是退化成"不加过滤"（那等于把整张审计表暴露出去）。
func TestIntersectPatternsDoesNotWidenScope(t *testing.T) {
	secPatterns := ManagementPatternsFor([]string{"secadmin"}, "")

	if got := IntersectPatterns(secPatterns, GroupPatterns("member")); len(got) != 0 {
		t.Fatalf("secadmin 不应看到成员动作，实际 %v", got)
	}

	got := IntersectPatterns(secPatterns, GroupPatterns("share"))
	if len(got) != 2 {
		t.Fatalf("分享分组应收敛到 approve/revoke 两条，实际 %v", got)
	}
	for _, g := range got {
		if g != "share.approve" && g != "share.revoke" {
			t.Fatalf("收敛结果越权: %v", got)
		}
	}

	all := IntersectPatterns(ManagementPatternsFor([]string{"sysadmin"}, ""), GroupPatterns("acl"))
	joined := strings.Join(all, ",")
	if !strings.Contains(joined, "acl.%") || !strings.Contains(joined, "classification.%") {
		t.Fatalf("系统管理员看权限分组应保留 acl/classification，实际 %v", all)
	}

	// 用户视角：选"成员"分组同样应为空（成员动作不属于用户日志）
	if got := IntersectPatterns(CategoryPatterns(CategoryUser), GroupPatterns("member")); len(got) != 0 {
		t.Fatalf("用户日志不应包含成员动作，实际 %v", got)
	}
}
