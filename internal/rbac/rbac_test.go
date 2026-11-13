package rbac

import "testing"

// 三权分立的判定必须是纯函数：它会被多个入口复用，
// 一旦依赖数据库状态就很难断言"到底哪条规则拦住了谁"。
func TestSeparationViolation(t *testing.T) {
	cases := []struct {
		name  string
		roles []string
		want  string // 空表示合规
	}{
		{"空角色", nil, ""},
		{"仅系统管理员", []string{SysAdmin}, ""},
		{"仅审计管理员", []string{Auditor}, ""},
		{"系统+安全", []string{SysAdmin, SecAdmin}, ""},
		{"审计+系统", []string{Auditor, SysAdmin}, "审计管理员不得同时拥有 [sysadmin]"},
		{"审计+安全", []string{SecAdmin, Auditor}, "审计管理员不得同时拥有 [secadmin]"},
		{"审计+系统+安全（两两冲突）", []string{Auditor, SysAdmin, SecAdmin}, "审计管理员不得同时拥有 [secadmin sysadmin]"},
		{"重复审计", []string{Auditor, Auditor}, ""},
	}
	for _, c := range cases {
		if got := SeparationViolation(c.roles); got != c.want {
			t.Errorf("%s: 期望 %q，实际 %q", c.name, c.want, got)
		}
	}
}

func TestContains(t *testing.T) {
	roles := []string{SysAdmin}
	if !Contains(roles, SysAdmin) {
		t.Fatal("应命中 sysadmin")
	}
	if !Contains(roles, Auditor, SysAdmin) {
		t.Fatal("多目标任一命中即应返回 true")
	}
	if Contains(roles, Auditor) {
		t.Fatal("不应命中 auditor")
	}
	if Contains(nil, SysAdmin) {
		t.Fatal("空集合不应命中任何角色")
	}
}

func TestKnownRole(t *testing.T) {
	for _, c := range All() {
		if !Known(c) {
			t.Fatalf("内置角色 %s 应被识别", c)
		}
	}
	if Known("superuser") {
		t.Fatal("未定义的角色不应被识别——静默接受等于放行")
	}
}

// 内置角色的展示信息必须与实际判定一致，否则界面会展示"不存在的角色"。
func TestDescribeMatchesAll(t *testing.T) {
	desc := Describe()
	if len(desc) != len(All()) {
		t.Fatalf("Describe 数量 %d 与 All %d 不一致", len(desc), len(All()))
	}
	for _, d := range desc {
		if !Known(d["code"]) {
			t.Fatalf("Describe 里出现了未定义角色 %v", d)
		}
		if d["name"] == "" || d["description"] == "" {
			t.Fatalf("角色 %s 缺少展示信息", d["code"])
		}
	}
}
