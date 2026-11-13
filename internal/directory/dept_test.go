package directory

import (
	"strings"
	"testing"
)

// AD 的 OU 不在属性里，只能从 DN 解析。这条用例固定解析规则与顺序。
func TestOUChainFromDN(t *testing.T) {
	chain := ouChainFromDN("CN=xin sun,OU=Data&Tech,OU=Neurongene,DC=neurongene,DC=cn")
	if len(chain) != 2 {
		t.Fatalf("应解析出 2 层 OU，实际 %d: %v", len(chain), chain)
	}
	// 顺序必须"外 → 内"，否则部门树会建反
	if chain[0].Name != "Neurongene" || chain[1].Name != "Data&Tech" {
		t.Fatalf("顺序或名称不对: %v", chain)
	}
	if chain[0].DN != "OU=Neurongene,DC=neurongene,DC=cn" {
		t.Fatalf("外层 DN 不对: %s", chain[0].DN)
	}
	if chain[1].DN != "OU=Data&Tech,OU=Neurongene,DC=neurongene,DC=cn" {
		t.Fatalf("内层 DN 不对: %s", chain[1].DN)
	}

	// 建在 CN=Users 下的账号没有 OU，不应造出部门
	if got := ouChainFromDN("CN=Administrator,CN=Users,DC=neurongene,DC=cn"); len(got) != 0 {
		t.Fatalf("CN=Users 下不应解析出 OU: %v", got)
	}
	// 空 DN 不 panic
	if got := ouChainFromDN(""); got != nil {
		t.Fatalf("空 DN 应返回 nil，实际 %v", got)
	}
}

// ltree 只接受字母数字下划线：中文与 & 必须被替换，且同名不同名的标签不能相撞。
func TestLtreeLabel(t *testing.T) {
	cases := []string{"Data&Tech", "研发部", "Finance", "Finance "}
	seen := map[string]string{}
	for _, name := range cases {
		label := ltreeLabel(name)
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '_') {
				t.Fatalf("标签 %q 含非法字符 %q", label, r)
			}
		}
		if label == "" || len(label) > 64 {
			t.Fatalf("标签长度异常: %q", label)
		}
		if prev, dup := seen[label]; dup {
			t.Fatalf("%q 与 %q 生成了相同标签 %q", name, prev, label)
		}
		seen[label] = name
	}
	// 同一个名字必须稳定（否则每次同步都会新建部门）
	if ltreeLabel("研发部") != ltreeLabel("研发部") {
		t.Fatal("同名标签必须稳定")
	}
	if !strings.HasPrefix(ltreeLabel("Finance"), "Finance_") {
		t.Fatalf("可读部分应保留: %s", ltreeLabel("Finance"))
	}
}
