package dept

import (
	"errors"
	"strings"
	"testing"
)

// ltree 只接受字母数字下划线：中文与 & 必须被替换，且不同名字不能拿到同一个标签。
//
// 这条规则以前只在目录同步里，手工建部门走的是另一条路径——
// 两边不一致的后果是"同步建的部门能授到权、手工建的不行"。
func TestLTLabel(t *testing.T) {
	cases := []string{"Data&Tech", "研发部", "Finance", "Finance ", "研发部 ", "FINANCE"}
	seen := map[string]string{}
	for _, name := range cases {
		label := LTLabel(name)
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
	// 同名必须稳定：不稳定的话每次同步都会新建一个部门
	if LTLabel("研发部") != LTLabel("研发部") {
		t.Fatal("同名标签必须稳定")
	}
	if !strings.HasPrefix(LTLabel("Finance"), "Finance_") {
		t.Fatalf("可读部分应保留: %s", LTLabel("Finance"))
	}
}

func TestCleanName(t *testing.T) {
	if _, err := cleanName("  "); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("空白名应被拒，实际 %v", err)
	}
	if _, err := cleanName("财务\n部"); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("含换行应被拒，实际 %v", err)
	}
	long := strings.Repeat("部", maxNameLen+1)
	if _, err := cleanName(long); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("超长名应被拒，实际 %v", err)
	}
	got, err := cleanName("  财务部  ")
	if err != nil || got != "财务部" {
		t.Fatalf("应去掉首尾空白，实际 %q / %v", got, err)
	}
	// 长度按字符数算：64 个汉字是合法的（按字节算会误拒）
	if _, err := cleanName(strings.Repeat("部", maxNameLen)); err != nil {
		t.Fatalf("%d 个汉字应合法，实际 %v", maxNameLen, err)
	}
}

func TestJoinPath(t *testing.T) {
	root := "root"
	child := joinPath(root, "财务部")
	if !strings.HasPrefix(child, root+".") {
		t.Fatalf("子部门路径应以父路径开头: %s", child)
	}
	// 顶层：只有标签本身
	if got := joinPath("", "财务部"); strings.Contains(got, ".") {
		t.Fatalf("顶层路径不应含点: %s", got)
	}
}
