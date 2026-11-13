package httpapi

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// 请求路径不得直接使用连接池 —— 用一个会失败的检查钉住，而不是靠注释纪律。
//
// 背景：应用以 docvault（超级用户 + BYPASSRLS）连接数据库，行级隔离只在
// db.WithTenant 里 SET LOCAL ROLE docvault_app 之后才生效。也就是说，
// 任何 `a.Pool.Query/QueryRow/Exec` 都拥有**跨租户读**的能力，且数据库层
// 没有任何兜底（详见 docs/28 S-13）。
//
// 这条约束此前只写在代码注释与文档里。注释不会在 PR 里报警，
// 所以它需要一个可执行的守门人：新增的直接查询必须显式标注理由。
//
// 允许的写法（豁免必须留痕）：
//
//	a.Pool.QueryRow(ctx, `...`)  // pool-ok: 平台级函数，无租户上下文
func TestNoUnscopedPoolUsage(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}

	var offenders []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(filepath.Clean(name))
		if err != nil {
			t.Fatal(err)
		}
		for i, line := range strings.Split(string(src), "\n") {
			if !strings.Contains(line, ".Pool.Query") && !strings.Contains(line, ".Pool.Exec") {
				continue
			}
			// 只关心调用，不关心字段声明/赋值
			if !strings.Contains(line, "(") {
				continue
			}
			if strings.Contains(line, "// pool-ok:") {
				continue
			}
			offenders = append(offenders, name+":"+strconv.Itoa(i+1)+"  "+strings.TrimSpace(line))
		}
	}

	if len(offenders) > 0 {
		t.Fatalf("请求路径直接使用连接池会绕过 RLS（详见 docs/28 S-13）。"+
			"请改用 db.WithTenant，或在该行标注 `// pool-ok: 理由`：\n  %s",
			strings.Join(offenders, "\n  "))
	}
}
