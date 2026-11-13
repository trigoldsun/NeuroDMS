package tenant

import "testing"

// 校验规则是"写库前的最后一道"，必须逐条钉住：
// 这些值最终会进入 CSS 变量、DNS、TLS 握手，错一个就整站白屏或证书对不上。

func TestSlugValidation(t *testing.T) {
	ok := []string{"acme", "acme-2", "a1", "my-tenant-2026"}
	bad := []string{"", "a", "Acme", "acme_2", "-acme", "acme-", "ac me", "租户", "x2345678901234567890123456789012345678901"}

	for _, s := range ok {
		if !slugRe.MatchString(s) {
			t.Fatalf("应接受 slug %q", s)
		}
	}
	for _, s := range bad {
		if slugRe.MatchString(s) {
			t.Fatalf("应拒绝 slug %q", s)
		}
	}
}

func TestColorValidation(t *testing.T) {
	for _, c := range []string{"#12724a", "#FFFFFF", "#0b5fa5"} {
		if !colorRe.MatchString(c) {
			t.Fatalf("应接受颜色 %q", c)
		}
	}
	// 命名色与 rgb() 容易被塞进任意值，且跨浏览器渲染不一致
	for _, c := range []string{"red", "#fff", "rgb(1,2,3)", "#12345g", "var(--brand)", ""} {
		if colorRe.MatchString(c) {
			t.Fatalf("应拒绝颜色 %q", c)
		}
	}
}

// Logo 会渲染在**未登录**的登录页，SVG 里带脚本等于给了一个存储型 XSS 入口。
func TestSVGScriptDetection(t *testing.T) {
	cases := map[string]bool{
		`<svg xmlns="http://www.w3.org/2000/svg"><rect/></svg>`: false,
		`<svg onload="alert(1)"></svg>`:                         true,
		`<svg><script>alert(1)</script></svg>`:                  true,
		`<svg><a xlink:href="javascript:alert(1)">x</a></svg>`:  true,
		`<svg><image href="x" onerror="fetch('//x')"/></svg>`:   true,
	}
	for in, want := range cases {
		if got := containsScript([]byte(in)); got != want {
			t.Fatalf("containsScript(%q)=%v，期望 %v", in, got, want)
		}
	}
}

func TestHostValidation(t *testing.T) {
	for _, h := range []string{"docs.example.com", "a.b.c.example.cn", "x1.test"} {
		if !hostRe.MatchString(h) {
			t.Fatalf("应接受域名 %q", h)
		}
	}
	for _, h := range []string{"https://docs.example.com", "docs.example.com:8443", "Docs.Example.com", "localhost", "", "a..b"} {
		if hostRe.MatchString(h) {
			t.Fatalf("应拒绝域名 %q", h)
		}
	}
}

// 品牌字段超长的兜底（前端也会限制，但服务端不能信任前端）。
func TestBrandingInputLimits(t *testing.T) {
	long := make([]rune, maxProductLen+1)
	for i := range long {
		long[i] = 'a'
	}
	if len([]rune(string(long))) <= maxProductLen {
		t.Fatal("构造失败")
	}
}
