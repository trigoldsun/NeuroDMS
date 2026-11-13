package httpapi

import "testing"

// 预览的内联类型必须收窄到"不会以本站文档身份执行"的集合。
//
// 回归背景：handlePreview 直接把上传时记录的 Content-Type 回给浏览器，
// 于是上传一份 text/html 就能让它以**同源文档**渲染——同源 iframe 可以读写
// 父页面的 localStorage（访问令牌就在那里），也能用 meta refresh / 表单跳转钓鱼。
func TestSafeInlineType(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"text/html", "text/plain; charset=utf-8"},
		{"text/html; charset=utf-8", "text/plain; charset=utf-8"},
		{"TEXT/HTML", "text/plain; charset=utf-8"},
		{"application/xhtml+xml", "text/plain; charset=utf-8"},
		{"text/xml", "text/plain; charset=utf-8"},
		{"application/rss+xml", "text/plain; charset=utf-8"},
		// SVG 已在入库前经 SanitizeSVG 白名单重写，必须保留原类型才能当图片显示
		{"image/svg+xml", "image/svg+xml"},
		{"application/pdf", "application/pdf"},
		{"image/png", "image/png"},
		{"text/plain; charset=utf-8", "text/plain; charset=utf-8"},
	}
	for _, c := range cases {
		if got := safeInlineType(c.in); got != c.want {
			t.Errorf("safeInlineType(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
