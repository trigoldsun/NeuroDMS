package tenant

import (
	"strings"
	"testing"
)

// 图标地址是三处共用的（登录页、分享页页眉、浏览器标签图标）。
// 拼装规则一变就会分裂成"侧栏有新图标、标签页还是旧的"，
// 所以这里把地址格式钉死。

func TestLogoURLEmpty(t *testing.T) {
	var b Branding
	if got := b.LogoURL("acme"); got != "" {
		t.Fatalf("没有图标时应返回空串，得到 %q", got)
	}
}

func TestLogoURLIncludesFingerprint(t *testing.T) {
	b := Branding{Slug: "acme", Logo: []byte{1, 2, 3, 4}, LogoMime: "image/png"}
	got := b.LogoURL("acme")
	if !strings.HasPrefix(got, "/v1/tenant/branding/logo?slug=acme&v=") {
		t.Fatalf("地址格式不符: %q", got)
	}
	// 内容变了，指纹必须跟着变，否则浏览器（和 CDN）会继续用旧图。
	other := Branding{Slug: "acme", Logo: []byte{1, 2, 3, 5}, LogoMime: "image/png"}
	if other.LogoURL("acme") == got {
		t.Fatalf("图标内容变了但地址没变: %q", got)
	}
}

func TestLogoURLFallsBackToOwnSlug(t *testing.T) {
	b := Branding{Slug: "acme", Logo: []byte{9}}
	if !strings.Contains(b.LogoURL(""), "slug=acme") {
		t.Fatalf("未给出 slug 时应使用品牌自带的 slug: %q", b.LogoURL(""))
	}
}

// 老数据可能没存 mime：按 PNG 兜底，不能给前端一个空 type——
// 空 type 的 link[rel=icon] 会让部分浏览器直接忽略该图标。
func TestLogoMimeOr(t *testing.T) {
	if got := (Branding{}).LogoMimeOr(); got != "image/png" {
		t.Fatalf("空 mime 应兜底为 png，得到 %q", got)
	}
	if got := (Branding{LogoMime: "image/svg+xml"}).LogoMimeOr(); got != "image/svg+xml" {
		t.Fatalf("应原样返回声明的 mime，得到 %q", got)
	}
}
