package notify

import (
	"errors"
	"net/mail"
	"testing"
)

func TestBrandDisplayName(t *testing.T) {
	cases := []struct{ in, want string }{
		{"", "NeuroDMS文档中心"},
		{"   ", "NeuroDMS文档中心"},
		{"森莘科创", "森莘科创文档中心"},
		// 历史数据里确实有租户把品牌名直接填成"文档中心"，不能拼成"文档中心文档中心"
		{"文档中心", "文档中心"},
		{"森莘科创文档中心", "森莘科创文档中心"},
		{"森莘科创文档管理系统", "森莘科创文档管理系统"},
	}
	for _, c := range cases {
		if got := BrandDisplayName(c.in); got != c.want {
			t.Errorf("BrandDisplayName(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// 发件人显示名必须真的进到 From 头里。
//
// 这个断言针对的是一次真实事故：平台默认 SMTP 通道的 From 只有地址，
// 收件人看到的发件人是 "noreply@..."，与"企业名+文档中心"的承诺不符。
func TestFormatFromCarriesBrandName(t *testing.T) {
	addr := "noreply@neurongene.cn"
	got := formatFrom(BrandDisplayName("森莘科创"), addr)
	parsed, err := mail.ParseAddress(got)
	if err != nil {
		t.Fatalf("From 头无法解析（RFC 2047 编码有问题）: %v — %q", err, got)
	}
	if parsed.Address != addr {
		t.Errorf("地址被改坏: %q", parsed.Address)
	}
	if parsed.Name != "森莘科创文档中心" {
		t.Errorf("显示名 = %q, 期望 %q", parsed.Name, "森莘科创文档中心")
	}
}

// 空品牌不能退化成纯地址。
func TestFormatFromNeverBareAddress(t *testing.T) {
	got := formatFrom(BrandDisplayName(""), "a@b.com")
	parsed, err := mail.ParseAddress(got)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Name == "" {
		t.Fatalf("空品牌时显示名为空，收件人只会看到地址: %q", got)
	}
	if errors.Is(nil, nil) && parsed.Name != "NeuroDMS文档中心" {
		t.Errorf("显示名 = %q", parsed.Name)
	}
}
