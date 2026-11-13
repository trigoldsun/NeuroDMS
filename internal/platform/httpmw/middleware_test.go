package httpmw

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
)

func req(remote, xff string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "/x", nil)
	r.RemoteAddr = remote
	if xff != "" {
		r.Header.Set("X-Forwarded-For", xff)
	}
	return r
}

func TestClientIPIgnoresXFFWhenNoTrustedProxy(t *testing.T) {
	// 未配置可信代理：即使伪造 XFF，也必须用 RemoteAddr（0201-C2）
	got := ClientIP(req("192.0.2.10:1234", "10.0.0.1"), nil)
	if got.String() != "192.0.2.10" {
		t.Fatalf("应使用 RemoteAddr，实际 %s", got)
	}
}

func TestClientIPUsesRightmostUntrustedHop(t *testing.T) {
	trusted := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	// 链路：客户端(203.0.113.9) -> 代理(10.0.0.2) -> 代理(10.0.0.3) -> 服务
	// 期望取最右侧的非信任跳，即 203.0.113.9
	got := ClientIP(req("10.0.0.3:5555", "203.0.113.9, 10.0.0.2"), trusted)
	if got.String() != "203.0.113.9" {
		t.Fatalf("应取最右侧非信任跳，实际 %s", got)
	}
}

func TestClientIPRejectsSpoofedLeftmostWhenUntrustedRemote(t *testing.T) {
	trusted := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
	// 直连来源不在可信网段：转发头一概不认，否则可伪造 IP 绕过 ip_cidr 条件
	got := ClientIP(req("198.51.100.7:1", "10.0.0.99"), trusted)
	if got.String() != "198.51.100.7" {
		t.Fatalf("不可信直连时应用 RemoteAddr，实际 %s", got)
	}
}

func TestClientIPHandlesIPv6Brackets(t *testing.T) {
	got := ClientIP(req("[2001:db8::1]:443", ""), nil)
	if got.String() != "2001:db8::1" {
		t.Fatalf("IPv6 解析错误: %s", got)
	}
}

func TestSecurityHeadersPresent(t *testing.T) {
	h := SecurityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req("192.0.2.1:1", ""))
	for _, k := range []string{"X-Content-Type-Options", "X-Frame-Options", "Content-Security-Policy", "Referrer-Policy"} {
		if rec.Header().Get(k) == "" {
			t.Fatalf("缺少安全响应头 %s", k)
		}
	}
}

// CSP 的 frame-src 必须放行 blob:
//
// 预览链路是"取回 PDF → 生成 Blob URL → 放进 iframe"，只写 'self' 会让浏览器
// 直接提示"该内容被屏蔽了"。这条断言防止未来为了"收紧安全"把它改回去——
// 那不会报错，只会在用户点预览时白屏。
func TestCSPAllowsBlobFrames(t *testing.T) {
	h := SecurityHeadersFor("")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/v1/nodes/x/preview", nil))

	csp := rec.Header().Get("Content-Security-Policy")
	for _, want := range []string{"frame-src 'self' blob:", "object-src 'none'", "frame-ancestors 'self'"} {
		if !strings.Contains(csp, want) {
			t.Fatalf("CSP 缺少 %q：%s", want, csp)
		}
	}
}

// RealIP 的语义只有两条：可信来源才采信 XFF；结果要能被下游直接当 RemoteAddr 用。
func TestRealIP(t *testing.T) {
	mustPrefix := func(s string) netip.Prefix { return netip.MustParsePrefix(s) }
	trusted := []netip.Prefix{mustPrefix("172.25.0.0/16")}

	cases := []struct {
		name   string
		trust  []netip.Prefix
		remote string
		xff    string
		want   string
	}{
		{"直连且未配置可信代理：不采信 XFF", nil, "203.0.113.9:5000", "1.2.3.4", "203.0.113.9:5000"},
		{"可信代理：采信 XFF", trusted, "172.25.0.4:5000", "1.2.3.4", "1.2.3.4:0"},
		{"不可信直连：忽略 XFF", trusted, "203.0.113.9:5000", "1.2.3.4", "203.0.113.9:5000"},
		{"可信代理 + 多跳：取最右侧不可信跳", trusted, "172.25.0.4:5000", "9.9.9.9, 1.2.3.4", "1.2.3.4:0"},
		{"IPv6 也要能回填", trusted, "172.25.0.4:5000", "2001:db8::1", "[2001:db8::1]:0"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var got string
			h := RealIP(c.trust)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				got = r.RemoteAddr
			}))
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = c.remote
			if c.xff != "" {
				req.Header.Set("X-Forwarded-For", c.xff)
			}
			h.ServeHTTP(httptest.NewRecorder(), req)
			if got != c.want {
				t.Fatalf("RemoteAddr = %q, want %q", got, c.want)
			}
		})
	}
}
