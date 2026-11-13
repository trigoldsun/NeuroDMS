package httpapi

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"docvault/internal/platform/httpmw"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// 配置不成立时必须"不启用"，而不是"启用了个半成品"。
// 这是认证绕过级别的开关，任何一项缺失都只能 fail-closed。
func TestNewSSOSettingsFailsClosed(t *testing.T) {
	cases := []struct {
		name    string
		enabled bool
		header  string
		secret  string
		cidrs   []string
		wantOn  bool
	}{
		{"开关关闭", false, "X-Remote-User", "s3cret", []string{"10.0.0.0/8"}, false},
		{"缺共享密钥", true, "X-Remote-User", "", []string{"10.0.0.0/8"}, false},
		{"缺可信网段", true, "X-Remote-User", "s3cret", nil, false},
		{"信任全网", true, "X-Remote-User", "s3cret", []string{"0.0.0.0/0"}, false},
		{"信任全部 IPv6", true, "X-Remote-User", "s3cret", []string{"::/0"}, false},
		{"客户端可控头", true, "Authorization", "s3cret", []string{"10.0.0.0/8"}, false},
		{"转发头不可作断言", true, "X-Forwarded-For", "s3cret", []string{"10.0.0.0/8"}, false},
		{"头名含非法字符", true, "X Remote User", "s3cret", []string{"10.0.0.0/8"}, false},
		{"网段无法解析", true, "X-Remote-User", "s3cret", []string{"10.0.0.0/999"}, false},
		{"配置完整", true, "X-Remote-User", "s3cret", []string{"10.0.0.0/8"}, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := NewSSOSettings(c.enabled, c.header, c.secret, c.cidrs, "demo", testLogger())
			if s.Enabled != c.wantOn {
				t.Fatalf("Enabled = %v, want %v (reason=%s)", s.Enabled, c.wantOn, s.Reason)
			}
			if !c.wantOn && s.Reason == "" {
				t.Fatal("未启用时必须给出原因，否则运维无从排查")
			}
		})
	}
}

// 断言值的归一化：代理写出来的形式有好几种，落到系统里必须是同一个登录名。
func TestNormalizeAssertedUser(t *testing.T) {
	cases := map[string]string{
		`NEURONGENE\ZhangSan`:    "zhangsan",
		"zhangsan@neurongene.cn": "zhangsan",
		"  ZhangSan  ":           "zhangsan",
		"":                       "",
	}
	for in, want := range cases {
		if got := normalizeAssertedUser(in); got != want {
			t.Errorf("normalizeAssertedUser(%q) = %q, want %q", in, got, want)
		}
	}
}

// ssoAssert 是整个功能的唯一入口，四种"不该认"的情况必须全部挡住。
func TestSSOAssertGates(t *testing.T) {
	mk := func(peer, secret string, hdr map[string]string) (string, bool) {
		s := NewSSOSettings(true, "X-Remote-User", "s3cret", []string{"10.0.0.0/8"}, "demo", testLogger())
		a := &API{SSO: s}
		var user string
		var ok bool
		// 走真实的 RealIP 中间件：直连对端是由它写进上下文的，
		// 直接用 clientIP 判断会被 XFF 改写带偏（那正是要防的绕过）。
		h := httpmw.RealIP(nil)(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			user, ok = a.ssoAssert(r)
		}))
		req := httptest.NewRequest(http.MethodGet, "/v1/auth/sso", nil)
		req.RemoteAddr = peer
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		h.ServeHTTP(httptest.NewRecorder(), req)
		return user, ok
	}

	if _, ok := mk("10.1.2.3:5555", "", map[string]string{"X-Remote-User": "zhangsan"}); ok {
		t.Error("没有共享密钥时不能认断言")
	}
	if _, ok := mk("10.1.2.3:5555", "wrong", map[string]string{"X-Remote-User": "zhangsan", "X-SSO-Secret": "wrong"}); ok {
		t.Error("密钥不匹配时不能认断言")
	}
	if _, ok := mk("203.0.113.9:5555", "s3cret", map[string]string{"X-Remote-User": "zhangsan", "X-SSO-Secret": "s3cret"}); ok {
		t.Error("来源不在可信网段时不能认断言")
	}
	if _, ok := mk("10.1.2.3:5555", "s3cret", map[string]string{"X-SSO-Secret": "s3cret"}); ok {
		t.Error("没有断言头时不能认")
	}

	user, ok := mk("10.1.2.3:5555", "s3cret",
		map[string]string{"X-Remote-User": `NEURONGENE\ZhangSan`, "X-SSO-Secret": "s3cret"})
	if !ok || user != "zhangsan" {
		t.Fatalf("合法断言应通过并归一化，实际 %q,%v", user, ok)
	}
}

// 即使来源可信，伪造的 X-Forwarded-For 也不能把地址"洗白"成受信网段。
func TestSSOAssertIgnoresForwardedFor(t *testing.T) {
	s := NewSSOSettings(true, "X-Remote-User", "s3cret", []string{"10.0.0.0/8"}, "demo", testLogger())
	a := &API{SSO: s}

	var ok bool
	h := httpmw.RealIP(nil)(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		_, ok = a.ssoAssert(r)
	}))
	req := httptest.NewRequest(http.MethodGet, "/v1/auth/sso", nil)
	req.RemoteAddr = "203.0.113.9:5555" // 真实来源不可信
	req.Header.Set("X-Forwarded-For", "10.1.2.3")
	req.Header.Set("X-Remote-User", "zhangsan")
	req.Header.Set("X-SSO-Secret", "s3cret")
	h.ServeHTTP(httptest.NewRecorder(), req)

	if ok {
		t.Fatal("XFF 不能影响可信判定")
	}
}
