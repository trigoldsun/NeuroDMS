package httpmw

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// 限流必须可测：它的失效方式是"静默不生效"。
// 一个单位写错（秒/毫秒）就可能让阈值放大 1000 倍，而正常测试全绿。

func TestLimiterBurstThenThrottle(t *testing.T) {
	now := time.Unix(1700000000, 0)
	l := NewLimiter(1, 3)
	l.now = func() time.Time { return now }

	for i := 0; i < 3; i++ {
		if ok, _ := l.Allow("a"); !ok {
			t.Fatalf("第 %d 次应放行（桶容量 3）", i+1)
		}
	}
	if ok, wait := l.Allow("a"); ok || wait <= 0 {
		t.Fatalf("超过容量应拒绝并给出等待时间，实际 ok=%v wait=%v", ok, wait)
	}

	// 时间前进 1 秒应补 1 个令牌
	now = now.Add(time.Second)
	if ok, _ := l.Allow("a"); !ok {
		t.Fatal("补充 1 个令牌后应放行")
	}
	if ok, _ := l.Allow("a"); ok {
		t.Fatal("只补了 1 个令牌，不该连续放行两次")
	}

	// 其他 key 互不影响（否则一个用户能把所有人拖死）
	if ok, _ := l.Allow("b"); !ok {
		t.Fatal("不同 key 应独立计数")
	}
}

// Nil 限流器必须放行而不是 panic：配置为 0 时调用方会传 nil。
func TestNilLimiterAllows(t *testing.T) {
	var l *Limiter
	if ok, _ := l.Allow("x"); !ok {
		t.Fatal("nil 限流器应放行")
	}
	if l.Len() != 0 {
		t.Fatal("nil 限流器 Len 应为 0")
	}
}

// 长期运行下桶必须被回收：否则随机 IP/随机 ID 会让 map 无限增长直到 OOM。
func TestLimiterBucketsAreGCed(t *testing.T) {
	now := time.Unix(1700000000, 0)
	l := NewLimiter(1, 1)
	l.now = func() time.Time { return now }

	for i := 0; i < 2000; i++ {
		l.Allow(string(rune('a'+i%26)) + string(rune('a'+i/26%26)) + time.Duration(i).String())
	}
	first := l.Len()
	if first < 1024 {
		t.Fatalf("应至少创建 1024 个桶，实际 %d", first)
	}
	now = now.Add(11 * time.Minute) // 超过 ttl
	l.Allow("fresh")
	if l.Len() >= first {
		t.Fatalf("过期桶应被回收，回收前 %d、回收后 %d", first, l.Len())
	}
}

// AC-29 / AC-56：按 IP 或按 key 枚举时，超限必须返回 429 且带 Retry-After。
func TestRateLimitReturns429WithRetryAfter(t *testing.T) {
	l := NewLimiter(1, 2)
	h := RateLimit(l, func(r *http.Request) string { return "ip:" + r.RemoteAddr })(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))

	call := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/v1/nodes/x", nil)
		req.RemoteAddr = "10.0.0.1:1234"
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	if c := call(); c.Code != 200 {
		t.Fatalf("前两次应放行，实际 %d", c.Code)
	}
	if c := call(); c.Code != 200 {
		t.Fatalf("第二次应放行，实际 %d", c.Code)
	}
	c := call()
	if c.Code != http.StatusTooManyRequests {
		t.Fatalf("超限应 429，实际 %d", c.Code)
	}
	if c.Header().Get("Retry-After") == "" {
		t.Fatal("429 必须带 Retry-After，否则客户端无从退避")
	}
	if body := c.Body.String(); body == "" || !strings.Contains(body, "RATE_LIMITED") {
		t.Fatalf("429 响应体应可被前端识别: %s", body)
	}

	// 换一个 IP 立刻可用（说明限流是按客户端维度，而不是全局限死）
	req := httptest.NewRequest(http.MethodGet, "/v1/nodes/x", nil)
	req.RemoteAddr = "10.0.0.2:1234"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 {
		t.Fatalf("另一个 IP 不应受影响，实际 %d", rec.Code)
	}
}

// 分档规则：公开端点用更严的阈值，业务端点用宽松阈值，且互不影响。
func TestRateLimitRulesByPrefix(t *testing.T) {
	publicL := NewLimiter(1, 1)
	apiL := NewLimiter(100, 100)
	h := RateLimitRules([]RateRule{
		{
			Match:   func(r *http.Request) bool { return r.URL.Path == "/v1/auth/login" },
			Limiter: publicL,
			Key:     func(*http.Request) string { return "public" },
		},
		{Limiter: apiL, Key: func(*http.Request) string { return "api" }},
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))

	do := func(path string) int {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, path, nil))
		return rec.Code
	}
	if do("/v1/auth/login") != 200 {
		t.Fatal("登录首次应放行")
	}
	if do("/v1/auth/login") != http.StatusTooManyRequests {
		t.Fatal("登录第二次应被公开档限流")
	}
	// 业务端点不受公开档影响
	for i := 0; i < 5; i++ {
		if do("/v1/spaces") != 200 {
			t.Fatalf("业务端点不应受公开档限流（第 %d 次）", i+1)
		}
	}
}
