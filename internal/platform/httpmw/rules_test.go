package httpmw

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
)

// 回归：登录与外链必须分属不同的桶（E2E 验收 F-06）。
//
// 早先它们共用一个 2 rps / burst 10 的桶，结果是"同一出口 IP 的 10 个人
// 早上同时登录"和"外链页首屏连发几个请求"都会 429。
func TestLoginDoesNotShareBucketWithPublicShare(t *testing.T) {
	h := RateLimitRules(DefaultRules(Limits{
		API: 50, APIBurst: 100,
		Public: 2, PublicBurst: 10,
		Login: 10, LoginBurst: 30,
		Ticket: 20, TicketBurst: 60,
	}, nil))(okHandler())

	// 1) 同一个 IP 连续 20 次登录：burst 30 之内，全部放行
	for i := 0; i < 20; i++ {
		if code := do(h, "203.0.113.7", "/v1/auth/login"); code != 200 {
			t.Fatalf("第 %d 次登录被限流（%d）——登录不该与外链共享 2 rps 的桶", i+1, code)
		}
	}
	// 2) 同一 IP 打外链兑换：burst 10，第 11 次必须 429
	for i := 0; i < 10; i++ {
		if code := do(h, "203.0.113.7", "/v1/public/shares/tok"); code != 200 {
			t.Fatalf("前 10 次外链请求应放行，第 %d 次得到 %d", i+1, code)
		}
	}
	if code := do(h, "203.0.113.7", "/v1/public/shares/tok"); code != http.StatusTooManyRequests {
		t.Fatalf("外链兑换超出 burst 应 429，实际 %d", code)
	}
	// 3) 登录仍然有自己的余量（说明第 2 步没有把登录桶一起耗尽）
	if code := do(h, "203.0.113.7", "/v1/auth/login"); code != 200 {
		t.Fatalf("外链被限流后登录应仍可用，实际 %d", code)
	}
}

// 票据按票据计数：同一公司出口的两个访客看不同分享，不该互相挤掉。
func TestTicketBucketIsPerTicketNotPerIP(t *testing.T) {
	h := RateLimitRules(DefaultRules(Limits{
		API: 50, APIBurst: 100,
		Public: 2, PublicBurst: 2,
		Login: 10, LoginBurst: 30,
		Ticket: 5, TicketBurst: 5,
	}, nil))(okHandler())

	// 票据 A 用满自己的桶
	for i := 0; i < 5; i++ {
		if code := do(h, "198.51.100.9", "/v1/public/tickets/aaa/nodes"); code != 200 {
			t.Fatalf("票据 A 第 %d 次应放行，实际 %d", i+1, code)
		}
	}
	if code := do(h, "198.51.100.9", "/v1/public/tickets/aaa/content"); code != http.StatusTooManyRequests {
		t.Fatalf("票据 A 超额应 429，实际 %d", code)
	}
	// 同一 IP 的票据 B 不受影响
	if code := do(h, "198.51.100.9", "/v1/public/tickets/bbb/nodes"); code != 200 {
		t.Fatalf("票据 B 应独立计数，实际 %d", code)
	}
}

// 票据路径在 /v1/public/ 之下：规则顺序如果写反，票据会永远命中严格的公开档。
func TestTicketRulePrecedesPublicRule(t *testing.T) {
	h := RateLimitRules(DefaultRules(Limits{
		API: 50, APIBurst: 100,
		Public: 1, PublicBurst: 1,
		Login: 10, LoginBurst: 30,
		Ticket: 20, TicketBurst: 60,
	}, nil))(okHandler())

	// 公开档 burst=1：若票据规则没先命中，第 2 个票据请求就会被拒
	for i := 0; i < 5; i++ {
		if code := do(h, "192.0.2.1", "/v1/public/tickets/t1/content"); code != 200 {
			t.Fatalf("票据第 %d 次被公开档误伤（%d）——规则顺序错误", i+1, code)
		}
	}
}

// 429 必须带 Retry-After，客户端才知道等多久（不要让它猜或立刻重试）。
func TestRateLimitSetsRetryAfter(t *testing.T) {
	h := RateLimitRules(DefaultRules(Limits{
		API: 1, APIBurst: 1, Public: 1, PublicBurst: 1,
		Login: 1, LoginBurst: 1, Ticket: 1, TicketBurst: 1,
	}, nil))(okHandler())

	do(h, "192.0.2.55", "/v1/files")
	req := httptest.NewRequest(http.MethodGet, "/v1/files", nil)
	req.RemoteAddr = "192.0.2.55:1234"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("应 429，实际 %d", rec.Code)
	}
	if v := rec.Header().Get("Retry-After"); v == "" {
		t.Fatal("429 缺少 Retry-After")
	} else if n, err := strconv.Atoi(v); err != nil || n < 1 {
		t.Fatalf("Retry-After 应为正整数秒，实际 %q", v)
	}
}

func okHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
}

func do(h http.Handler, ip, path string) int {
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.RemoteAddr = ip + ":1234"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code
}
