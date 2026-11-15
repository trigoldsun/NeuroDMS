package httpmw

import (
	"net/http"
	"net/netip"
	"strings"
)

// Limits 是四档限流的阈值（0 表示该档关闭）。
//
// 单独定义在这里、而不是直接写在 main 里，是为了**能被测试**：
// "登录与外链是否共用一个桶"这类问题，只有把规则装起来打一遍请求才看得出来。
type Limits struct {
	API      float64
	APIBurst int

	Public      float64
	PublicBurst int

	Login      float64
	LoginBurst int

	Ticket      float64
	TicketBurst int
}

// 登录入口（口令 / 短信验证码 / 二次验证 / 平台账号）。
// 这四个都是"猜凭据"的入口，共用同一个按 IP 计数的桶。
var loginPaths = map[string]bool{
	"/v1/auth/login":          true,
	"/v1/auth/sms/login":      true,
	"/v1/auth/mfa/verify":     true,
	"/v1/platform/auth/login": true,
}

// DefaultRules 组装四档规则。顺序即优先级，**第一条命中生效**：
//
//	票据 → 登录 → 其余公开 → 业务
//
// 票据必须在"其余公开"之前，否则永远命中不到（它的路径也在 /v1/public/ 下）。
func DefaultRules(l Limits, trusted []netip.Prefix) []RateRule {
	ipKey := func(prefix string) func(*http.Request) string {
		return func(r *http.Request) string {
			return prefix + ClientIP(r, trusted).String()
		}
	}
	return []RateRule{
		{
			// 票据：已凭高熵票据认证，一屏要连发多个请求（列表/缩略图/正文）。
			// 按**票据**计数而不是按 IP：同一份内容被同一公司的多人打开时，
			// 不该互相挤掉；取不到票据时退回按 IP，避免留一个不限流的空洞。
			Match: func(r *http.Request) bool {
				return strings.HasPrefix(r.URL.Path, "/v1/public/tickets/")
			},
			Limiter: NewLimiter(l.Ticket, l.TicketBurst),
			Key: func(r *http.Request) string {
				tk := strings.TrimPrefix(r.URL.Path, "/v1/public/tickets/")
				if i := strings.IndexByte(tk, '/'); i > 0 {
					tk = tk[:i]
				}
				if tk == "" {
					return "ticket:ip:" + ClientIP(r, trusted).String()
				}
				return "ticket:" + tk
			},
		},
		{
			// 登录：按 IP 计数。真正防爆破的是账号级锁定，这里只是第一层，
			// 所以给了"同一个出口 IP 下多人同时登录"留够余量。
			Match: func(r *http.Request) bool {
				return loginPaths[r.URL.Path]
			},
			Limiter: NewLimiter(l.Login, l.LoginBurst),
			Key:     ipKey("login:"),
		},
		{
			// 其余公开端点（含 /v1/public/shares/{token} 的兑换）：防令牌枚举，保持最严
			Match: func(r *http.Request) bool {
				return strings.HasPrefix(r.URL.Path, "/v1/public/")
			},
			Limiter: NewLimiter(l.Public, l.PublicBurst),
			Key:     ipKey("public:"),
		},
		{
			Limiter: NewLimiter(l.API, l.APIBurst),
			Key:     ipKey("api:"),
		},
	}
}
