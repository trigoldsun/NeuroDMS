package httpmw

import (
	"net/http"
	"strconv"
	"sync"
	"time"
)

// Limiter 是按 key 计数的令牌桶限流器（进程内）。
//
// 为什么不用 Redis 实现：
// 当前是单实例部署，跨进程共享的代价（一次网络往返、Redis 故障时的取舍）
// 换不来收益；接口按 key 设计，将来换 Redis 只需替换实现，不动调用方。
//
// 取舍说明：进程内限流在多副本下是"每副本各自限流"，等效阈值会被放大。
// 这一点写在这里，避免有人误以为它是全局配额——全局配额属于 M3（计量计费）。
type Limiter struct {
	mu      sync.Mutex
	rate    float64 // 每秒补充的令牌数
	burst   float64 // 桶容量
	ttl     time.Duration
	buckets map[string]*bucket
	now     func() time.Time
}

type bucket struct {
	tokens float64
	last   time.Time
}

// NewLimiter 创建限流器。rate<=0 时返回 nil（调用方据此关闭限流）。
func NewLimiter(rate float64, burst int) *Limiter {
	if rate <= 0 || burst <= 0 {
		return nil
	}
	return &Limiter{
		rate: rate, burst: float64(burst),
		ttl:     10 * time.Minute,
		buckets: make(map[string]*bucket),
		now:     time.Now,
	}
}

// Allow 判断某 key 是否可以放行；不允许时返回建议的重试等待时间。
func (l *Limiter) Allow(key string) (bool, time.Duration) {
	if l == nil {
		return true, 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	b, ok := l.buckets[key]
	if !ok {
		// 惰性清理：只在新建桶时扫一遍，避免每次请求都遍历全表
		l.gcLocked(now)
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[key] = b
	}

	elapsed := now.Sub(b.last).Seconds()
	if elapsed > 0 {
		b.tokens += elapsed * l.rate
		if b.tokens > l.burst {
			b.tokens = l.burst
		}
		b.last = now
	}

	if b.tokens >= 1 {
		b.tokens--
		return true, 0
	}
	need := (1 - b.tokens) / l.rate
	return false, time.Duration(need * float64(time.Second))
}

// gcLocked 清理长期未使用的桶。长期运行下这是必须的：
// 攻击者可以用大量随机 IP/随机 nodeId 让 map 无限增长，最终把进程 OOM。
func (l *Limiter) gcLocked(now time.Time) {
	if len(l.buckets) < 1024 {
		return
	}
	for k, b := range l.buckets {
		if now.Sub(b.last) > l.ttl {
			delete(l.buckets, k)
		}
	}
}

// Len 返回当前桶数量（测试与观测用）。
func (l *Limiter) Len() int {
	if l == nil {
		return 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.buckets)
}

// RateLimit 按 keyFn 提取的键做限流，超限返回 429 并带 Retry-After。
//
// 为什么 429 而不是 403：限流是"现在不行、等会儿可以"，403 会让客户端
// 认为这是永久性权限问题而放弃重试；Retry-After 才能让行为良好的客户端退避。
func RateLimit(l *Limiter, keyFn func(*http.Request) string) func(http.Handler) http.Handler {
	return RateLimitRules([]RateRule{{Limiter: l, Key: keyFn}})
}

// RateRule 是一条限流规则：匹配则用该限流器。
type RateRule struct {
	// Match 为 nil 表示匹配所有请求
	Match   func(*http.Request) bool
	Limiter *Limiter
	Key     func(*http.Request) string
}

// RateLimitRules 按顺序匹配规则，第一条命中的规则生效。
//
// 用"规则列表"而不是单一阈值，是因为不同端点的风险完全不同：
// 登录与公开兑换链接是暴力破解入口（必须很严），
// 而文件列表/预览可能被前端合理并发（太严会误伤）。
// 按路径前缀分流比"一刀切调大阈值"安全得多。
func RateLimitRules(rules []RateRule) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			for _, rule := range rules {
				if rule.Limiter == nil {
					continue
				}
				if rule.Match != nil && !rule.Match(r) {
					continue
				}
				key := ""
				if rule.Key != nil {
					key = rule.Key(r)
				}
				ok, wait := rule.Limiter.Allow(key)
				if !ok {
					secs := int(wait.Seconds() + 0.999)
					if secs < 1 {
						secs = 1
					}
					w.Header().Set("Retry-After", strconv.Itoa(secs))
					w.Header().Set("Content-Type", "application/json; charset=utf-8")
					w.WriteHeader(http.StatusTooManyRequests)
					_, _ = w.Write([]byte(`{"code":"RATE_LIMITED","message":"请求过于频繁，请稍后再试","data":null}`))
					return
				}
				break
			}
			next.ServeHTTP(w, r)
		})
	}
}
