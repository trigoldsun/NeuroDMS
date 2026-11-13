// Package httpmw 提供全局中间件。
//
// 关键纪律（0201-C2）：clientIP 默认只认 RemoteAddr。
// 只有在显式配置了可信代理网段时，才解析 X-Forwarded-For，且取"最右侧的非信任跳"，
// 而不是取首段——首段完全由客户端控制。
package httpmw

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"
)

type ctxKey string

const requestIDKey ctxKey = "request_id"

// RequestID 为每个请求生成可追踪 ID，写入响应头与上下文。
func RequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-Id")
		if id == "" || len(id) > 64 {
			var b [12]byte
			if _, err := rand.Read(b[:]); err != nil {
				id = "req-fallback"
			} else {
				id = hex.EncodeToString(b[:])
			}
		}
		w.Header().Set("X-Request-Id", id)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), requestIDKey, id)))
	})
}

// RequestIDFrom 取出请求 ID。
func RequestIDFrom(ctx context.Context) string {
	if v, ok := ctx.Value(requestIDKey).(string); ok {
		return v
	}
	return ""
}

// Recover 兜底 panic，返回统一信封且不泄漏堆栈。
func Recover(log *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if rec := recover(); rec != nil {
					log.Error("panic recovered",
						"request_id", RequestIDFrom(r.Context()),
						"path", r.URL.Path,
						"panic", rec)
					w.Header().Set("Content-Type", "application/json; charset=utf-8")
					w.WriteHeader(http.StatusInternalServerError)
					_, _ = w.Write([]byte(`{"code":"INTERNAL","message":"internal error","data":null}`))
				}
			}()
			next.ServeHTTP(w, r)
		})
	}
}

// SecurityHeaders 统一安全响应头（踩坑 50：15/15 的 Agent 生成应用都缺这一组）。
// SecurityHeaders 使用默认策略（不允许任何外部来源）。
func SecurityHeaders(next http.Handler) http.Handler {
	return SecurityHeadersFor("")(next)
}

// SecurityHeadersFor 允许指定一个额外的受信来源（在线编辑的文档服务）。
//
// 为什么不能简单放开成 '*'：CSP 是防 XSS 的最后一道，放开等于放弃。
// 这里只允许**确知的一个源**，且只放开脚本、frame、连接与图片四类，
// 文档服务地址来自配置而非请求，攻击者无法影响它。
func SecurityHeadersFor(extraOrigin string) func(http.Handler) http.Handler {
	extra := ""
	if o := strings.TrimRight(extraOrigin, "/"); o != "" {
		extra = " " + o
	}
	csp := "default-src 'self'; " +
		// 'wasm-unsafe-eval' 只放行 WebAssembly 编译，不放行 eval()/new Function()，
		// 比 'unsafe-eval' 窄一个量级。HEIC 预览在浏览器里靠 wasm 解码
		// （服务端 ffmpeg/imagemagick 都没有 heic 解码器），没有这一项会被 CSP 直接拦掉，
		// 表现为"预览一直转圈、控制台只有一条 CompileError"。
		"script-src 'self' 'wasm-unsafe-eval'" + extra + "; " +
		"style-src 'self' 'unsafe-inline'" + extra + "; " +
		"img-src 'self' data: blob:" + extra + "; " +
		"media-src 'self' blob:" + extra + "; " +
		"connect-src 'self'" + extra + "; " +
		// blob: 必须放行：预览把 PDF 读成 Blob 再用 <iframe src="blob:..."> 展示，
		// 只写 'self' 会让浏览器直接提示"该内容被屏蔽了"（实测）。
		"frame-src 'self' blob: data:" + extra + "; " +
		"object-src 'none'; " +
		"frame-ancestors 'self'"

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := w.Header()
			h.Set("X-Content-Type-Options", "nosniff")
			h.Set("X-Frame-Options", "SAMEORIGIN")
			h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
			h.Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
			// 文档系统一律不应被搜索引擎索引：一旦被索引，分享链接与文件清单
			// 就等于公开（robots.txt 只是请求，响应头才是逐页生效的那道）。
			h.Set("X-Robots-Tag", "noindex, nofollow, noarchive")
			h.Set("Content-Security-Policy", csp)
			if r.TLS != nil {
				h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
			}
			next.ServeHTTP(w, r)
		})
	}
}

// AccessLog 输出结构化访问日志（踩坑 61：不能只有 console.log）。
func AccessLog(log *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			rec := &statusRecorder{ResponseWriter: w, status: 200}
			next.ServeHTTP(rec, r)
			log.Info("http",
				"request_id", RequestIDFrom(r.Context()),
				"method", r.Method,
				"path", r.URL.Path,
				"status", rec.status,
				"bytes", rec.bytes,
				"dur_ms", time.Since(start).Milliseconds(),
				"ip", ClientIP(r, nil).String())
		})
	}
}

type statusRecorder struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	n, err := s.ResponseWriter.Write(b)
	s.bytes += n
	return n, err
}

// Unwrap 让 http.ResponseController 能穿透到真实连接。
//
// Go 1.20 起按请求调整读/写截止时间（SetReadDeadline）依赖这条链：
// 包装器不实现 Unwrap，ResponseController 找不到底层 net.Conn，
// 返回 ErrNotSupported——而调用方通常会忽略这个 error，
// 结果是"按租户配置上传超时"看起来改完了，实际一点没生效。
func (s *statusRecorder) Unwrap() http.ResponseWriter { return s.ResponseWriter }

// ClientIP 解析真实来源 IP。
//
// trusted 为空 => 一律使用 RemoteAddr，忽略任何转发头。
// trusted 非空 => 从右往左跳过可信代理，返回第一个不可信跳的地址。
func ClientIP(r *http.Request, trusted []netip.Prefix) netip.Addr {
	remote := parseHost(r.RemoteAddr)
	if len(trusted) == 0 {
		return remote
	}
	if !isTrusted(remote, trusted) {
		// 直连来源本身不可信，转发头无意义
		return remote
	}
	xf := r.Header.Get("X-Forwarded-For")
	if xf == "" {
		return remote
	}
	parts := strings.Split(xf, ",")
	for i := len(parts) - 1; i >= 0; i-- {
		addr := parseHost(strings.TrimSpace(parts[i]))
		if !addr.IsValid() {
			return remote
		}
		if !isTrusted(addr, trusted) {
			return addr
		}
	}
	return remote
}

func isTrusted(addr netip.Addr, trusted []netip.Prefix) bool {
	if !addr.IsValid() {
		return false
	}
	for _, p := range trusted {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// RealIP 在"直连来源可信"时把 r.RemoteAddr 改写为真实客户端地址。
//
// 为什么改写 RemoteAddr，而不是再提供一个"从 ctx 取真实 IP"的函数：
// 下游要取来源 IP 的地方很多——审计日志、分享链接的 IP 白名单、水印页脚、
// 登录失败记录、限流键。任何一处忘了改读 ctx，就会悄悄退回代理地址，
// 而"所有记录都是同一个内网 IP"在界面上几乎看不出来，只有翻审计时才会发现
// 取证信息已经废掉；IP 白名单则会变成"要么全拦、要么全放"。
// 改写一次，所有既有调用点（httpapi.clientIP）自动正确。
//
// trusted 为空时不做任何事：本地直连场景下 XFF 完全由客户端控制，采信即为伪造。
func RealIP(trusted []netip.Prefix) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			peer := parseHost(r.RemoteAddr)

			// 直连对端**永远**记下来，与是否配置可信代理无关。
			//
			// 用途是 SSO：判断"这条断言是不是受信代理写的"，必须看真实对端。
			// 若用改写后的 RemoteAddr，前置代理会把客户端地址填进来，
			// 于是任何 LAN 客户端都"像是"可信任来源——那是认证绕过。
			r = r.Clone(context.WithValue(r.Context(), peerKey{}, peer))

			if len(trusted) > 0 {
				if ip := ClientIP(r, trusted); ip.IsValid() && ip != peer {
					r.RemoteAddr = net.JoinHostPort(ip.String(), "0")
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

type peerKey struct{}

// DirectPeer 返回直连本服务的对端地址（未经 X-Forwarded-For 改写）。
//
// 与 clientIP(r) 的区别：后者是"业务意义上的客户端"（可能是转发来的真实用户），
// 而这个是"TCP 连接的对端"。判断请求是否来自受信代理时只能用后者。
func DirectPeer(ctx context.Context) netip.Addr {
	if v, ok := ctx.Value(peerKey{}).(netip.Addr); ok {
		return v
	}
	return netip.Addr{}
}

func parseHost(s string) netip.Addr {
	s = strings.TrimSpace(s)
	if s == "" {
		return netip.Addr{}
	}
	if host, _, err := net.SplitHostPort(s); err == nil {
		s = host
	}
	s = strings.Trim(s, "[]")
	if a, err := netip.ParseAddr(s); err == nil {
		return a.Unmap()
	}
	return netip.Addr{}
}
