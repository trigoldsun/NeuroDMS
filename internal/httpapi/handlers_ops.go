package httpapi

import (
	"crypto/subtle"
	"fmt"
	"net/http"
	"runtime"
)

// registerOps 注册运维类端点。
func (a *API) registerOps(mux *http.ServeMux) {
	mux.HandleFunc("GET /metrics", a.handleMetrics)
}

// handleMetrics 暴露最小化的 Prometheus 指标。
//
// 为什么用独立令牌而不是用户会话：
// 指标里会有进程与租户级计数，属于"运维可见、业务不可见"的数据。
// 抓取端是 Prometheus，不该持有任何人的登录凭证。
// 未配置令牌时一律 401（fail-closed）——绝不能因为"忘了配"就公开指标。
func (a *API) handleMetrics(w http.ResponseWriter, r *http.Request) {
	if a.MetricsToken == "" {
		writeErr(w, r, http.StatusUnauthorized, "UNAUTHORIZED", "指标端点未启用")
		return
	}
	raw := r.Header.Get("Authorization")
	want := "Bearer " + a.MetricsToken
	if len(raw) != len(want) || subtle.ConstantTimeCompare([]byte(raw), []byte(want)) != 1 {
		writeErr(w, r, http.StatusUnauthorized, "UNAUTHORIZED", "缺少指标抓取令牌")
		return
	}

	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "# HELP docvault_up 服务是否存活\n# TYPE docvault_up gauge\ndocvault_up 1\n")
	fmt.Fprintf(w, "# HELP docvault_goroutines 当前 goroutine 数\n# TYPE docvault_goroutines gauge\ndocvault_goroutines %d\n", runtime.NumGoroutine())
	fmt.Fprintf(w, "# HELP docvault_heap_bytes 堆内存字节数\n# TYPE docvault_heap_bytes gauge\ndocvault_heap_bytes %d\n", ms.HeapAlloc)
	fmt.Fprintf(w, "# HELP docvault_start_time_seconds 进程启动时间（Unix 秒）\n# TYPE docvault_start_time_seconds gauge\ndocvault_start_time_seconds %d\n", a.startedAt.Unix())
}

// handleRobots 明确禁止搜索引擎抓取。
//
// 文档系统里的链接一旦被搜索索引，等于把内部文件清单公开：
// 分享链接可以被猜、被缓存、被第三方镜像。robots.txt 是"请求"而非"强制"，
// 所以同时给所有响应加 X-Robots-Tag（见 httpmw.SecurityHeaders）。
func (a *API) handleRobots(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	_, _ = w.Write([]byte("User-agent: *\nDisallow: /\n"))
}
