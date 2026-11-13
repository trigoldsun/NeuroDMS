// Package webui 提供前端静态资源与 SPA 回退。
//
// 为什么需要回退：前端是单页应用，/files、/s/{token} 这些路径在服务端没有对应文件，
// 直接 404 会让用户刷新页面就白屏。这里把"找不到文件"的 GET 请求统一交回 index.html，
// 由前端路由接管。
package webui

import (
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
)

// Handler 是静态资源处理器；目录未就绪时 Available() 为 false。
type Handler struct {
	dir       string
	available bool
}

// New 创建处理器。dir 不存在时不报错，只是标记为不可用（便于纯 API 模式启动）。
func New(dir string) *Handler {
	if dir == "" {
		return &Handler{}
	}
	if st, err := os.Stat(filepath.Join(dir, "index.html")); err != nil || st.IsDir() {
		return &Handler{dir: dir}
	}
	return &Handler{dir: dir, available: true}
}

// entryFor 选择回退用的入口 HTML。
//
// 平台运营后台（/platform）刻意与租户侧分成两个入口：
// 它们的登录体系、令牌存放位置、可访问的能力都不同，
// 混在一个 SPA 里最容易出现"用错令牌调错接口"的问题。
// 分成两个 bundle 后，平台页面的代码里根本不存在租户 API 的调用路径。
func (h *Handler) entryFor(clean string) string {
	if clean == "/platform" || strings.HasPrefix(clean, "/platform/") {
		if st, err := os.Stat(filepath.Join(h.dir, "platform.html")); err == nil && !st.IsDir() {
			return "platform.html"
		}
	}
	return "index.html"
}

// Available 表示前端产物是否就绪。
func (h *Handler) Available() bool { return h.available }

// ServeHTTP 先找静态文件，找不到则回退到 index.html（仅 GET/HEAD）。
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !h.available {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 防目录穿越：清理后必须仍在根目录内。
	//
	// 判定用 root+分隔符 而不是裸前缀：裸前缀下 /srv/web 与 /srv/web-evil 都能通过。
	// 今天之所以没被利用，是因为 path.Clean("/"+p) 已经把 ".." 折叠掉了；
	// 但只要以后有人把这一步换成别的前缀处理，裸前缀立刻变成目录穿越。
	clean := path.Clean("/" + r.URL.Path)
	full := filepath.Join(h.dir, filepath.FromSlash(clean))
	root, rerr := filepath.Abs(h.dir)
	abs, aerr := filepath.Abs(full)
	if rerr != nil || aerr != nil ||
		(abs != root && !strings.HasPrefix(abs, root+string(os.PathSeparator))) {
		http.NotFound(w, r)
		return
	}

	if st, err := os.Stat(abs); err == nil && !st.IsDir() {
		http.ServeFile(w, r, abs)
		return
	}

	// SPA 回退：入口 HTML 不缓存，避免发版后用户仍拿到旧页面
	w.Header().Set("Cache-Control", "no-cache")
	http.ServeFile(w, r, filepath.Join(h.dir, h.entryFor(clean)))
}
