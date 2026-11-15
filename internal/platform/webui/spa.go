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

// looksLikeAsset 判断这个路径是否"看起来是静态资源/探测路径"而不是 SPA 路由。
//
// 两类：
//  1. 任一段以点开头（.env、.git/config）——扫描器与小动作最常试的形态；
//     .well-known 例外（ACME / 站点验证要能访问）。
//  2. 最后一段带扩展名（/go.mod、/backup.sql）。
//
// SPA 路由约定为纯标识段（/files/<uuid>、/s/<token>、/platform/tenants），
// 所以这个判断不会误伤正常页面。
func looksLikeAsset(p string) bool {
	for _, seg := range strings.Split(p, "/") {
		if seg == "" || seg == "." || seg == ".." {
			continue
		}
		if strings.HasPrefix(seg, ".") && seg != ".well-known" {
			return true
		}
	}
	return path.Ext(p) != ""
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

	if st, err := os.Stat(abs); err == nil {
		if !st.IsDir() {
			http.ServeFile(w, r, abs)
			return
		}
		// 目录请求（例如 /manual/）优先给它的 index.html。
		//
		// 不这么做会落到下面的 SPA 回退：从工作台点"使用手册"，打开的却是
		// 应用首页——比 404 更让人困惑，因为界面上完全看不出哪里错了。
		idx := filepath.Join(abs, "index.html")
		if ist, e := os.Stat(idx); e == nil && !ist.IsDir() {
			http.ServeFile(w, r, idx)
			return
		}
	}

	// 浏览器没用 link[rel=icon] 时仍会盲取 /favicon.ico（旧书签、外链预览、
	// 部分安卓浏览器的"添加到桌面"）。直接落到下面的 SPA 回退会返回 HTML，
	// 浏览器解码失败，标签页上就是一个空白文档图标——像没做完的产品。
	// 这里回落到内置的 SVG 图标；真放了 favicon.ico 时上面的 Stat 已经命中。
	if clean == "/favicon.ico" {
		svg := filepath.Join(h.dir, "favicon.svg")
		if st, err := os.Stat(svg); err == nil && !st.IsDir() {
			w.Header().Set("Content-Type", "image/svg+xml")
			w.Header().Set("Cache-Control", "public, max-age=3600")
			http.ServeFile(w, r, svg)
			return
		}
	}

	// 带扩展名且确实不存在实体文件的请求 → 404，不回退 index.html。
	//
	// SPA 的地址约定是"无扩展名"（/files/<uuid>、/s/<token>、/platform/tenants），
	// 而扫描器与运维探测的都是 /.env、/.git/config、/backup.sql 这类带扩展名的路径。
	// 把探测回退成 200 + 首页，会让人误以为"这个路径存在"，也让日志里的 404
	// 失去排障价值。真实文件（/manual/x.html、/assets/x.js）在上面的 Stat 已经命中。
	if looksLikeAsset(clean) {
		http.NotFound(w, r)
		return
	}

	// SPA 回退：入口 HTML 不缓存，避免发版后用户仍拿到旧页面
	w.Header().Set("Cache-Control", "no-cache")
	http.ServeFile(w, r, filepath.Join(h.dir, h.entryFor(clean)))
}
