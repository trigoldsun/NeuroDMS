package httpapi

// RAW 预览：先用内嵌预览图秒开，再让服务端渲染统一尺寸的高清版。
//
// 为什么要有"两段式"：
//   LibRaw 全解码单张 3~11 秒（实测），同步等会让用户以为页面坏了；
//   而 RAW 文件里通常嵌着一张 JPEG，取出来只要 55ms。
//   所以首次请求返回内嵌图，同时在后台渲染，下次打开就是高清且尺寸统一的版本。
//
// 响应头 X-Preview-Source 告诉前端当前拿到的是哪一种：
//   embedded —— 内嵌图，前端可提示"正在生成高清预览"
//   rendered —— 服务端渲染的最终产物

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"docvault/internal/content"
	"docvault/internal/preview"
)

// rawExts 是需要服务端解码的相机原始格式。
var rawExts = map[string]bool{
	".cr2": true, ".cr3": true, ".nef": true, ".arw": true, ".dng": true,
	// 常见但当前未逐一验证的，一并覆盖：解码失败会走错误分支，不会误报成功
	".orf": true, ".rw2": true, ".raf": true, ".pef": true, ".srw": true,
}

func isRawName(name string) bool {
	i := strings.LastIndex(name, ".")
	if i < 0 {
		return false
	}
	return rawExts[strings.ToLower(name[i:])]
}

// tryRawPreview 处理 RAW 预览。返回 false 表示"不是 RAW 或未启用"，交回原有分流。
func (a *API) tryRawPreview(w http.ResponseWriter, r *http.Request, tenantID string, n content.Node) bool {
	if a.Raw == nil || !a.Raw.Available() || !isRawName(n.Name) {
		return false
	}

	key := fmt.Sprintf("raw:%s:%d:%d", n.ID, n.SizeBytes, n.UpdatedAt.UnixNano())
	// 缓存参数进 key：改了最长边/质量之后旧产物自然失效
	key += "|" + a.Raw.Name()

	// 1. 已有渲染产物 → 直接给
	if e, ok := a.Raw.Lookup(key); ok {
		serveJPEGFile(w, r, e.Path, "rendered")
		return true
	}

	// 2. 未渲染：先把内嵌预览图取出来（快），能取到就立刻给用户看
	src, _, err := a.Content.OpenContent(r.Context(), tenantID, n.ID)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "内容不可用")
		return true
	}
	raw, rerr := io.ReadAll(src)
	_ = src.Close()
	if rerr != nil {
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "读取文件失败")
		return true
	}

	if emb, ok := preview.EmbeddedJPEG(raw); ok {
		// 内嵌图常常是全尺寸高质量 JPEG（实测 6.4MB），先缩到统一尺寸再返回，
		// 否则"秒开"会变成"下行几 MB 的慢开"
		emb = a.Raw.ShrinkEmbedded(r.Context(), emb)
		// 后台渲染高清版：只有拿到名额才做，拿不到就等下次请求（不排队、不阻塞）
		if release, aerr := a.Raw.Acquire(); aerr == nil {
			nodeID := n.ID
			go func() {
				defer release()
				// 用独立 context：请求结束后用户可能已关页面，但渲染值得完成
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
				defer cancel()
				rc, _, oerr := a.Content.OpenContent(ctx, tenantID, nodeID)
				if oerr != nil {
					return
				}
				defer func() { _ = rc.Close() }()
				_, _ = a.Raw.Cached(ctx, key, func() (io.ReadCloser, error) { return rc, nil })
			}()
		}
		serveJPEGBytes(w, r, emb, "embedded")
		return true
	}

	// 3. 没有内嵌图：只能同步渲染（少数机型/被裁剪过的文件）
	entry, err := a.Raw.Cached(r.Context(), key, func() (io.ReadCloser, error) {
		rc, _, oerr := a.Content.OpenContent(r.Context(), tenantID, n.ID)
		return rc, oerr
	})
	if err != nil {
		switch {
		case errors.Is(err, preview.ErrRawBusy):
			w.Header().Set("Retry-After", "5")
			writeErr(w, r, http.StatusTooManyRequests, "PREVIEW_BUSY", "预览任务较多，请稍后重试")
		case errors.Is(err, preview.ErrRawUnsupported):
			writeErr(w, r, http.StatusNotImplemented, "PREVIEW_UNAVAILABLE", "本服务器未启用 RAW 解码")
		default:
			writeErr(w, r, http.StatusInternalServerError, "PREVIEW_FAILED", "RAW 解码失败，请下载后查看")
		}
		return true
	}
	serveJPEGFile(w, r, entry.Path, "rendered")
	return true
}

func serveJPEGFile(w http.ResponseWriter, r *http.Request, path, source string) {
	f, err := os.Open(path)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "读取预览失败")
		return
	}
	defer func() { _ = f.Close() }()
	st, err := f.Stat()
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "读取预览失败")
		return
	}
	w.Header().Set("Content-Type", "image/jpeg")
	w.Header().Set("Content-Disposition", "inline")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", st.Size()))
	w.Header().Set("Cache-Control", "private, max-age=60")
	w.Header().Set("X-Preview-Source", source)
	w.WriteHeader(http.StatusOK)
	_, _ = io.Copy(w, f)
}

func serveJPEGBytes(w http.ResponseWriter, r *http.Request, b []byte, source string) {
	w.Header().Set("Content-Type", "image/jpeg")
	w.Header().Set("Content-Disposition", "inline")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(b)))
	w.Header().Set("Cache-Control", "private, max-age=60")
	w.Header().Set("X-Preview-Source", source)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(b)
}
