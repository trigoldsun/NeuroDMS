package httpapi

import (
	"context"
	"io"
	"mime"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"docvault/internal/authz"
	"docvault/internal/feature"
)

// registerMedia 注册音视频播放路由。
func (a *API) registerMedia(mux *http.ServeMux) {
	mux.HandleFunc("GET /v1/nodes/{id}/media", a.requireAuth(a.handleMediaInfo))
	// 播放列表与分片：无会话，靠签名 URL（浏览器原生播放器带不了 Authorization 头）
	mux.HandleFunc("GET /v1/media/{key}/{path...}", a.handleMediaAsset)
}

// 转码任务去重：同一版本只允许一个后台任务在跑
var mediaInflight sync.Map

// handleMediaInfo 返回播放地址；转码未完成时返回 202 并触发后台转码。
//
// 为什么异步：一个 2 小时的会议录像重编码要几分钟到几十分钟，
// 让 HTTP 请求等这么久必然超时；前端应显示"正在准备"并轮询。
func (a *API) handleMediaInfo(w http.ResponseWriter, r *http.Request) {
	c, _ := claimsFrom(r.Context())
	nodeID := r.PathValue("id")

	if a.Media == nil {
		writeErr(w, r, http.StatusNotImplemented, "MEDIA_UNAVAILABLE", "服务器未启用音视频转码")
		return
	}

	n, err := a.Content.GetNode(r.Context(), c.TenantID, nodeID)
	if err != nil {
		writeErr(w, r, http.StatusNotFound, "NOT_FOUND", "对象不存在")
		return
	}
	if n.Kind != "file" {
		writeErr(w, r, http.StatusBadRequest, "INVALID_ARGUMENT", "目录不支持播放")
		return
	}
	// 播放要求 preview 位：能看不等于能下载
	d, err := a.check(r.Context(), c, n.SpaceID, nodeID, authz.Preview)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "INTERNAL", "权限判定失败")
		return
	}
	if a.denyUnless(w, r, d) {
		return
	}

	// 灰度开关：平台可以关闭某租户的转码能力（例如额度用尽或合规要求）。
	// 关闭后仍可播放**已转码**的产物——否则一次开关动作会让所有历史视频无法播放。
	//
	// 读不到开关时按"不能转码"处理（fail-closed），但仍允许播放已就绪的产物：
	// 既不让故障变成静默的能力放开，也不让历史视频在故障期间集体失效。
	transcodeAllowed := false
	var mediaFlag feature.EffectiveFlag
	if fs, ferr := a.featureState(r.Context(), c.TenantID, feature.MediaTranscode); ferr == nil {
		transcodeAllowed, mediaFlag = fs.Enabled, fs
	}

	key := mediaKey(n.ID, n.SizeBytes, n.UpdatedAt)
	if !transcodeAllowed && !a.Media.Ready(key) {
		msg := "当前租户未开启音视频转码，请联系平台运营"
		if mediaFlag.Code != "" {
			msg = featureDenyMessage(mediaFlag, "音视频转码")
		} else {
			msg = "转码能力暂时不可用，请稍后重试"
		}
		writeErr(w, r, http.StatusForbidden, "FEATURE_DISABLED", msg)
		return
	}
	if !a.Media.Ready(key) {
		// 后台转码（同一 key 只启动一次）
		if _, loaded := mediaInflight.LoadOrStore(key, struct{}{}); !loaded {
			go func(id, tenantID, k string, size int64) {
				defer mediaInflight.Delete(k)
				ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
				defer cancel()
				_, perr := a.Media.Prepare(ctx, k, size, func() (io.ReadCloser, error) {
					rc, _, oerr := a.Content.OpenContent(ctx, tenantID, id)
					return rc, oerr
				})
				if perr != nil && a.Log != nil {
					a.Log.Warn("音视频转码失败", "node", id, "err", perr.Error())
				}
			}(n.ID, c.TenantID, key, n.SizeBytes)
		}
		w.Header().Set("Retry-After", "5")
		writeJSON(w, r, http.StatusAccepted, map[string]any{
			"data": map[string]any{"status": "preparing", "retryAfter": 5},
		})
		return
	}

	master := a.Media.SignPlaylist(key, "master.m3u8", 2*time.Hour)
	writeOK(w, r, map[string]any{
		"status":      "ready",
		"playlistUrl": master,
		"format":      "hls",
	})
}

// handleMediaAsset 提供播放列表与分片。
func (a *API) handleMediaAsset(w http.ResponseWriter, r *http.Request) {
	if a.Media == nil {
		http.NotFound(w, r)
		return
	}
	key := r.PathValue("key")
	rel := r.PathValue("path")
	q := r.URL.Query()

	if !a.Media.VerifyPlaylist(key, rel, q.Get("e"), q.Get("s")) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	f, err := a.Media.Open(key, rel)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer func() { _ = f.Close() }()

	st, err := f.Stat()
	if err != nil {
		http.Error(w, "internal", http.StatusInternalServerError)
		return
	}

	switch strings.ToLower(filepath.Ext(rel)) {
	case ".m3u8":
		w.Header().Set("Content-Type", "application/vnd.apple.mpegurl")
		// 播放列表会引出分片请求，必须先于分片失效，否则用户会拿到 403 的分片
		w.Header().Set("Cache-Control", "private, max-age=30")
	case ".m4s", ".mp4":
		w.Header().Set("Content-Type", "video/mp4")
		w.Header().Set("Cache-Control", "private, max-age=600")
	default:
		w.Header().Set("Content-Type", mime.TypeByExtension(filepath.Ext(rel)))
	}
	w.Header().Set("Content-Length", itoa64(st.Size()))
	http.ServeContent(w, r, rel, st.ModTime(), f)
}

func mediaKey(nodeID string, size int64, updated time.Time) string {
	return nodeID + ":" + itoa64(size) + ":" + itoa64(updated.UnixNano())
}

func itoa64(v int64) string {
	if v == 0 {
		return "0"
	}
	neg := v < 0
	if neg {
		v = -v
	}
	var b [20]byte
	i := len(b)
	for v > 0 {
		i--
		b[i] = byte('0' + v%10)
		v /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
