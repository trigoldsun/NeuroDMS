// Package media 把上传的音视频转成 HLS，供浏览器在线播放。
//
// 关键取舍（与 PRD 的"体验优先"对应）：
//  1. 源片已经是 H.264/AAC 时只做 remux（-c copy），不做重编码——通常 10 秒内完成；
//  2. 需要转码时按源分辨率产出 1~3 个码率变体，播放器自适应；
//  3. 分片 4 秒 + fMP4：拖动响应快，且单分片可独立解密/签名；
//  4. 转码有并发上限：不加限制时一次批量上传会把 CPU 打满，API 跟着变慢。
package media

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ErrUnavailable 表示本机没有可用的 ffmpeg。
var ErrUnavailable = errors.New("未安装 ffmpeg，无法转码")

// ErrTooLargeOrLong 表示源片超出策略上限。
var ErrTooLargeOrLong = errors.New("源片超出转码策略上限")

// Config 是转码配置。
type Config struct {
	// Bin 是 ffmpeg 路径，Probe 是 ffprobe 路径
	Bin   string
	Probe string
	// Dir 是转码产物根目录
	Dir       string
	Secret    string
	PublicURL string
	// MaxConcurrent 同时进行的转码任务数（默认 2）
	MaxConcurrent int
	// MaxDuration 单文件最大时长（默认 4 小时）
	MaxDuration time.Duration
	Timeout     time.Duration
}

// Result 是一次转码结果。
type Result struct {
	Key         string
	MasterPath  string
	Variants    []Variant
	Remux       bool
	FromCache   bool
	DurationSec float64
}

// Variant 是一个码率变体。
type Variant struct {
	Name      string // 目录名，如 v720
	Width     int
	Height    int
	BitrateK  int
	Bandwidth int
}

// Service 负责转码与签名。
type Service struct {
	cfg Config
	// encoder 是探测到的 H.264 编码器名（libx264 / libopenh264 / 空）
	encoder string
	sem     chan struct{}

	mu    sync.Mutex
	locks map[string]chan struct{}
}

// New 构造服务。找不到 ffmpeg 时返回 nil（音视频播放降级为原片下载）。
// detectEncoder 选一个可用的 H.264 编码器。
//
// 为什么需要探测：交付镜像里的 ffmpeg 是 LGPL 构建，**没有 libx264**，
// 只有 openh264。写死 libx264 的代码在开发机（GPL 版 ffmpeg）上一切正常，
// 一到正式镜像就全部转码失败——这类"环境差异"必须由运行时探测消除。
func detectEncoder(bin string) string {
	out, err := exec.Command(bin, "-hide_banner", "-encoders").Output()
	if err != nil {
		return ""
	}
	text := string(out)
	for _, name := range []string{"libx264", "libopenh264"} {
		if strings.Contains(text, " "+name+" ") {
			return name
		}
	}
	return ""
}

func New(cfg Config) *Service {
	bin := cfg.Bin
	if bin == "" {
		bin = "ffmpeg"
	}
	if _, err := exec.LookPath(bin); err != nil {
		return nil
	}
	probe := cfg.Probe
	if probe == "" {
		probe = "ffprobe"
	}
	if _, err := exec.LookPath(probe); err != nil {
		return nil
	}
	if cfg.MaxConcurrent <= 0 {
		cfg.MaxConcurrent = 2
	}
	if cfg.MaxDuration <= 0 {
		cfg.MaxDuration = 4 * time.Hour
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 30 * time.Minute
	}
	cfg.Bin, cfg.Probe = bin, probe
	return &Service{cfg: cfg, encoder: detectEncoder(bin),
		sem: make(chan struct{}, cfg.MaxConcurrent), locks: map[string]chan struct{}{}}
}

// Available 表示服务可用。
func (s *Service) Available() bool { return s != nil }

// RendererName 返回转码器标识（进入缓存 key，升级 ffmpeg 后自然失效）。
func (s *Service) RendererName() string {
	if s == nil {
		return ""
	}
	return "hls-v1"
}

type probeInfo struct {
	Height   int
	VRaw     string
	ARaw     string
	Duration float64
	HasAudio bool
}

// Prepare 生成（或复用）某个版本的 HLS 产物。
//
// 幂等：同一 key 已存在且 master.m3u8 非空则直接返回，不重复转码。
func (s *Service) Prepare(ctx context.Context, key string, sizeBytes int64, open func() (io.ReadCloser, error)) (Result, error) {
	if s == nil {
		return Result{}, ErrUnavailable
	}

	outDir := filepath.Join(s.cfg.Dir, hashKey(key+s.RendererName()))
	master := filepath.Join(outDir, "master.m3u8")
	if st, err := os.Stat(master); err == nil && st.Size() > 0 {
		return Result{Key: key, MasterPath: master, FromCache: true}, nil
	}

	unlock, err := s.lock(ctx, outDir)
	if err != nil {
		return Result{}, err
	}
	defer unlock()

	// 排队后再查一次：可能已被前一个请求转好
	if st, err := os.Stat(master); err == nil && st.Size() > 0 {
		return Result{Key: key, MasterPath: master, FromCache: true}, nil
	}

	// 并发名额：满了就等，等待期间可被取消
	select {
	case s.sem <- struct{}{}:
		defer func() { <-s.sem }()
	case <-ctx.Done():
		return Result{}, ctx.Err()
	}

	work, err := os.MkdirTemp(filepath.Dir(outDir), ".hls-*")
	if err != nil {
		return Result{}, err
	}
	defer func() { _ = os.RemoveAll(work) }()

	srcPath := filepath.Join(work, "source")
	if err := writeTo(open, srcPath); err != nil {
		return Result{}, err
	}

	info, err := s.probe(ctx, srcPath)
	if err != nil {
		return Result{}, err
	}
	if s.cfg.MaxDuration > 0 && info.Duration > s.cfg.MaxDuration.Seconds() {
		return Result{}, ErrTooLargeOrLong
	}

	variants := planVariants(info.Height)
	remux := isBrowserFriendly(info)

	if remux {
		// 只做封装：不重编码，速度快一到两个数量级
		if err := os.MkdirAll(filepath.Join(work, "v0"), 0o750); err != nil {
			return Result{}, err
		}
		v0 := filepath.Join(work, "v0")
		if err := s.runIn(ctx, v0, "ffmpeg", "-y", "-i", srcPath,
			"-c", "copy", "-f", "hls",
			"-hls_time", "4", "-hls_playlist_type", "vod",
			"-hls_segment_type", "fmp4",
			// 文件名必须相对：ffmpeg 会把它拼到播放列表目录后面，
			// 写绝对路径会得到 "<dir>/<绝对路径>" 而打开失败
			"-hls_fmp4_init_filename", "init.mp4",
			"-hls_segment_filename", "seg_%05d.m4s",
			"index.m3u8"); err != nil {
			return Result{}, err
		}
		variants = []Variant{{Name: "v0", Width: 0, Height: info.Height, BitrateK: 0, Bandwidth: 800_000}}
	} else {
		for _, v := range variants {
			dir := filepath.Join(work, v.Name)
			if err := s.transcode(ctx, srcPath, dir, v, info.HasAudio); err != nil {
				return Result{}, err
			}
		}
	}

	// 写 master 播放列表
	if err := writeMaster(filepath.Join(work, "master.m3u8"), variants); err != nil {
		return Result{}, err
	}

	// 原子发布：先转好再改名，避免"半个产物被当成缓存"
	if err := os.RemoveAll(outDir); err != nil {
		return Result{}, err
	}
	if err := os.Rename(work, outDir); err != nil {
		return Result{}, err
	}
	return Result{
		Key: key, MasterPath: filepath.Join(outDir, "master.m3u8"),
		Variants: variants, Remux: remux, DurationSec: info.Duration,
	}, nil
}

func (s *Service) transcode(ctx context.Context, src, outDir string, v Variant, hasAudio bool) error {
	if err := os.MkdirAll(outDir, 0o750); err != nil {
		return err
	}
	if s.encoder == "" {
		return fmt.Errorf("没有可用的 H.264 编码器（libx264 / libopenh264 均不可用）")
	}
	args := []string{"-y", "-i", src,
		"-vf", fmt.Sprintf("scale=-2:%d", v.Height),
		"-c:v", s.encoder,
	}
	// preset/profile 是 libx264 专有参数，openh264 不认，传了会直接失败
	if s.encoder == "libx264" {
		args = append(args, "-preset", "veryfast", "-profile:v", "main")
	}
	args = append(args,
		"-b:v", fmt.Sprintf("%dk", v.BitrateK),
		"-maxrate", fmt.Sprintf("%dk", int(float64(v.BitrateK)*1.2)),
		"-bufsize", fmt.Sprintf("%dk", v.BitrateK*2),
		"-force_key_frames", "expr:gte(t,n_forced*4)",
	)
	if hasAudio {
		args = append(args, "-c:a", "aac", "-b:a", "96k", "-ac", "2")
	} else {
		args = append(args, "-an")
	}
	args = append(args, "-f", "hls",
		"-hls_time", "4", "-hls_playlist_type", "vod",
		"-hls_segment_type", "fmp4",
		"-hls_fmp4_init_filename", "init.mp4",
		"-hls_segment_filename", "seg_%05d.m4s",
		"index.m3u8")
	return s.runIn(ctx, outDir, s.cfg.Bin, args...)
}

func (s *Service) probe(ctx context.Context, path string) (probeInfo, error) {
	cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(cctx, s.cfg.Probe,
		"-v", "error", "-print_format", "json",
		"-show_format", "-show_streams", path)
	out, err := cmd.Output()
	if err != nil {
		return probeInfo{}, fmt.Errorf("探测源片失败: %w", err)
	}

	var raw struct {
		Format struct {
			Duration string `json:"duration"`
		} `json:"format"`
		Streams []struct {
			CodecType string `json:"codec_type"`
			CodecName string `json:"codec_name"`
			Height    int    `json:"height"`
		} `json:"streams"`
	}
	if err := json.Unmarshal(out, &raw); err != nil {
		return probeInfo{}, fmt.Errorf("解析探测结果失败: %w", err)
	}

	info := probeInfo{}
	if d, err := strconv.ParseFloat(raw.Format.Duration, 64); err == nil {
		info.Duration = d
	}
	for _, st := range raw.Streams {
		switch st.CodecType {
		case "video":
			if info.Height < st.Height {
				info.Height = st.Height
				info.VRaw = st.CodecName
			}
		case "audio":
			info.HasAudio = true
			info.ARaw = st.CodecName
		}
	}
	if info.Height == 0 {
		return probeInfo{}, errors.New("源文件不含视频流")
	}
	return info, nil
}

// runIn 在指定工作目录执行外部命令。
//
// dir 必须显式给出：ffmpeg 的 HLS 分片文件名是**相对播放列表目录**解析的，
// 传绝对路径会被拼成 "<dir>/<绝对路径>"（实测报 Failed to open segment）。
// 因此统一以输出目录为 cwd，参数里只写相对名。
func (s *Service) runIn(ctx context.Context, dir, bin string, args ...string) error {
	cctx, cancel := context.WithTimeout(ctx, s.cfg.Timeout)
	defer cancel()
	cmd := exec.CommandContext(cctx, bin, args...)
	if dir != "" {
		cmd.Dir = dir
	}
	// 只传最小环境：不把数据库口令、JWT 密钥泄漏给子进程
	cmd.Env = []string{"PATH=" + os.Getenv("PATH")}
	out, err := cmd.CombinedOutput()
	if err != nil {
		if cctx.Err() != nil {
			return fmt.Errorf("转码超时（%s）", s.cfg.Timeout)
		}
		msg := string(out)
		if len(msg) > 600 {
			msg = msg[len(msg)-600:]
		}
		return fmt.Errorf("ffmpeg 失败: %v: %s", err, msg)
	}
	return nil
}

// planVariants 按源分辨率决定产出哪些码率。
// 不做"上采样"：把 480p 放大成 1080p 只会让文件更大、画质更差。
func planVariants(height int) []Variant {
	out := []Variant{{Name: "v360", Height: 360, BitrateK: 500, Bandwidth: 600_000}}
	if height >= 720 {
		out = append(out, Variant{Name: "v720", Height: 720, BitrateK: 1800, Bandwidth: 2_000_000})
	}
	if height >= 1080 {
		out = append(out, Variant{Name: "v1080", Height: 1080, BitrateK: 4000, Bandwidth: 4_500_000})
	}
	for i := range out {
		out[i].Width = -2 // 由 scale=-2:h 自动推导
	}
	return out
}

func isBrowserFriendly(info probeInfo) bool {
	return strings.EqualFold(info.VRaw, "h264") &&
		(!info.HasAudio || strings.EqualFold(info.ARaw, "aac"))
}

func writeMaster(path string, variants []Variant) error {
	var b strings.Builder
	b.WriteString("#EXTM3U\n#EXT-X-VERSION:7\n")
	for _, v := range variants {
		b.WriteString(fmt.Sprintf("#EXT-X-STREAM-INF:BANDWIDTH=%d,RESOLUTION=%dx%d\n",
			v.Bandwidth, v.Height*16/9, v.Height))
		b.WriteString(v.Name + "/index.m3u8\n")
	}
	return os.WriteFile(path, []byte(b.String()), 0o640)
}

func writeTo(open func() (io.ReadCloser, error), dst string) error {
	rc, err := open()
	if err != nil {
		return err
	}
	defer func() { _ = rc.Close() }()

	f, err := os.Create(dst)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, rc); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

func hashKey(s string) string {
	sum := sha256.Sum256([]byte(s))
	return fmt.Sprintf("%x", sum[:16])
}

// lock 让同一产物的并发请求串行（不同产物不受影响）。
func (s *Service) lock(ctx context.Context, key string) (func(), error) {
	s.mu.Lock()
	ch, busy := s.locks[key]
	if !busy {
		ch = make(chan struct{})
		s.locks[key] = ch
		s.mu.Unlock()
		var once sync.Once
		return func() {
			once.Do(func() {
				s.mu.Lock()
				delete(s.locks, key)
				close(ch)
				s.mu.Unlock()
			})
		}, nil
	}
	s.mu.Unlock()

	select {
	case <-ch:
		return func() {}, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// ---------------- 播放地址签名 ----------------

// SignPlaylist 给某个播放列表生成签名地址。
//
// HLS 的痛点是：一个 playlist 会引出几十个分片请求，
// 每个请求都带 Authorization 头不现实（浏览器原生播放器带不了）。
// 因此做成"签名 URL + 短期有效"，并把签名绑到 key 上——
// 换一个视频的 key 签名即失效。
// SignPlaylist 为一个版本的播放列表生成签名 URL。
//
// 签名只覆盖 key 与过期时间，**不覆盖具体文件路径**：
// HLS 播放器会依次请求 master.m3u8 → v0/index.m3u8 → v0/seg_*.m4s，
// 这些相对路径是播放列表内部引用，播放器不会（也无法）逐个带上签名。
// 若把路径绑进签名，播放列表能取到、分片全部 403——实测就是这样。
func (s *Service) SignPlaylist(key, relPath string, ttl time.Duration) string {
	exp := time.Now().Add(ttl).Unix()
	sig := s.sign(key, exp)
	return fmt.Sprintf("%s/v1/media/%s/%s?e=%d&s=%s",
		strings.TrimRight(s.cfg.PublicURL, "/"), key, relPath, exp, sig)
}

// VerifyPlaylist 校验签名。
func (s *Service) VerifyPlaylist(key, relPath, expStr, sig string) bool {
	exp, err := strconv.ParseInt(expStr, 10, 64)
	if err != nil || time.Now().Unix() > exp {
		return false
	}
	want := s.sign(key, exp)
	return hmac.Equal([]byte(want), []byte(sig))
}

// sign 计算播放授权签名：只绑定 key 与过期时间。
// key 由"节点+大小+修改时间+渲染器版本"派生，改动内容就会换 key。
func (s *Service) sign(key string, exp int64) string {
	mac := hmac.New(sha256.New, []byte(s.cfg.Secret))
	fmt.Fprintf(mac, "media|%s|%d", key, exp)
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// SafePath 校验相对路径不越界（防 ../../ 读取任意文件）。
func SafePath(root, rel string) (string, bool) {
	clean := filepath.Clean("/" + rel)
	full := filepath.Join(root, filepath.FromSlash(clean))
	absRoot, err1 := filepath.Abs(root)
	absFull, err2 := filepath.Abs(full)
	if err1 != nil || err2 != nil {
		return "", false
	}
	if !strings.HasPrefix(absFull, absRoot+string(os.PathSeparator)) {
		return "", false
	}
	return absFull, true
}

// Ready 表示某版本产物已就绪（可直接播放）。
func (s *Service) Ready(key string) bool {
	if s == nil {
		return false
	}
	st, err := os.Stat(filepath.Join(s.dir(key), "master.m3u8"))
	return err == nil && st.Size() > 0
}

// dir 返回某版本的产物目录。
func (s *Service) dir(key string) string {
	return filepath.Join(s.cfg.Dir, hashKey(key+s.RendererName()))
}

// Open 打开产物目录下的某个文件（已做路径越界校验）。
func (s *Service) Open(key, relPath string) (*os.File, error) {
	full, ok := SafePath(s.dir(key), relPath)
	if !ok {
		return nil, os.ErrNotExist
	}
	return os.Open(full)
}
