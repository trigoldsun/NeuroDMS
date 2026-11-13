package preview

// RAW 预览：服务端用 LibRaw 全解码，输出统一尺寸的 JPEG。
//
// 为什么不靠"提取内嵌 JPEG"作为主路径：内嵌预览的尺寸随机型变化，
// 有的机型给全尺寸、有的只给 160×120 缩略图，无法做统一的预览体验。
// 但内嵌图仍然有用——它只要 55ms，适合做首屏（见 handlers_raw.go）。
//
// 实测（16 核）：CR2 8688×5792 解码约 10 秒、峰值内存 644MB；NEF 2832×4256 约 2.7 秒。
// 因此这里有三条硬约束：并发必须限流、必须有超时、必须缓存。

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"image/jpeg"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"
)

// ErrRawBusy 表示渲染并发已满，调用方应降级（用内嵌图）或稍后重试。
var ErrRawBusy = errors.New("RAW 渲染任务已满")

// ErrRawUnsupported 表示本实例没有可用的 RAW 解码器。
var ErrRawUnsupported = errors.New("本服务器未启用 RAW 解码")

const rawRendererRev = "libraw-r1"

// RawOptions 是渲染器参数。
type RawOptions struct {
	// CacheDir 存放渲染产物（JPEG）；与 PDF 缓存分开，避免混在一起清理
	CacheDir string
	// MaxEdge 输出 JPEG 的最长边
	MaxEdge int
	// Quality 是 ffmpeg 的 -q:v（1 最好，31 最差）
	Quality int
	// MaxConcurrent 同时渲染的张数。单张峰值 644MB，这个值直接决定内存上限
	MaxConcurrent int
	// Timeout 单张渲染超时
	Timeout time.Duration
}

// RawRenderer 负责 RAW → JPEG。
type RawRenderer struct {
	dcraw    string
	ffmpeg   string
	dir      string
	maxEdge  int
	quality  int
	timeout  time.Duration
	sem      chan struct{}
	sf       *singleflight
	renderer string
}

// NewRawRenderer 创建渲染器。工具缺失时返回 error（调用方据此判定"未启用"）。
func NewRawRenderer(opt RawOptions) (*RawRenderer, error) {
	dc, err := exec.LookPath("dcraw_emu")
	if err != nil {
		return nil, fmt.Errorf("未找到 dcraw_emu（安装 libraw-tools）: %w", err)
	}
	ff, err := exec.LookPath("ffmpeg")
	if err != nil {
		return nil, fmt.Errorf("未找到 ffmpeg: %w", err)
	}
	if opt.MaxEdge <= 0 {
		opt.MaxEdge = 2400
	}
	if opt.Quality <= 0 || opt.Quality > 31 {
		opt.Quality = 3
	}
	if opt.MaxConcurrent <= 0 {
		opt.MaxConcurrent = 2
	}
	if opt.Timeout <= 0 {
		opt.Timeout = 120 * time.Second
	}
	if opt.CacheDir == "" {
		return nil, errors.New("RAW 缓存目录不能为空")
	}
	if err := os.MkdirAll(opt.CacheDir, 0o750); err != nil {
		return nil, fmt.Errorf("创建 RAW 缓存目录失败: %w", err)
	}
	return &RawRenderer{
		dcraw: dc, ffmpeg: ff, dir: opt.CacheDir,
		maxEdge: opt.MaxEdge, quality: opt.Quality, timeout: opt.Timeout,
		sem:      make(chan struct{}, opt.MaxConcurrent),
		sf:       newSingleflight(),
		renderer: rawRendererRev,
	}, nil
}

// Available 供格式目录判定"能不能预览"。
func (r *RawRenderer) Available() bool { return r != nil }

// Name 返回渲染器标识（进缓存 key，换参数自然失效）。
func (r *RawRenderer) Name() string {
	return fmt.Sprintf("%s-e%d-q%d", r.renderer, r.maxEdge, r.quality)
}

// ShrinkEmbedded 把内嵌预览图缩到统一尺寸。
//
// 为什么需要：相机内嵌的往往是全尺寸高质量 JPEG（实测 NEF 的内嵌图 6.4MB、
// 比服务端渲染出的 1.5MB 还大）。下行慢时首屏光传输就要几十秒，
// "秒开"变成"慢开"。这里用 ffmpeg 重编码一次，代价约 200ms，体积降一个量级。
// 失败时返回原图——宁可大一点，也不要因为缩图失败而看不了。
func (r *RawRenderer) ShrinkEmbedded(ctx context.Context, b []byte) []byte {
	if len(b) <= 1<<20 {
		return b // 已经够小，不值得再编一次
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, r.ffmpeg, "-y", "-loglevel", "error",
		"-f", "image2pipe", "-c:v", "mjpeg", "-i", "-",
		"-vf", "scale=min("+strconv.Itoa(r.maxEdge)+"\\,iw):-2",
		"-q:v", strconv.Itoa(r.quality),
		"-f", "mjpeg", "-")
	cmd.Stdin = bytes.NewReader(b)
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil || out.Len() == 0 {
		return b
	}
	return out.Bytes()
}

// Lookup 只查缓存，不触发渲染。
//
// 首屏走这条路径：命中就直接给高清图；未命中时调用方先用内嵌预览图顶上，
// 再决定要不要排队渲染——不能让用户为了"看一眼"等十秒。
func (r *RawRenderer) Lookup(key string) (Entry, bool) {
	path := filepath.Join(r.dir, r.fileName(key))
	st, err := os.Stat(path)
	if err != nil || st.Size() == 0 {
		return Entry{}, false
	}
	return Entry{Path: path, Size: st.Size(), FromCache: true}, true
}

// Cached 取缓存，未命中则渲染。
//
// key 应由调用方用"版本内容"构造（节点 ID + 大小 + 更新时间），
// 用文件名会让用户看到上一版内容。
func (r *RawRenderer) Cached(ctx context.Context, key string, open func() (io.ReadCloser, error)) (Entry, error) {
	path := filepath.Join(r.dir, r.fileName(key))
	if st, err := os.Stat(path); err == nil && st.Size() > 0 {
		return Entry{Path: path, Size: st.Size(), FromCache: true}, nil
	}

	release, err := r.sf.acquire(ctx, path)
	if err != nil {
		return Entry{}, err
	}
	defer release()

	// 排队结束后再查一次：可能刚被前一个请求渲染好
	if st, err := os.Stat(path); err == nil && st.Size() > 0 {
		return Entry{Path: path, Size: st.Size(), FromCache: true}, nil
	}

	src, err := open()
	if err != nil {
		return Entry{}, err
	}
	defer func() { _ = src.Close() }()

	tmp, err := os.CreateTemp(r.dir, ".tmp-*")
	if err != nil {
		return Entry{}, err
	}
	tmpPath := tmp.Name()
	_ = tmp.Close()
	defer func() { _ = os.Remove(tmpPath) }()

	if err := r.renderTo(ctx, src, tmpPath); err != nil {
		return Entry{}, err
	}
	// 先落临时文件再改名：转换中断不会留下半个文件被当成缓存命中
	if err := os.Rename(tmpPath, path); err != nil {
		return Entry{}, err
	}
	st, err := os.Stat(path)
	if err != nil {
		return Entry{}, err
	}
	return Entry{Path: path, Size: st.Size()}, nil
}

// RenderTo 同步渲染到指定路径（异步预热用）。
func (r *RawRenderer) RenderTo(ctx context.Context, src io.Reader, dst string) error {
	return r.renderTo(ctx, src, dst)
}

// Acquire 占一个渲染名额，返回释放函数。拿不到名额立即返回 ErrRawBusy（不排队），
// 因为调用方有"用内嵌图先顶上"这个降级选项，没必要让请求原地等待。
func (r *RawRenderer) Acquire() (func(), error) {
	select {
	case r.sem <- struct{}{}:
		return func() { <-r.sem }, nil
	default:
		return nil, ErrRawBusy
	}
}

// renderTo 把 RAW 解码成 JPEG 写到 dst。
//
// 数据流：RAW 文件 → dcraw_emu（stdout PPM）→ ffmpeg（stdin）→ dst。
// 中间不落 TIFF：TIFF 单张 146MB，且 ffmpeg 的 tiff 不是可用的 demuxer（实测报
// "Unknown input format: tiff"），PPM 才是能流式喂进去的格式。
func (r *RawRenderer) renderTo(ctx context.Context, src io.Reader, dst string) error {
	ctx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()

	// dcraw_emu 只接受文件路径，先把原始 RAW 落到临时文件（20~60MB）
	in, err := os.CreateTemp("", "rawsrc-*")
	if err != nil {
		return err
	}
	inPath := in.Name()
	defer func() { _ = os.Remove(inPath) }()
	if _, err := io.Copy(in, src); err != nil {
		_ = in.Close()
		return fmt.Errorf("暂存原始文件失败: %w", err)
	}
	if err := in.Close(); err != nil {
		return err
	}

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer func() { _ = out.Close() }()

	dec := exec.CommandContext(ctx, r.dcraw, "-w", "-o", "1", "-q", "3", "-Z", "-", inPath)
	enc := exec.CommandContext(ctx, r.ffmpeg, "-y", "-loglevel", "error",
		"-f", "image2pipe", "-c:v", "ppm", "-i", "-",
		"-vf", "scale=min("+strconv.Itoa(r.maxEdge)+"\\,iw):-2",
		"-q:v", strconv.Itoa(r.quality),
		"-f", "mjpeg", "-")

	pipeR, pipeW := io.Pipe()
	dec.Stdout = pipeW
	enc.Stdin = pipeR
	enc.Stdout = out
	var decErr, encErr bytes.Buffer
	dec.Stderr = &decErr
	enc.Stderr = &encErr

	if err := enc.Start(); err != nil {
		_ = pipeR.Close()
		_ = pipeW.Close()
		return fmt.Errorf("启动 ffmpeg 失败: %w", err)
	}
	if err := dec.Start(); err != nil {
		_ = enc.Process.Kill()
		_ = pipeR.Close()
		_ = pipeW.Close()
		_ = enc.Wait()
		return fmt.Errorf("启动 dcraw_emu 失败: %w", err)
	}

	// dec 结束后必须关闭写端，ffmpeg 才会读到 EOF；否则两边互等
	waitDec := make(chan error, 1)
	go func() {
		e := dec.Wait()
		_ = pipeW.CloseWithError(e)
		waitDec <- e
	}()
	e1 := <-waitDec
	e2 := enc.Wait()
	_ = pipeR.Close()

	if ctx.Err() != nil {
		return fmt.Errorf("RAW 渲染超时（%s）", r.timeout)
	}
	if e1 != nil {
		return fmt.Errorf("RAW 解码失败: %w（%s）", e1, truncate(decErr.String(), 200))
	}
	if e2 != nil {
		return fmt.Errorf("图像编码失败: %w（%s）", e2, truncate(encErr.String(), 200))
	}

	// 校验产物：宁可报失败，也不把半个/损坏的 JPEG 写进缓存
	if err := out.Close(); err != nil {
		return err
	}
	f, err := os.Open(dst)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	if _, err := jpeg.DecodeConfig(f); err != nil {
		return fmt.Errorf("渲染产物不是有效 JPEG: %w", err)
	}
	if st, serr := f.Stat(); serr != nil || st.Size() == 0 {
		return errors.New("渲染产物为空")
	}
	return nil
}

// ---------- 内嵌预览图（首屏用） ----------

// EmbeddedJPEG 从 RAW 字节里取出最大的可解析 JPEG 预览。
//
// 不用"找第一个 FFD9"这种暴力法：JPEG 的 APP 段里可能嵌着缩略图，
// 直接找 EOI 会把边界截在缩略图上，得到一个半截的文件。
// 这里按 JPEG 段结构走（跳过带长度的段），并对每个候选做 DecodeConfig 校验。
func EmbeddedJPEG(b []byte) ([]byte, bool) {
	bestW, bestH := 0, 0
	var best []byte
	for i := 0; i+3 < len(b); i++ {
		if !(b[i] == 0xFF && b[i+1] == 0xD8 && b[i+2] == 0xFF) {
			continue
		}
		end := jpegEnd(b, i)
		if end <= i {
			continue
		}
		cfg, err := jpeg.DecodeConfig(bytes.NewReader(b[i:end]))
		if err != nil {
			continue
		}
		if cfg.Width*cfg.Height > bestW*bestH {
			bestW, bestH = cfg.Width, cfg.Height
			best = b[i:end]
		}
	}
	return best, best != nil
}

// jpegEnd 按段结构找 JPEG 的结束位置（返回 EOF 之后的下标）。
func jpegEnd(b []byte, start int) int {
	i := start
	for i+3 < len(b) {
		if b[i] != 0xFF {
			i++
			continue
		}
		m := b[i+1]
		switch {
		case m == 0xD9: // EOI
			return i + 2
		case m == 0xDA: // SOS：之后是熵编码数据，找真正的 EOI
			// 段长度位置：FFDA len_hi len_lo
			size := int(b[i+2])<<8 | int(b[i+3])
			j := i + 2 + size
			for j+1 < len(b) {
				if b[j] == 0xFF && b[j+1] == 0xD9 {
					return j + 2
				}
				j++
			}
			return -1
		case m == 0x00 || (m >= 0xD0 && m <= 0xD8):
			// 填充字节 / RST / SOI（嵌套缩略图）：跳过
			i += 2
		default:
			if i+4 >= len(b) {
				return -1
			}
			size := int(b[i+2])<<8 | int(b[i+3])
			if size < 2 {
				return -1
			}
			i += 2 + size
		}
	}
	return -1
}

func (r *RawRenderer) fileName(key string) string {
	sum := sha256.Sum256([]byte(key + "|" + r.Name()))
	return hex.EncodeToString(sum[:16]) + ".jpg"
}
