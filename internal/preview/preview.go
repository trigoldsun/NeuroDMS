// Package preview 负责把 Office 文档转成可在线查看的 PDF。
//
// 三个设计决定：
//  1. 转换是"不可信输入解析"，必须跑在独立进程/容器里（此处用子进程），
//     不能和 API 进程共享权限；
//  2. 结果按 "内容版本 + 渲染器版本" 缓存：同一份文件被 200 人预览只转一次，
//     而换了字体/换了 LibreOffice 版本会自然失效（渲染器版本进 key）；
//  3. 并发同一份文件只转一次（single-flight）：否则一次群发通知会让 CPU 打满。
package preview

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// ErrUnsupported 表示该文件类型不需要/不支持转 PDF。
var ErrUnsupported = errors.New("该文件类型不支持转 PDF")

// Converter 把源文件转成 PDF 流。
type Converter interface {
	// Name 返回渲染器标识，会进入缓存 key（换渲染器即失效）
	Name() string
	Convert(ctx context.Context, src io.Reader, filename string) (io.ReadCloser, error)
}

// Entry 是缓存项。
type Entry struct {
	Path      string
	Size      int64
	FromCache bool
}

// Cache 是按版本缓存的 PDF 渲染器。
type Cache struct {
	dir       string
	conv      Converter
	sf        *singleflight
	renderVer string
}

// NewCache 创建缓存目录。
func NewCache(dir string, conv Converter) (*Cache, error) {
	if dir == "" {
		return nil, errors.New("预览缓存目录不能为空")
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, fmt.Errorf("创建预览缓存目录失败: %w", err)
	}
	return &Cache{dir: dir, conv: conv, sf: newSingleflight(), renderVer: conv.Name()}, nil
}

// Get 取某个版本的 PDF，必要时转换。
//
// cacheKey 应是"内容版本 ID"（不是文件名）：同名文件改了内容就是新 key，
// 用文件名会让用户看到旧内容——这是最容易被投诉的一类 bug。
func (c *Cache) Get(ctx context.Context, cacheKey, filename string, open func() (io.ReadCloser, error)) (Entry, error) {
	path := filepath.Join(c.dir, c.fileName(cacheKey))
	if st, err := os.Stat(path); err == nil && st.Size() > 0 {
		return Entry{Path: path, Size: st.Size(), FromCache: true}, nil
	}

	// 同一 key 的并发请求排队，只有第一个真正转换
	release, err := c.sf.acquire(ctx, path)
	if err != nil {
		return Entry{}, err
	}
	defer release()

	// 排队结束后再查一次：可能刚被前一个请求转好了
	if st, err := os.Stat(path); err == nil && st.Size() > 0 {
		return Entry{Path: path, Size: st.Size(), FromCache: true}, nil
	}

	src, err := open()
	if err != nil {
		return Entry{}, err
	}
	defer func() { _ = src.Close() }()

	pdf, err := c.conv.Convert(ctx, src, filename)
	if err != nil {
		return Entry{}, err
	}
	defer func() { _ = pdf.Close() }()

	// 先写临时文件再改名：避免"转换中断留下半个 PDF"被当成缓存命中
	tmp, err := os.CreateTemp(c.dir, ".tmp-*")
	if err != nil {
		return Entry{}, err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()

	size, err := io.Copy(tmp, pdf)
	if err != nil {
		_ = tmp.Close()
		return Entry{}, err
	}
	// Windows 上必须先 Close 才能 Rename
	if err := tmp.Close(); err != nil {
		return Entry{}, err
	}
	if size == 0 {
		return Entry{}, errors.New("转换结果是空文件")
	}
	if err := os.Rename(tmpName, path); err != nil {
		return Entry{}, err
	}
	return Entry{Path: path, Size: size, FromCache: false}, nil
}

// InvalidateVersion 清除某个版本的缓存（内容被替换时调用）。
func (c *Cache) InvalidateVersion(cacheKey string) {
	_ = os.Remove(filepath.Join(c.dir, c.fileName(cacheKey)))
}

func (c *Cache) fileName(cacheKey string) string {
	// 文件名里带上渲染器版本与 key 的摘要：避免超长文件名，也避免路径注入
	sum := sha256.Sum256([]byte(cacheKey + "|" + c.renderVer))
	return hex.EncodeToString(sum[:16]) + ".pdf"
}

// ---------------- single-flight ----------------
//
// 只做"同一 key 串行"，不负责共享结果：串行结束后由调用方再查一次文件，
// 若已被前一个请求写好就直接命中。这样比"共享返回值"简单，
// 也避免了"第一个请求的 reader 被第二个请求读走"这类生命周期问题。

type singleflight struct {
	mu    sync.Mutex
	locks map[string]chan struct{}
}

func newSingleflight() *singleflight {
	return &singleflight{locks: make(map[string]chan struct{})}
}

// acquire 抢占某个 key。返回的 release 必须被调用（幂等）。
// 非领导者会阻塞到领导者完成；ctx 取消时提前返回错误，避免客户端断开后永久占锁。
func (s *singleflight) acquire(ctx context.Context, key string) (func(), error) {
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
		// 前一个请求已完成：什么都不需要释放
		return func() {}, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// ---------------- LibreOffice 实现 ----------------

// LibreOffice 调用 soffice 做转换。
type LibreOffice struct {
	Binary  string
	Timeout time.Duration
	// ProfileDir 必须每进程独立：soffice 用同一个 profile 并发启动会互相踢掉
	ProfileDir string
	// version 是实测的 LibreOffice 版本（如 25.8.7.3），进缓存 key
	version string
}

// rendererRev 是「转换行为」的版本号，进缓存 key。
//
// 只要改了转换参数（哪怕 LibreOffice 版本没变），就必须改它——
// 否则升级前生成的缓存会被继续复用，用户看到的还是旧效果。
// r2：表格类改用 SinglePageSheets 导出（见 Convert）。
const rendererRev = "r2"

// Name 返回渲染器标识。版本号进缓存 key，升级 LibreOffice 后缓存自然失效。
//
// 版本号**实测**而不是写死：镜像里的 LibreOffice 可能是 25.8 也可能被替换成
// 26.x，写死会让缓存 key 说谎（升级后旧缓存不失效，或反之）。
// 探测失败时退回 "unknown"，仍能保证 key 稳定。
func (l *LibreOffice) Name() string { return "libreoffice-" + l.version + "-" + rendererRev }

// detectVersion 跑一次 `soffice --version` 取版本号。
// 输出形如 "LibreOffice 25.8.7.3 580(Build:3)"，取第二个字段。
func detectVersion(bin string) string {
	out, err := exec.Command(bin, "--version").Output()
	if err != nil {
		return "unknown"
	}
	fields := strings.Fields(string(out))
	for i, f := range fields {
		if strings.HasPrefix(strings.ToLower(f), "libreoffice") && i+1 < len(fields) {
			return fields[i+1]
		}
	}
	if len(fields) >= 2 {
		return fields[1]
	}
	return "unknown"
}

// NewLibreOffice 探测可执行文件。未安装时返回 nil（预览降级为"不支持"）。
func NewLibreOffice(profileDir string) *LibreOffice {
	bin, err := exec.LookPath("soffice")
	if err != nil {
		bin, err = exec.LookPath("libreoffice")
	}
	if err != nil {
		return nil
	}
	timeout := 90 * time.Second
	return &LibreOffice{Binary: bin, Timeout: timeout, ProfileDir: profileDir, version: detectVersion(bin)}
}

// Convert 用 soffice 转 PDF。
//
// 安全要点：
//   - 不继承调用方的环境变量（避免泄漏 JWT/DB 口令给子进程）；
//   - 工作目录是本次临时目录，转换完即删；
//   - 有超时：畸形文档可能让 soffice 长时间空转。
func (l *LibreOffice) Convert(ctx context.Context, src io.Reader, filename string) (io.ReadCloser, error) {
	work, err := os.MkdirTemp("", "dv-preview-*")
	if err != nil {
		return nil, err
	}
	cleanup := func() { _ = os.RemoveAll(work) }

	ext := filepath.Ext(filename)
	if ext == "" {
		ext = ".bin"
	}
	inPath := filepath.Join(work, "input"+ext)
	f, err := os.Create(inPath)
	if err != nil {
		cleanup()
		return nil, err
	}
	if _, err := io.Copy(f, src); err != nil {
		_ = f.Close()
		cleanup()
		return nil, err
	}
	if err := f.Close(); err != nil {
		cleanup()
		return nil, err
	}

	cctx, cancel := context.WithTimeout(ctx, l.Timeout)
	defer cancel()

	// 转换目标：表格类必须显式给过滤器参数，其余用默认 PDF 导出。
	//
	// 表格为什么特殊：Calc 默认按**纸张宽度切列**，一张宽表会被切成好几页，
	// 每页只剩左边几列，且默认不打印单元格网格线。结果就是"一页页零散文字"，
	// 完全看不出这是表格——这正是用户报的"Excel 预览像 Word 文档"。
	//
	// SinglePageSheets 把整张工作表输出到一页：页面按内容自动加宽（列一个不丢），
	// LibreOffice 同时会把单元格网格一起绘出。代价是超宽表在查看器里需要缩放/横向滚动，
	// 但"看得到全部数据"比"字号刚好但数据被裁掉"更重要。
	target := "pdf"
	if isSpreadsheetExt(ext) {
		target = `pdf:calc_pdf_Export:{"SinglePageSheets":{"type":"boolean","value":"true"}}`
	}

	args := []string{
		"--headless", "--norestore", "--nolockcheck", "--nodefault",
		"-env:UserInstallation=file://" + filepath.ToSlash(filepath.Join(work, "profile")),
		"--convert-to", target, "--outdir", work, inPath,
	}
	cmd := exec.CommandContext(cctx, l.Binary, args...)
	cmd.Dir = work
	cmd.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + work,
		"TMPDIR=" + work,
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		cleanup()
		if cctx.Err() != nil {
			return nil, fmt.Errorf("转换超时（%s）", l.Timeout)
		}
		return nil, fmt.Errorf("转换失败: %v: %s", err, truncate(string(out), 400))
	}

	pdfPath := filepath.Join(work, "input.pdf")
	pdf, err := os.Open(pdfPath)
	if err != nil {
		cleanup()
		return nil, errors.New("转换未产出 PDF")
	}
	// 用包装器把临时目录的清理挂到 Close 上
	return &cleanupReader{Reader: pdf, cleanup: cleanup}, nil
}

type cleanupReader struct {
	io.Reader
	cleanup func()
	once    sync.Once
}

// Close 关闭底层文件并清理临时目录。
func (c *cleanupReader) Close() error {
	if rc, ok := c.Reader.(io.Closer); ok {
		_ = rc.Close()
	}
	c.once.Do(c.cleanup)
	return nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// isSpreadsheetExt 判断是否走 Calc 的导出路径（决定是否附加 SinglePageSheets）。
func isSpreadsheetExt(ext string) bool {
	switch strings.ToLower(ext) {
	case ".xlsx", ".xlsm", ".xls", ".xltx", ".xlt", ".ods", ".fods", ".csv":
		return true
	}
	return false
}
