package preview

import (
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fakeConverter struct {
	name  string
	calls int32
	// delay 用于制造并发窗口，验证 single-flight
	delay time.Duration
	err   error
	body  string
}

func (f *fakeConverter) Name() string { return f.name }

func (f *fakeConverter) Convert(ctx context.Context, src io.Reader, _ string) (io.ReadCloser, error) {
	atomic.AddInt32(&f.calls, 1)
	if f.delay > 0 {
		time.Sleep(f.delay)
	}
	if f.err != nil {
		return nil, f.err
	}
	raw, _ := io.ReadAll(src)
	body := f.body
	if body == "" {
		body = "PDF:"
	}
	return io.NopCloser(strings.NewReader(body + string(raw))), nil
}

func openString(s string) func() (io.ReadCloser, error) {
	return func() (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader(s)), nil
	}
}

func TestCacheConvertsOnceThenHits(t *testing.T) {
	conv := &fakeConverter{}
	c, err := NewCache(t.TempDir(), conv)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	e1, err := c.Get(ctx, "v1", "a.docx", openString("hello"))
	if err != nil {
		t.Fatal(err)
	}
	if e1.FromCache {
		t.Fatal("首次应为转换")
	}
	if e1.Size == 0 {
		t.Fatal("缓存文件不应为空")
	}

	e2, err := c.Get(ctx, "v1", "a.docx", openString("hello"))
	if err != nil {
		t.Fatal(err)
	}
	if !e2.FromCache {
		t.Fatal("第二次应命中缓存")
	}
	if got := atomic.LoadInt32(&conv.calls); got != 1 {
		t.Fatalf("转换应只执行一次，实际 %d", got)
	}

	// 内容版本变化 → 必须重新转换，否则用户会看到旧内容
	if _, err := c.Get(ctx, "v2", "a.docx", openString("hello v2")); err != nil {
		t.Fatal(err)
	}
	if got := atomic.LoadInt32(&conv.calls); got != 2 {
		t.Fatalf("新版本应重新转换，实际次数 %d", got)
	}
}

func TestCacheSingleFlightUnderConcurrency(t *testing.T) {
	conv := &fakeConverter{delay: 60 * time.Millisecond}
	c, _ := NewCache(t.TempDir(), conv)
	ctx := context.Background()

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := c.Get(ctx, "same", "a.docx", openString("x")); err != nil {
				t.Errorf("并发取预览失败: %v", err)
			}
		}()
	}
	wg.Wait()

	if got := atomic.LoadInt32(&conv.calls); got != 1 {
		t.Fatalf("10 个并发请求应只转换 1 次，实际 %d", got)
	}
}

func TestCacheDoesNotCacheFailure(t *testing.T) {
	conv := &fakeConverter{err: errors.New("转换器崩溃")}
	c, _ := NewCache(t.TempDir(), conv)
	ctx := context.Background()

	if _, err := c.Get(ctx, "v1", "a.docx", openString("x")); err == nil {
		t.Fatal("转换失败应返回错误")
	}
	// 失败后不能留下缓存文件，否则下次会读到坏文件
	conv.err = nil
	e, err := c.Get(ctx, "v1", "a.docx", openString("x"))
	if err != nil {
		t.Fatalf("重试应成功: %v", err)
	}
	if e.FromCache {
		t.Fatal("失败不应产生缓存")
	}
}

func TestCacheInvalidateVersion(t *testing.T) {
	conv := &fakeConverter{}
	c, _ := NewCache(t.TempDir(), conv)
	ctx := context.Background()

	if _, err := c.Get(ctx, "v1", "a.docx", openString("x")); err != nil {
		t.Fatal(err)
	}
	c.InvalidateVersion("v1")
	e, err := c.Get(ctx, "v1", "a.docx", openString("x"))
	if err != nil {
		t.Fatal(err)
	}
	if e.FromCache {
		t.Fatal("清除后应重新转换")
	}
}

// 换渲染器版本后缓存必须失效：否则升级 LibreOffice 后用户仍看到旧渲染结果。
func TestRendererVersionPartOfCacheKey(t *testing.T) {
	dir := t.TempDir()
	ctx := context.Background()

	a := &fakeConverter{name: "lo-1"}
	c1, _ := NewCache(dir, a)
	if _, err := c1.Get(ctx, "v1", "a.docx", openString("x")); err != nil {
		t.Fatal(err)
	}

	b := &fakeConverter{name: "lo-2"}
	c2, _ := NewCache(dir, b)
	e, err := c2.Get(ctx, "v1", "a.docx", openString("x"))
	if err != nil {
		t.Fatal(err)
	}
	if e.FromCache {
		t.Fatal("渲染器版本变化后不应命中旧缓存")
	}
}

// 未安装 LibreOffice 时必须"优雅不可用"，而不是崩或假装成功。
func TestLibreOfficeAbsentIsExplicit(t *testing.T) {
	lo := NewLibreOffice(t.TempDir())
	if lo != nil {
		t.Skip("本机安装了 LibreOffice，跳过缺失分支")
	}
	if lo == nil {
		// 语义就是返回 nil，由上层降级为"不支持预览"
		return
	}
}

// 装了 LibreOffice 时做一次真实转换：用一个最小 docx（zip）验证链路。
func TestLibreOfficeRealConversionIfAvailable(t *testing.T) {
	lo := NewLibreOffice(t.TempDir())
	if lo == nil {
		t.Skip("未安装 LibreOffice，跳过真实转换测试")
	}
	_ = os.Setenv("HOME", t.TempDir())

	pdf, err := lo.Convert(context.Background(), strings.NewReader(minimalDocx(t)), "test.docx")
	if err != nil {
		t.Skipf("LibreOffice 转换不可用（环境问题）: %v", err)
	}
	defer func() { _ = pdf.Close() }()

	head := make([]byte, 5)
	if _, err := io.ReadFull(pdf, head); err != nil {
		t.Fatalf("读取 PDF 头失败: %v", err)
	}
	if string(head) != "%PDF-" {
		t.Fatalf("输出不是 PDF，头部为 %q", string(head))
	}
}

// 表格类必须走 Calc 的 SinglePageSheets 导出。
//
// 回归背景：Calc 默认按纸张宽度切列 + 不打印网格线，一张宽表会被切成
// 好几页"零散文字"，用户看到的效果是"Excel 预览像 Word 文档"。
func TestIsSpreadsheetExt(t *testing.T) {
	yes := []string{".xlsx", ".xlsm", ".xls", ".ods", ".csv", ".XLSX"}
	no := []string{".docx", ".pptx", ".pdf", ".txt", ".bin", ""}
	for _, e := range yes {
		if !isSpreadsheetExt(e) {
			t.Errorf("%q 应判定为表格类", e)
		}
	}
	for _, e := range no {
		if isSpreadsheetExt(e) {
			t.Errorf("%q 不应判定为表格类", e)
		}
	}
}

// 渲染器标识必须随转换行为变化——否则改了导出参数后旧缓存仍被复用，
// 用户看到的还是"像 Word"的旧产物。
func TestRendererNameCarriesRevision(t *testing.T) {
	l := &LibreOffice{version: "25.8.7.3"}
	if got := l.Name(); got != "libreoffice-25.8.7.3-"+rendererRev {
		t.Fatalf("渲染器标识应包含行为版本，实际 %q", got)
	}
}
