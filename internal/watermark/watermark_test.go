package watermark

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/pdfcpu/pdfcpu/pkg/api"
	"github.com/pdfcpu/pdfcpu/pkg/pdfcpu/model"
)

func mustNew(t *testing.T) *Service {
	t.Helper()
	svc, err := New(t.TempDir(), "")
	if err != nil {
		t.Fatalf("水印初始化失败: %v", err)
	}
	return svc
}

func readSample(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/sample.pdf")
	if err != nil {
		t.Fatalf("读取测试 PDF 失败: %v", err)
	}
	return b
}

// 水印必须真的进入内容流。只断言"输出是合法 PDF"是不够的——
// 那只能证明文件没坏，证明不了水印存在。
func TestApplyAddsVisibleWatermark(t *testing.T) {
	src := readSample(t)
	out, err := mustNew(t).Apply(context.Background(), src, "alice", "")
	if err != nil {
		t.Fatalf("叠加水印失败: %v", err)
	}
	if len(out) <= len(src) {
		t.Fatalf("输出应大于输入（新增内容），实际 %d ≤ %d", len(out), len(src))
	}
	conf := model.NewDefaultConfiguration()
	conf.ValidationMode = model.ValidationRelaxed
	if err := api.Validate(context.Background(), bytes.NewReader(out), conf, nil); err != nil {
		t.Fatalf("输出 PDF 不合法: %v", err)
	}

	var all bytes.Buffer
	if err := api.ExtractContent(context.Background(), bytes.NewReader(out), nil,
		func(r io.Reader, _ int) error {
			b, e := io.ReadAll(r)
			if e != nil {
				return e
			}
			all.Write(b)
			return nil
		}, conf); err != nil {
		t.Fatalf("提取内容失败: %v", err)
	}
	// 断言"水印对象真的被写进页面内容流"，而不是去搜原文：
	// pdfcpu 把水印画在独立的 Form XObject（/Fm0）里，ExtractContent 不展开该对象，
	// 且其中的文字按字体编码（非明文）。页面级能拿到的可靠证据是
	// `/Subtype /Watermark` 标记 + 引用该 XObject 的绘制指令。
	got := all.Bytes()
	if !bytes.Contains(got, []byte("/Watermark")) {
		t.Fatalf("页面内容流中没有水印标记: %q", got)
	}
	if !bytes.Contains(got, []byte("/Fm0 Do")) {
		t.Fatalf("页面内容流中没有水印 XObject 的绘制指令: %q", got)
	}
}

// 空文字必须报错而不是"叠一层看不见的东西"。
func TestApplyRejectsEmptyText(t *testing.T) {
	if _, err := mustNew(t).Apply(context.Background(), readSample(t), "   ", ""); !errors.Is(err, ErrEmptyText) {
		t.Fatalf("空文字应返回 ErrEmptyText，实际 %v", err)
	}
}

// 中文/表情必须被清洗成 ASCII，不能把不可渲染字符塞进 PDF。
func TestAsciiTextStripsNonASCII(t *testing.T) {
	got := asciiText("张三 alice@example.com 🚀")
	if got == "" {
		t.Fatal("清洗后不应为空（ASCII 部分要保留）")
	}
	for _, r := range got {
		if r >= 0x7f {
			t.Fatalf("仍含非 ASCII 字符: %q", got)
		}
	}
	if !bytes.Contains([]byte(got), []byte("alice@example.com")) {
		t.Fatalf("ASCII 部分应保留: %q", got)
	}
}

// 纯中文输入清洗后为空 → 调用方应据此回退到账号名，而不是产生空水印。
func TestAsciiTextAllCJK(t *testing.T) {
	if got := asciiText("张三"); got != "" {
		t.Fatalf("纯中文应清洗为空，实际 %q", got)
	}
}

// 非 PDF 输入必须失败且不 panic（预览链路会把用户文件喂进来）。
func TestApplyRejectsNonPDF(t *testing.T) {
	if _, err := mustNew(t).Apply(context.Background(), []byte("not a pdf at all"), "alice", ""); err == nil {
		t.Fatal("非 PDF 输入应失败")
	}
}

func TestFooterText(t *testing.T) {
	got := FooterText("2026-11-08 19:30:00Z", "10.1.2.3", "仅供授权查看")
	if got != "2026-11-08 19:30:00Z  ·  10.1.2.3  ·  仅供授权查看" {
		t.Fatalf("页脚文字拼装不符: %q", got)
	}
	if FooterText("", "", "") != "" {
		t.Fatal("全空应返回空串（由调用方决定是否降级）")
	}
}

// 中文字体路径：从包目录回到仓库根。
func cjkFontPath() string {
	return filepath.Join("..", "..", "assets", "fonts", "WVSans-Regular.ttf")
}

// 安装 glyf 中文字体后，中文水印必须能真正写入（而不是空白/乱码）。
func TestApplyWithCJKFont(t *testing.T) {
	if _, err := os.Stat(cjkFontPath()); err != nil {
		t.Skipf("中文字体缺失，跳过: %v", err)
	}
	svc, err := New(t.TempDir(), cjkFontPath())
	if err != nil {
		t.Fatalf("安装中文字体失败: %v", err)
	}
	if !svc.HasCJKFont() {
		t.Fatal("应报告已启用中文字体")
	}

	out, err := svc.Apply(context.Background(), readSample(t), "张三", "2026-11-08 12:00Z")
	if err != nil {
		t.Fatalf("中文水印失败: %v", err)
	}
	if len(out) == 0 {
		t.Fatal("输出为空")
	}
	conf := model.NewDefaultConfiguration()
	conf.ValidationMode = model.ValidationRelaxed
	if err := api.Validate(context.Background(), bytes.NewReader(out), conf, nil); err != nil {
		t.Fatalf("带中文水印的 PDF 不合法: %v", err)
	}
	// 中文不能把水印搞成空串（cleanText 不该剥掉汉字）
	if got := cleanText("张三 2026-11-08"); got != "张三 2026-11-08" {
		t.Fatalf("中文应被保留，实际 %q", got)
	}
}

// 字体缺失时不应致命：返回可用的服务（回退 Helvetica）+ 一个说明原因的错误。
func TestMissingCJKFontFallsBack(t *testing.T) {
	svc, err := New(t.TempDir(), filepath.Join(t.TempDir(), "nope.ttf"))
	if err == nil {
		t.Fatal("字体缺失应返回提示性错误")
	}
	if svc == nil {
		t.Fatal("字体缺失不应让服务不可用（应回退 ASCII）")
	}
	if svc.HasCJKFont() {
		t.Fatal("回退状态不应报告启用中文字体")
	}
	// 回退后仍能出 ASCII 水印（调用方传的是账号+邮箱+时间，含 ASCII）
	if _, aerr := svc.Apply(context.Background(), readSample(t), "zhangsan", "2026-11-08"); aerr != nil {
		t.Fatalf("回退后应能出 ASCII 水印: %v", aerr)
	}
	// 纯中文在无字体时必须明确失败，而不是悄悄出一个空水印
	if _, aerr := svc.Apply(context.Background(), readSample(t), "张三", ""); !errors.Is(aerr, ErrEmptyText) {
		t.Fatalf("无字体时纯中文应返回 ErrEmptyText，实际 %v", aerr)
	}
}
