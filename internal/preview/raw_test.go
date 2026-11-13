package preview

import (
	"bytes"
	"context"
	"image"
	"image/color"
	"image/jpeg"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func encodeJPEG(t *testing.T, w, h int) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			img.Set(x, y, color.RGBA{R: uint8(x * 3), G: uint8(y * 5), B: 128, A: 255})
		}
	}
	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, img, &jpeg.Options{Quality: 80}); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// 取最大的那张：RAW 里通常有缩略图 + 全尺寸预览两张。
func TestEmbeddedJpegPicksLargest(t *testing.T) {
	small := encodeJPEG(t, 16, 16)
	big := encodeJPEG(t, 64, 48)

	var buf []byte
	buf = append(buf, bytes.Repeat([]byte{0xAA}, 100)...) // 模拟 RAW 头部
	buf = append(buf, small...)
	buf = append(buf, bytes.Repeat([]byte{0x00}, 500)...)
	buf = append(buf, big...)
	buf = append(buf, bytes.Repeat([]byte{0x55}, 50)...)

	got, ok := EmbeddedJPEG(buf)
	if !ok {
		t.Fatal("应找到内嵌 JPEG")
	}
	cfg, err := jpeg.DecodeConfig(bytes.NewReader(got))
	if err != nil {
		t.Fatalf("取出的字节不是完整 JPEG: %v", err)
	}
	if cfg.Width != 64 || cfg.Height != 48 {
		t.Fatalf("应取最大的 64x48，实际 %dx%d", cfg.Width, cfg.Height)
	}
}

// 关键回归：JPEG 的 APP1 段里可能嵌着缩略图（EXIF Thumbnail）。
// 如果按"找到第一个 FFD9 就结束"来截断，会把边界截在缩略图上，
// 得到一个半截文件——这正是真机上第一次失败的原因。
func TestEmbeddedJpegSurvivesNestedThumbnail(t *testing.T) {
	big := encodeJPEG(t, 64, 48)
	thumb := encodeJPEG(t, 8, 8)

	// 在 SOI 之后插入一个 APP1 段，段内容是 Exif 头 + 一张完整缩略图
	payload := append([]byte("Exif\x00\x00"), thumb...)
	app1 := []byte{0xFF, 0xE1, byte((len(payload) + 2) >> 8), byte((len(payload) + 2) & 0xFF)}

	crafted := make([]byte, 0, len(big)+len(app1)+len(payload))
	crafted = append(crafted, big[:2]...) // SOI
	crafted = append(crafted, app1...)
	crafted = append(crafted, payload...)
	crafted = append(crafted, big[2:]...)

	buf := append(bytes.Repeat([]byte{0x00}, 64), crafted...)
	buf = append(buf, bytes.Repeat([]byte{0x00}, 64)...)

	got, ok := EmbeddedJPEG(buf)
	if !ok {
		t.Fatal("应找到内嵌 JPEG")
	}
	// 必须完整覆盖 crafted（含 APP1 里的缩略图），不能截在缩略图的 EOI
	if len(got) != len(crafted) {
		t.Fatalf("取出的长度 %d，应为完整 %d（截断在了嵌套缩略图上）", len(got), len(crafted))
	}
	cfg, err := jpeg.DecodeConfig(bytes.NewReader(got))
	if err != nil {
		t.Fatalf("取出的字节不是完整 JPEG: %v", err)
	}
	if cfg.Width != 64 || cfg.Height != 48 {
		t.Fatalf("尺寸应为 64x48，实际 %dx%d", cfg.Width, cfg.Height)
	}
}

// 没有 JPEG 的二进制应明确返回 false，而不是返回垃圾字节。
func TestEmbeddedJpegNone(t *testing.T) {
	if _, ok := EmbeddedJPEG([]byte("not a raw file at all")); ok {
		t.Fatal("不应返回结果")
	}
	if _, ok := EmbeddedJPEG(nil); ok {
		t.Fatal("空输入不应返回结果")
	}
}

// 真实文件渲染（需要 dcraw_emu + ffmpeg 在 PATH，且提供样张）。
// 没有环境时跳过：CI 上不装 LibRaw，这个用例只在验证机上跑。
func TestRawRenderRealFile(t *testing.T) {
	sample := os.Getenv("RAW_SAMPLE")
	if sample == "" {
		t.Skip("未设置 RAW_SAMPLE，跳过真实 RAW 渲染")
	}
	if _, err := exec.LookPath("dcraw_emu"); err != nil {
		t.Skip("未找到 dcraw_emu")
	}
	f, err := os.Open(sample)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()

	dir := t.TempDir()
	r, err := NewRawRenderer(RawOptions{CacheDir: dir, MaxEdge: 2400, Quality: 3, MaxConcurrent: 1, Timeout: 120 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(dir, "out.jpg")
	start := time.Now()
	if err := r.RenderTo(context.Background(), f, dst); err != nil {
		t.Fatalf("渲染失败: %v", err)
	}
	elapsed := time.Since(start)

	out, err := os.Open(dst)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = out.Close() }()
	cfg, err := jpeg.DecodeConfig(out)
	if err != nil {
		t.Fatalf("产物不是有效 JPEG: %v", err)
	}
	if cfg.Width != 2400 && cfg.Height != 2400 {
		t.Fatalf("最长边应为 2400，实际 %dx%d", cfg.Width, cfg.Height)
	}
	st, _ := out.Stat()
	t.Logf("渲染完成：%dx%d，%d KB，耗时 %s", cfg.Width, cfg.Height, st.Size()/1024, elapsed.Round(time.Millisecond))
}
