package tenant

import (
	"bytes"
	"encoding/binary"
	"image"
	"image/png"
	"testing"
)

// 这些用例钉住的是"读图头"的字节布局。
// 布局错一位不会 panic，只会让尺寸判定失效——而尺寸判定是防内存放大的唯一闸门，
// 静默失效比直接报错更危险。

func pngBytes(w, h uint32) []byte {
	b := make([]byte, 33)
	copy(b, []byte{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A})
	binary.BigEndian.PutUint32(b[8:12], 13) // IHDR 长度
	copy(b[12:16], []byte("IHDR"))
	binary.BigEndian.PutUint32(b[16:20], w)
	binary.BigEndian.PutUint32(b[20:24], h)
	b[24] = 8 // bit depth
	b[25] = 6 // color type RGBA
	return b
}

func jpegBytes(w, h uint16) []byte {
	// SOI + APP0（跳过）+ SOF0
	app0 := []byte{0xFF, 0xE0, 0x00, 0x10, 'J', 'F', 'I', 'F', 0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00}
	sof := make([]byte, 19)
	sof[0], sof[1] = 0xFF, 0xC0
	binary.BigEndian.PutUint16(sof[2:4], 17) // 段长
	sof[4] = 8                               // 精度
	binary.BigEndian.PutUint16(sof[5:7], h)
	binary.BigEndian.PutUint16(sof[7:9], w)
	sof[9] = 3 // 分量数
	out := []byte{0xFF, 0xD8}
	out = append(out, app0...)
	out = append(out, sof...)
	return append(out, make([]byte, 16)...)
}

func webpVP8XBytes(w, h int) []byte {
	b := make([]byte, 30)
	copy(b[0:4], []byte("RIFF"))
	binary.LittleEndian.PutUint32(b[4:8], 22)
	copy(b[8:12], []byte("WEBP"))
	copy(b[12:16], []byte("VP8X"))
	binary.LittleEndian.PutUint32(b[16:20], 10)
	// b[20] flags, b[21:24] reserved
	put3 := func(off int, v int) {
		v-- // 存的是实际值 - 1
		b[off] = byte(v)
		b[off+1] = byte(v >> 8)
		b[off+2] = byte(v >> 16)
	}
	put3(24, w)
	put3(27, h)
	return b
}

func webpVP8LBytes(w, h int) []byte {
	b := make([]byte, 25)
	copy(b[0:4], []byte("RIFF"))
	binary.LittleEndian.PutUint32(b[4:8], 17)
	copy(b[8:12], []byte("WEBP"))
	copy(b[12:16], []byte("VP8L"))
	binary.LittleEndian.PutUint32(b[16:20], 9)
	b[20] = 0x2F
	// 14 位宽 + 14 位高（各存 -1）
	bits := uint32(w-1) | uint32(h-1)<<14
	binary.LittleEndian.PutUint32(b[21:25], bits)
	return b
}

func TestImageProbeFormats(t *testing.T) {
	cases := []struct {
		name   string
		data   []byte
		format string
		w, h   int
		ok     bool
	}{
		{"png", pngBytes(128, 128), "png", 128, 128, true},
		{"png 非方形", pngBytes(200, 64), "png", 200, 64, true},
		{"jpeg", jpegBytes(96, 48), "jpeg", 96, 48, true},
		{"webp VP8X", webpVP8XBytes(256, 256), "webp", 256, 256, true},
		{"webp VP8L", webpVP8LBytes(64, 32), "webp", 64, 32, true},
		{"空", nil, "", 0, 0, false},
		{"gif 不支持", []byte("GIF89a\x10\x00\x10\x00"), "", 0, 0, false},
	}
	for _, c := range cases {
		f, w, h, ok := imageProbe(c.data)
		if ok != c.ok || f != c.format || (ok && (w != c.w || h != c.h)) {
			t.Fatalf("%s: got (%q,%d,%d,%v) want (%q,%d,%d,%v)",
				c.name, f, w, h, ok, c.format, c.w, c.h, c.ok)
		}
	}
}

// 真实编码的 PNG（不是伪造头）也必须读得对。
// 伪造头能过，说明的是"字节布局对"；真实编码能过，说明"不只对自家构造的数据有效"。
func TestImageProbeRealPNG(t *testing.T) {
	img := image.NewRGBA(image.Rect(0, 0, 37, 21))
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		t.Fatal(err)
	}
	f, w, h, ok := imageProbe(buf.Bytes())
	if !ok || f != "png" || w != 37 || h != 21 {
		t.Fatalf("真实 PNG 解析失败: (%q,%d,%d,%v)", f, w, h, ok)
	}
}

// 截断的头部不能 panic，也不能给出错误的宽高。
func TestImageProbeTruncated(t *testing.T) {
	for _, b := range [][]byte{
		{0xFF, 0xD8},                         // JPEG 只有 SOI
		{0x89, 'P', 'N', 'G'},                // PNG 半截
		[]byte("RIFF\x00\x00\x00\x00WEBP"),   // WebP 无 chunk
		{0xFF, 0xD8, 0xFF, 0xC0, 0x00, 0x01}, // JPEG 段长为 1（非法）
		append([]byte{0xFF, 0xD8}, bytes.Repeat([]byte{0xFF}, 40)...), // 全是填充
	} {
		if _, _, _, ok := imageProbe(b); ok {
			t.Fatalf("截断/非法输入不应判定为可解析: %v", b)
		}
	}
}
