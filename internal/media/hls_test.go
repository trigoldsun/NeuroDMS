package media

import (
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func testService(t *testing.T) *Service {
	t.Helper()
	s := New(Config{Dir: t.TempDir(), Secret: "media-secret-0123456789abcdef", PublicURL: "http://docvault"})
	if s == nil {
		t.Skip("本机没有 ffmpeg/ffprobe，跳过转码测试")
	}
	return s
}

// ffmpeg 生成测试源片。
func makeVideo(t *testing.T, codec string, height int) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "src.mp4")
	args := []string{"-y",
		"-f", "lavfi", "-i", "testsrc=size=" + itoa(height*16/9) + "x" + itoa(height) + ":rate=25",
		"-f", "lavfi", "-i", "sine=frequency=440",
		"-t", "3", "-c:v", codec, "-pix_fmt", "yuv420p", "-c:a", "aac", "-shortest", path}
	out, err := exec.Command("ffmpeg", args...).CombinedOutput()
	if err != nil {
		t.Skipf("无法生成测试视频: %v: %s", err, truncate(string(out), 300))
	}
	return path
}

func itoa(v int) string { return strconv.Itoa(v) }

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[len(s)-n:]
}

func openFile(path string) func() (io.ReadCloser, error) {
	return func() (io.ReadCloser, error) { return os.Open(path) }
}

// 源片已是 H.264/AAC：应走 remux（不重编码），产出单变体。
func TestPrepareRemuxesBrowserFriendlySource(t *testing.T) {
	s := testService(t)
	src := makeVideo(t, "libx264", 720)

	start := time.Now()
	res, err := s.Prepare(context.Background(), "node-1:123:456", 0, openFile(src))
	if err != nil {
		t.Fatalf("转码失败: %v", err)
	}
	elapsed := time.Since(start)

	if !res.Remux {
		t.Fatalf("H.264/AAC 源片应走 remux，实际走转码")
	}
	if len(res.Variants) != 1 || res.Variants[0].Name != "v0" {
		t.Fatalf("remux 应产出单变体，实际 %+v", res.Variants)
	}
	if res.FromCache {
		t.Fatal("首次不应命中缓存")
	}
	assertHLSLayout(t, filepath.Dir(res.MasterPath), []string{"v0"})
	t.Logf("remux 耗时 %s", elapsed)
}

// 非浏览器友好编码：应真的转码，并按分辨率产出多个变体。
func TestPrepareTranscodesNonFriendlySource(t *testing.T) {
	s := testService(t)
	src := makeVideo(t, "mpeg4", 720)

	res, err := s.Prepare(context.Background(), "node-2:1:2", 0, openFile(src))
	if err != nil {
		t.Fatalf("转码失败: %v", err)
	}
	if res.Remux {
		t.Fatal("mpeg4 源片不应走 remux")
	}
	if len(res.Variants) < 2 {
		t.Fatalf("720p 源片应产出至少 2 个变体，实际 %d", len(res.Variants))
	}
	names := make([]string, 0, len(res.Variants))
	for _, v := range res.Variants {
		names = append(names, v.Name)
	}
	assertHLSLayout(t, filepath.Dir(res.MasterPath), names)
}

func TestPrepareIsIdempotent(t *testing.T) {
	s := testService(t)
	src := makeVideo(t, "libx264", 360)

	if _, err := s.Prepare(context.Background(), "k", 0, openFile(src)); err != nil {
		t.Fatal(err)
	}
	res2, err := s.Prepare(context.Background(), "k", 0, openFile(src))
	if err != nil {
		t.Fatal(err)
	}
	if !res2.FromCache {
		t.Fatal("同一 key 第二次应命中缓存")
	}
}

func assertHLSLayout(t *testing.T, root string, variants []string) {
	t.Helper()
	master, err := os.ReadFile(filepath.Join(root, "master.m3u8"))
	if err != nil {
		t.Fatalf("缺少 master.m3u8: %v", err)
	}
	if !strings.HasPrefix(string(master), "#EXTM3U") {
		t.Fatalf("master 不是合法播放列表: %q", string(master))
	}
	for _, v := range variants {
		idx := filepath.Join(root, v, "index.m3u8")
		raw, err := os.ReadFile(idx)
		if err != nil {
			t.Fatalf("缺少变体播放列表 %s: %v", v, err)
		}
		if !strings.Contains(string(raw), "#EXTINF") {
			t.Fatalf("变体播放列表缺少分片信息: %s", idx)
		}
		if _, err := os.Stat(filepath.Join(root, v, "init.mp4")); err != nil {
			t.Fatalf("缺少 fMP4 初始化段: %v", err)
		}
		segs, _ := filepath.Glob(filepath.Join(root, v, "seg_*.m4s"))
		if len(segs) == 0 {
			t.Fatalf("变体 %s 没有分片", v)
		}
		// 分片不能是 0 字节：0 字节分片是最典型的"看起来成功、实际播不了"
		for _, seg := range segs {
			st, err := os.Stat(seg)
			if err != nil || st.Size() == 0 {
				t.Fatalf("分片为空: %s", seg)
			}
		}
	}
}

func TestPlanVariantsNeverUpscales(t *testing.T) {
	if got := planVariants(480); len(got) != 1 || got[0].Height != 360 {
		t.Fatalf("480p 只应产出 360 变体，实际 %+v", got)
	}
	if got := planVariants(720); len(got) != 2 {
		t.Fatalf("720p 应产出 2 个变体，实际 %d", len(got))
	}
	if got := planVariants(2160); len(got) != 3 {
		t.Fatalf("4K 也只产出 3 个变体（不做 4K 分发），实际 %d", len(got))
	}
}

func TestPlaylistSignature(t *testing.T) {
	s := testService(t)
	u := s.SignPlaylist("node-1:1:2", "v0/index.m3u8", time.Minute)
	if !strings.Contains(u, "/v1/media/node-1:1:2/v0/index.m3u8") {
		t.Fatalf("签名地址形态不符: %s", u)
	}
	// 从 URL 里解出参数再验
	q := parseQuery(t, u)
	if !s.VerifyPlaylist("node-1:1:2", "v0/index.m3u8", q["e"], q["s"]) {
		t.Fatal("合法签名应通过")
	}
	if s.VerifyPlaylist("node-2:1:2", "v0/index.m3u8", q["e"], q["s"]) {
		t.Fatal("换 key 后签名必须失效")
	}
	// 同一 key 下的其它文件（分片、init 段、子播放列表）必须能用同一签名取到：
	// HLS 播放器不会为每个分片单独带签名，路径进签名会让播放彻底失效
	for _, rel := range []string{"master.m3u8", "v0/index.m3u8", "v0/init.mp4", "v0/seg_00000.m4s"} {
		if !s.VerifyPlaylist("node-1:1:2", rel, q["e"], q["s"]) {
			t.Fatalf("同一 key 下的 %s 应可通过校验", rel)
		}
	}
}

func parseQuery(t *testing.T, raw string) map[string]string {
	t.Helper()
	out := map[string]string{}
	i := strings.Index(raw, "?")
	if i < 0 {
		t.Fatalf("URL 缺少查询串: %s", raw)
	}
	for _, kv := range strings.Split(raw[i+1:], "&") {
		parts := strings.SplitN(kv, "=", 2)
		if len(parts) == 2 {
			out[parts[0]] = parts[1]
		}
	}
	return out
}

func TestSafePathBlocksTraversal(t *testing.T) {
	root := t.TempDir()
	// 穿越路径会被规范化回根目录内部：结果必须仍在 root 下（而不是真的跳出）
	full, ok := SafePath(root, "../../etc/passwd")
	if ok {
		absRoot, _ := filepath.Abs(root)
		abs, _ := filepath.Abs(full)
		if !strings.HasPrefix(abs, absRoot+string(os.PathSeparator)) {
			t.Fatalf("穿越后跳出了根目录: %s", abs)
		}
	}
	got, ok := SafePath(root, "v0/index.m3u8")
	if !ok || !strings.HasSuffix(got, filepath.Join("v0", "index.m3u8")) {
		t.Fatalf("正常相对路径应通过，实际 %q ok=%v", got, ok)
	}
}
