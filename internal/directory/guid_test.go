package directory

import "testing"

// 真实 AD 的 objectGUID 是 16 字节二进制。这条用例固定"字节 → GUID 字符串"的规则，
// 免得以后有人改成简单 hex（那样就无法和 AD 管理工具里的值对照）。
func TestGUIDString(t *testing.T) {
	// 取自实测域控上 sunxin 账号的原始字节
	raw := []byte{0x4f, 0xa5, 0xba, 0xc9, 0x94, 0x3f, 0x42, 0xe2,
		0xba, 0x15, 0x7a, 0x86, 0x73, 0x35, 0xf6, 0x3d}
	got := guidString(raw)
	want := "c9baa54f-3f94-e242-ba15-7a867335f63d"
	if got != want {
		t.Fatalf("GUID 转换错误\n want %s\n got  %s", want, got)
	}
	if len(got) != 36 {
		t.Fatalf("GUID 字符串应为 36 字符，实际 %d", len(got))
	}

	// 长度异常时退化为 hex，不 panic
	if got := guidString([]byte{1, 2, 3}); got != "010203" {
		t.Fatalf("异常长度应退化为 hex，实际 %s", got)
	}
	// 空值不 panic
	if got := guidString(nil); got != "" {
		t.Fatalf("空值应返回空串，实际 %q", got)
	}
}
