package auth

import "testing"

func TestNormalizePhone(t *testing.T) {
	ok := map[string]string{
		"13800138000":      "+8613800138000",
		" 138 0013 8000 ":  "+8613800138000",
		"+8613800138000":   "+8613800138000",
		"008613800138000":  "+8613800138000",
		"86 138-0013-8000": "+8613800138000",
		"(138)0013-8000":   "+8613800138000",
	}
	for raw, want := range ok {
		got, err := NormalizePhone(raw)
		if err != nil || got != want {
			t.Errorf("NormalizePhone(%q) = %q,%v want %q", raw, got, err, want)
		}
	}
	bad := []string{"", "1380013800", "138001380001", "12800138000", "abcdefghijk", "+861380013800a"}
	for _, raw := range bad {
		if _, err := NormalizePhone(raw); err == nil {
			t.Errorf("NormalizePhone(%q) 应失败", raw)
		}
	}
}

func TestMaskPhone(t *testing.T) {
	if got := MaskPhone("+8613800138000"); got != "138****8000" {
		t.Fatalf("掩码错误: %s", got)
	}
	if got := MaskPhone(""); got != "" {
		t.Fatalf("空号码应返回空串，实际 %q", got)
	}
	// 脏数据不能把中间四位漏出来
	if got := MaskPhone("+86123"); got != "***" {
		t.Fatalf("非法长度应打满星，实际 %q", got)
	}
}
