package password

import "testing"

// 长度按"字符"算，不按字节。这一条如果不测，
// 中文口令会以三分之一的门槛通过（"密码密"3 个字 = 9 字节）。
func TestRunesCountsCharactersNotBytes(t *testing.T) {
	cases := []struct {
		pw    string
		runes int
		short bool
	}{
		{"", 0, true},
		{"1234567", 7, true},
		{"12345678", 8, false},
		{"123456789", 9, false},
		{"密码密", 3, true},       // 9 字节，但只有 3 个字
		{"密码密码密码密码", 8, false}, // 24 字节 / 8 字
		{"abc 1234", 8, false}, // 空格是字符，也是口令的一部分
		{"😀😀😀😀😀😀😀😀", 8, false}, // 4 字节一个，仍按字符算
	}
	for _, c := range cases {
		if got := Runes(c.pw); got != c.runes {
			t.Fatalf("Runes(%q) = %d，期望 %d", c.pw, got, c.runes)
		}
		if got := TooShort(c.pw); got != c.short {
			t.Fatalf("TooShort(%q) = %v，期望 %v", c.pw, got, c.short)
		}
	}
}

// 下限必须是 8：产品已确认（docs/48）。这里钉住，防止有人"顺手"改回 12。
func TestMinLengthIsEight(t *testing.T) {
	if MinLength != 8 {
		t.Fatalf("MinLength 应为 8，实际 %d", MinLength)
	}
}
