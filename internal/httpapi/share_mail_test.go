package httpapi

import (
	"strings"
	"testing"

	"docvault/internal/share"
)

func contains(s, sub string) bool { return strings.Contains(s, sub) }

// shareOptionsForTest 构造带口令的选项（passwordHash 是散列串，正文里只判断"有没有口令"）。
func shareOptionsForTest(pwd string, uses int) share.Options {
	return share.Options{PasswordHash: pwd, MaxUses: &uses}
}

// 收件人校验的第一职责不是"邮箱对不对"，而是**挡住邮件头注入**：
// 一个带 \r\n 的字符串如果进了 Subject/To 头，就能给任意地址密送。
func TestNormalizeRecipients(t *testing.T) {
	got, err := normalizeRecipients([]string{" Alice@Example.com ", "bob@example.com", "alice@example.com"})
	if err != nil {
		t.Fatalf("合法收件人被拒: %v", err)
	}
	if len(got) != 2 || got[0] != "alice@example.com" || got[1] != "bob@example.com" {
		t.Fatalf("应去重并统一小写，实际 %v", got)
	}

	bad := []string{
		"a@b.com\r\nBcc: evil@example.com", // 头注入
		"a@b.com\nBcc: evil@example.com",   // 只用 LF 的头注入
		"no-at-sign",                       // 缺 @
		"a@nodot",                          // 域名无点
		"@example.com",                     // 缺本地部分
		"a b@example.com",                  // 含空格
	}
	for _, b := range bad {
		if _, err := normalizeRecipients([]string{b}); err == nil {
			t.Errorf("%q 应被拒绝", b)
		}
	}

	// 从列表里粘贴常带尾部换行：应当被裁掉而不是被拒
	if got, err := normalizeRecipients([]string{"carol@example.com\n"}); err != nil || len(got) != 1 {
		t.Fatalf("尾部换行应被裁剪，实际 %v / %v", got, err)
	}

	many := make([]string, 0, maxShareRecipients+1)
	for i := 0; i <= maxShareRecipients; i++ {
		many = append(many, string(rune('a'+i))+"@example.com")
	}
	if _, err := normalizeRecipients(many); err == nil {
		t.Fatal("超过上限应被拒绝（避免被当成群发工具）")
	}
}

// 邮件正文绝不能包含口令：邮件与口令必须是两条独立通道。
func TestShareMailBodyNeverContainsPassword(t *testing.T) {
	uses := 1
	subject, text, html := shareMailBody("张三", "合同.docx", "https://x/s/tok", shareOptionsForTest("S3cretPass!", uses))
	for _, s := range []string{subject, text, html} {
		if contains(s, "S3cretPass!") {
			t.Fatalf("邮件内容泄漏了口令: %s", s)
		}
	}
	if !contains(text, "另行告知") {
		t.Fatalf("应明确告知口令另行走通道，实际: %s", text)
	}
	if !contains(text, "仅可打开 1 次") {
		t.Fatalf("应写明访问次数，实际: %s", text)
	}
}
