// Package password 统一口令长度的唯一口径。
//
// 为什么单独建一个包：改密（auth）、成员管理（iam）、开通租户（tenant）、
// 平台账号（platformauth）四处各写了一个长度常量，其中三处是硬编码的 12。
// 需求把下限降到 8 时，如果只改一处，就会出现"管理员建号能过、用户自己改密过不去"
// 这种自相矛盾的状态——而这正是客户最常打客服电话的那类问题。
//
// 两个约定：
//  1. **按字符数，不按字节数**。`len("密码密码")` 是 12，但只有 4 个字符；
//     用字节数判会让中文口令以三分之一的门槛通过。utf8.RuneCountInString 才符合"位"的语义。
//  2. 只判长度，不判复杂度。复杂度策略（大小写/符号）一旦加进来，
//     就会与"口令管理器生成的随机串"和"中文长口令"打架，且没有实测收益。
//     真正有效的是长度 + 登录频控 + 泄露检测，这三样都在别处。
package password

import "unicode/utf8"

// MinLength 是口令长度下限（字符数）。
//
// 8 是 2026-11-14 的产品决定（此前为 12）：现场反馈是"实施交付时客户记不住，
// 大量写在便签上"，反而降低了实际安全性；配合登录失败锁定与二次输入确认，
// 8 位的整体风险可接受。
const MinLength = 8

// Runes 返回字符串的字符数（不是字节数）。
func Runes(s string) int { return utf8.RuneCountInString(s) }

// TooShort 判断口令是否短于下限。
func TooShort(s string) bool { return Runes(s) < MinLength }
