// Package phone 统一手机号的规范化与掩码。
//
// 为什么单开一个包：规范与掩码现在有两个消费者——auth（登录、绑定）
// 与 directory（从认证源同步）。两边各写一份的结果是，某天会出现
// "目录同步进来的号码登录时被判格式非法"，而这类问题只在真实域控环境暴露。
package phone

import (
	"errors"
	"strings"
)

// ErrInvalid 表示号码不是可接受的大陆手机号。
//
// 只支持中国大陆号码是有意的：短信认证服务本身只对国内号码下发，
// 放开国际号只会让用户走进一个必然失败的流程。
var ErrInvalid = errors.New("手机号格式不正确")

// Normalize 把各种写法收敛成 +86 的 E.164。
//
// 接受：13800138000 / +8613800138000 / 008613800138000 / 86 138 0013 8000。
func Normalize(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", ErrInvalid
	}
	repl := strings.NewReplacer(" ", "", "-", "", "(", "", ")", "", "　", "")
	s = repl.Replace(s)
	s = strings.TrimPrefix(s, "+86")
	s = strings.TrimPrefix(s, "0086")
	if len(s) == 13 && strings.HasPrefix(s, "86") {
		s = s[2:]
	}
	if len(s) != 11 || s[0] != '1' || s[1] < '3' || s[1] > '9' {
		return "", ErrInvalid
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return "", ErrInvalid
		}
	}
	return "+86" + s, nil
}

// Mask 只保留前 3 位与后 4 位；非 11 位一律打星。
//
// 空串返回空串（不是 "***"）：界面上"没登记"与"登记了但看不到"
// 是两件事，前者该显示"—"。
func Mask(e164 string) string {
	s := strings.TrimPrefix(strings.TrimSpace(e164), "+86")
	if len(s) != 11 {
		if s == "" {
			return ""
		}
		return "***"
	}
	return s[:3] + "****" + s[7:]
}
