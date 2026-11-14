package main

// 短信认证服务凭据自检（不发送短信）。
//
// 只调 CheckSmsVerifyCode：官方标注核验免费，且不需要真实号码就能验证
// "AccessKey 是否存在、Secret 是否正确、Action 是否可用"。
// 真发一条短信去试，既花钱也会打扰到号码主人。
//
// 用法：
//   set -a; . docker/.env; set +a
//   go run ./cmd/smscheck
//
// 常见返回：
//   InvalidAccessKeyId.NotFound → AccessKeyId 不存在（换过账号/已删除/抄错）
//   SignatureDoesNotMatch       → Secret 不对
//   Forbidden.RAM / isv.*       → 该 AccessKey 未被授权或产品未开通
//   err=<nil>                   → 凭证可用（ok=false 属正常：这个码本来就不存在）

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"docvault/internal/sms"
)

func main() {
	p, err := sms.NewAliyun(sms.AliyunConfig{
		AccessKeyID:     os.Getenv("DOCVAULT_SMS_ACCESS_KEY_ID"),
		AccessKeySecret: os.Getenv("DOCVAULT_SMS_ACCESS_KEY_SECRET"),
		SignName:        os.Getenv("DOCVAULT_SMS_SIGN_NAME"),
		TemplateCode:    os.Getenv("DOCVAULT_SMS_TEMPLATE_CODE"),
		SchemeName:      os.Getenv("DOCVAULT_SMS_SCHEME_NAME"),
	})
	if err != nil {
		fmt.Println("✗ 配置不完整:", err)
		os.Exit(2)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	ok, err := p.Check(ctx, "+8613000000000", "000000")
	switch {
	case err == nil:
		fmt.Printf("✓ 凭据可用（核验返回 ok=%v，属预期：该号码没有有效验证码）\n", ok)
		fmt.Println("  下一步：在网页端「账户 → 手机号」用真实号码走一次发送")
	case strings.Contains(err.Error(), "InvalidAccessKeyId"):
		fmt.Println("✗ AccessKeyId 不存在：请确认这个 Key 属于已购买短信包的账号，且未被删除")
		fmt.Println(" ", err)
	case strings.Contains(err.Error(), "SignatureDoesNotMatch"):
		fmt.Println("✗ AccessKeySecret 不正确")
		fmt.Println(" ", err)
	default:
		fmt.Println("✗ 调用失败：", err)
		os.Exit(1)
	}
}
