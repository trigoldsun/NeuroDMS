package main

// 短信认证服务凭据自检（不发送短信）。
//
// 只调 CheckSmsVerifyCode：官方标注核验免费，且不需要真实号码就能验证
// "AccessKey 是否存在、Secret 是否正确、Action 是否可用"。
// 真发一条短信去试，既花钱也会打扰到号码主人。
//
// 用法：
//   set -a; . docker/.env; set +a
//   go run ./cmd/smscheck              # 只核验凭据，不发短信
//   go run ./cmd/smscheck -send 138... # 真发一条（会计费、会打扰机主）
//
// 常见返回：
//   InvalidAccessKeyId.NotFound → AccessKeyId 不存在（换过账号/已删除/抄错）
//   SignatureDoesNotMatch       → Secret 不对
//   Forbidden.RAM / isv.*       → 该 AccessKey 未被授权或产品未开通
//   err=<nil>                   → 凭证可用（ok=false 属正常：这个码本来就不存在）

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"docvault/internal/phone"
	"docvault/internal/sms"
)

func main() {
	p, err := sms.NewAliyun(
		os.Getenv("DOCVAULT_SMS_ACCESS_KEY_ID"),
		os.Getenv("DOCVAULT_SMS_ACCESS_KEY_SECRET"),
		os.Getenv("DOCVAULT_SMS_SIGN_NAME"),
		os.Getenv("DOCVAULT_SMS_TEMPLATE_CODE"),
		os.Getenv("DOCVAULT_SMS_SCHEME_NAME"),
	)
	if err != nil {
		fmt.Println("✗ 配置不完整:", err)
		os.Exit(2)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// -send 走真实下发：这是唯一能验证"签名与模板在该账号下可用"的方式。
	// 单列一个开关而不是默认行为，因为它真的会发短信、真的计费。
	sendTo := flag.String("send", "", "向该号码真实发送一条验证码（会计费）")
	verifyTo := flag.String("verify", "", "核验某个号码收到的验证码（配合 -code）")
	verifyCode := flag.String("code", "", "要核验的验证码")
	flag.Parse()

	// -verify 用真实号码 + 真实验证码走一次核验，证明"校验侧"也通。
	// 核验成功会消耗该验证码（一次性），所以只用于排障，不用于业务。
	if *verifyTo != "" {
		norm, perr := phone.Normalize(*verifyTo)
		if perr != nil || *verifyCode == "" {
			fmt.Println("✗ 需要 -verify <号码> -code <验证码>")
			os.Exit(2)
		}
		ok, err := p.Verify(ctx, norm, *verifyCode)
		if err != nil {
			fmt.Println("✗ 核验失败：", err)
			os.Exit(1)
		}
		if ok {
			fmt.Printf("✓ 核验通过（PASS）：%s 的验证码有效，发送与校验两侧都正常\n", phone.Mask(norm))
			return
		}
		fmt.Printf("✗ 核验未通过（非 PASS）：%s —— 验证码错误、已过期，或已被使用\n", phone.Mask(norm))
		os.Exit(1)
	}
	if *sendTo != "" {
		norm, perr := phone.Normalize(*sendTo)
		if perr != nil {
			fmt.Println("✗ 号码格式不正确（仅支持中国大陆 11 位）")
			os.Exit(2)
		}
		if err := p.Send(ctx, norm, ""); err != nil {
			fmt.Println("✗ 发送失败：", err)
			os.Exit(1)
		}
		fmt.Printf("✓ 已提交下发：%s（若 1 分钟内未收到，多为签名/模板未在该账号生效，见服务端日志）\n",
			phone.Mask(norm))
		return
	}

	ok, err := p.Verify(ctx, "+8613000000000", "000000")
	switch {
	case err == nil:
		fmt.Printf("✓ 凭据可用（核验返回 ok=%v，属预期：该号码没有有效验证码）\n", ok)
		fmt.Println("  下一步：在网页端「账户 → 手机号」用真实号码走一次发送")
	case strings.Contains(err.Error(), "InvalidAccessKeyId"):
		fmt.Println("✗ AccessKeyId 不存在：请确认这个 Key 属于已购买短信包的账号，且未被删除")
		fmt.Println(" ", err)
	case strings.Contains(err.Error(), "isv.ValidateFail"):
		// 核验接口在"该号码没有待核验的验证码"时会返回这个业务错误。
		// 它出现在鉴权之后，所以恰好证明：Key 有效、签名正确、Action 可用。
		fmt.Println("✓ 凭据可用（核验返回 isv.ValidateFail：该号码没有待核验的验证码，属预期）")
		fmt.Println("  下一步：用一个真实号码走一次发送（网页端「账户 → 手机号」）")
	case strings.Contains(err.Error(), "SignatureDoesNotMatch"):
		fmt.Println("✗ AccessKeySecret 不正确")
		fmt.Println(" ", err)
	default:
		fmt.Println("✗ 调用失败：", err)
		os.Exit(1)
	}
}
