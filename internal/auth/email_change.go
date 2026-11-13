package auth

// 联系方式换绑（AC-61）。
//
// 换绑邮箱是账号接管的经典路径：拿到会话的人改掉邮箱，再走"忘记密码"就把账号彻底拿走。
// 所以这里强制两道凭证：
//   1. **当前口令**（证明是本人，而不只是"持有某个已登录的浏览器"）；
//   2. **新邮箱的验证码**（证明对目标地址有控制权，防止把账号绑到攻击者邮箱）。
//
// 两道都不能省：
//   - 只验口令：会话被盗后换绑照样成功（口令可能已保存在浏览器里或已被键盘记录）；
//   - 只验证码：别人邮箱收到码不代表有权改这个账号。
//
// 未配置邮件通道时一律拒绝（fail-closed），而不是"跳过验证码直接生效"——
// 后者在漏配通道的环境里会静默退化成"只验口令"。

import (
	"context"
	"errors"
	"strings"

	"docvault/internal/db"

	"github.com/jackc/pgx/v5"
)

const purposeEmailChange = "email_change"

// ErrEmailTaken 表示目标邮箱已被其他账号占用。
var ErrEmailTaken = errors.New("该邮箱已被其他账号使用")

// ErrEmailInvalid 表示邮箱格式不合法。
var ErrEmailInvalid = errors.New("邮箱格式不正确")

// ErrChannelUnavailable 表示未配置验证码投递通道。
var ErrChannelUnavailable = errors.New("未配置邮箱验证码通道，无法完成换绑")

// validEmail 做保守校验：必须有本地部分、@、域名且域名含点，长度受限。
//
// 不追求 RFC 5322 完整语法（那玩意儿的正则没人能读懂也没必要）：
// 邮箱最终由邮件服务器裁决，这里只挡明显非法与超长输入。
func validEmail(s string) bool {
	if len(s) < 5 || len(s) > 254 {
		return false
	}
	at := strings.LastIndexByte(s, '@')
	if at <= 0 || at == len(s)-1 {
		return false
	}
	domain := s[at+1:]
	if !strings.Contains(domain, ".") || strings.HasPrefix(domain, ".") ||
		strings.HasSuffix(domain, ".") {
		return false
	}
	for _, r := range s {
		if r <= 0x20 || r == 0x7f || r == ',' || r == ';' || r == '<' || r == '>' {
			return false
		}
	}
	return true
}

// RequestEmailChange 校验当前口令后，把验证码发到**新**邮箱。
// 返回掩码后的目标地址与有效期秒数。
func (s *Service) RequestEmailChange(ctx context.Context, tenantID, userID, newEmail, password string) (string, int, error) {
	if s.otp == nil || s.sender == nil {
		return "", 0, ErrChannelUnavailable
	}
	newEmail = strings.ToLower(strings.TrimSpace(newEmail))
	if !validEmail(newEmail) {
		return "", 0, ErrEmailInvalid
	}
	if password == "" {
		// 空口令不能走"跳过校验"，必须明确拒绝（否则一次参数遗漏就成了免校验入口）
		return "", 0, ErrInvalidCredentials
	}

	var pwHash *string
	err := db.WithTenant(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
			SELECT password_hash FROM app_user WHERE id = $1 AND deleted_at IS NULL`, userID).
			Scan(&pwHash)
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", 0, ErrSessionInvalid
		}
		return "", 0, err
	}
	if pwHash == nil || *pwHash == "" {
		// 域账号没有本地口令：换绑必须走管理员/目录侧流程，不能在这个接口里绕开
		return "", 0, ErrInvalidCredentials
	}
	if err := VerifyPassword(*pwHash, password); err != nil {
		return "", 0, ErrInvalidCredentials
	}

	var taken int
	if err := db.WithTenant(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
			SELECT count(*) FROM app_user
			 WHERE lower(email) = $1 AND id <> $2 AND deleted_at IS NULL`,
			newEmail, userID).Scan(&taken)
	}); err != nil {
		return "", 0, err
	}
	if taken > 0 {
		return "", 0, ErrEmailTaken
	}

	// 验证码主体绑定"用户 + 新邮箱"：
	// 只绑用户的话，A 用户拿到任一邮箱的码就能改绑；只绑邮箱的话，码会跨账号通用。
	subject := userID + "|" + newEmail
	code, _, err := s.otp.Issue(ctx, tenantID, subject, purposeEmailChange)
	if err != nil {
		return "", 0, err
	}
	if err := s.sender.SendCode(ctx, tenantID, newEmail, purposeEmailChange, code); err != nil {
		// 发不出去就等于验证不成立，不能返回"已发送"
		return "", 0, err
	}
	return maskEmail(newEmail), 300, nil
}

// ConfirmEmailChange 校验新邮箱验证码并落库。
//
// 换绑成功后吊销该账号的全部会话：攻击者若已持有会话，换绑就是最后一步，
// 这时把所有人踢下线，是唯一能让他"刚拿到就失效"的手段。
func (s *Service) ConfirmEmailChange(ctx context.Context, tenantID, userID, newEmail, code string) error {
	if s.otp == nil {
		return ErrChannelUnavailable
	}
	newEmail = strings.ToLower(strings.TrimSpace(newEmail))
	if !validEmail(newEmail) {
		return ErrEmailInvalid
	}
	if code == "" {
		return ErrCodeInvalid
	}

	subject := userID + "|" + newEmail
	if err := s.otp.Verify(ctx, tenantID, subject, purposeEmailChange, code); err != nil {
		return err
	}

	err := db.WithTenant(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		// 再次检查唯一性：发码与确认之间可能被别人占用（TOCTOU）
		var taken int
		if e := tx.QueryRow(ctx, `
			SELECT count(*) FROM app_user
			 WHERE lower(email) = $1 AND id <> $2 AND deleted_at IS NULL`,
			newEmail, userID).Scan(&taken); e != nil {
			return e
		}
		if taken > 0 {
			return ErrEmailTaken
		}
		ct, e := tx.Exec(ctx, `
			UPDATE app_user
			   SET email = $2, session_epoch = session_epoch + 1, updated_at = now()
			 WHERE id = $1 AND deleted_at IS NULL`, userID, newEmail)
		if e != nil {
			return e
		}
		if ct.RowsAffected() == 0 {
			return ErrSessionInvalid
		}
		_, e = tx.Exec(ctx,
			`UPDATE session SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL`, userID)
		return e
	})
	if err != nil {
		return err
	}
	// 本实例立即收敛（其它实例 ≤ TTL）
	s.guard.InvalidateAll()
	return nil
}

// purposeShareVerify 是"分享链接的访客邮箱验证"用途。
//
// 与登录二次验证用不同的 purpose：验证码按 (subject, purpose) 隔离，
// 混用会让"登录用的码"能被拿去兑换分享，反之亦然。
const purposeShareVerify = "share_verify"

// shareSubject 把验证码主体绑定到"某个链接 + 某个邮箱"。
//
// 只绑邮箱：A 链接的码能兑换 B 链接；只绑链接：同一链接下任意邮箱的码通用。
// 两者都必须绑。
func shareSubject(shareID, email string) string {
	return "share:" + shareID + "|" + strings.ToLower(strings.TrimSpace(email))
}

// RequestShareCode 向访客邮箱发送分享验证码。
//
// 这里不做白名单判断：白名单属于分享策略，由调用方（share/handler）在**发码之前**判定。
// 把策略留在上层是有意的——认证服务不该知道"这个链接允许谁访问"。
func (s *Service) RequestShareCode(ctx context.Context, tenantID, shareID, email string) (string, int, error) {
	if s.otp == nil || s.sender == nil {
		return "", 0, ErrChannelUnavailable
	}
	email = strings.ToLower(strings.TrimSpace(email))
	if !validEmail(email) {
		return "", 0, ErrEmailInvalid
	}
	code, _, err := s.otp.Issue(ctx, tenantID, shareSubject(shareID, email), purposeShareVerify)
	if err != nil {
		return "", 0, err
	}
	if err := s.sender.SendCode(ctx, tenantID, email, purposeShareVerify, code); err != nil {
		return "", 0, err
	}
	// 有效期与 OTP 默认 TTL 一致（10 分钟）；具体判定由 OTPStore 内部完成，
	// 这里返回的只是给界面显示用的秒数，不参与校验。
	return maskEmail(email), 600, nil
}

// VerifyShareCode 校验分享验证码（错误次数与锁定由 OTPStore 负责）。
func (s *Service) VerifyShareCode(ctx context.Context, tenantID, shareID, email, code string) error {
	if s.otp == nil {
		return ErrChannelUnavailable
	}
	email = strings.ToLower(strings.TrimSpace(email))
	if !validEmail(email) {
		return ErrEmailInvalid
	}
	if code == "" {
		return ErrCodeInvalid
	}
	return s.otp.Verify(ctx, tenantID, shareSubject(shareID, email), purposeShareVerify, code)
}
