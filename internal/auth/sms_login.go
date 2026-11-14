package auth

// 短信验证码登录。
//
// 与邮件二次验证不同：验证码由阿里云"短信认证服务"生成与核验，
// 本地不签发、不存储、不比对明文码。这里负责的是**登录语义**：
// 这个号码属于哪个租户、账号是否可用、发得太频繁没有、失败几次要不要冷静一下。

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"docvault/internal/db"

	"github.com/jackc/pgx/v5"
)

// SMSRate 是短信入口的频控参数。
//
// 三层都要有：只限号码挡不住"换号刷"，只限 IP 挡不住"同一人换网络"，
// 只限租户挡不住"盯着一个人轰炸"。数值保守是刻意的——多发一条就是一条的钱。
type SMSRate struct {
	Interval   time.Duration // 同号最小间隔
	PerHour    int           // 同号每小时上限
	PerDay     int           // 同号每天上限
	IPPerHour  int           // 同 IP 每小时上限
	FailWindow time.Duration // 失败计数窗口
	FailMax    int           // 窗口内失败多少次后暂时拒绝
}

// DefaultSMSRate 是默认频控。
func DefaultSMSRate() SMSRate {
	return SMSRate{
		Interval: 60 * time.Second, PerHour: 5, PerDay: 10, IPPerHour: 10,
		FailWindow: 15 * time.Minute, FailMax: 5,
	}
}

// RateLimitError 带"还要等多久"，前端据此显示倒计时而不是干瞪眼。
type RateLimitError struct {
	RetryAfter int
	Reason     string
}

func (e *RateLimitError) Error() string { return e.Reason }

// SMSCodeResult 是发码成功后的可公开信息（掩码 + 重发间隔）。
type SMSCodeResult struct {
	SentTo     string
	RetryAfter int
	// TenantID 仅供审计归属，不对外暴露；未登记的号码为空。
	TenantID string
}

// SendLoginCode 发送登录验证码。
//
// 关键取舍：账号不存在时**也返回成功**（同样的文案与结构），只是不发短信。
// 否则这个接口就成了"输入手机号查询是否注册"的免费工具。
func (s *Service) SendLoginCode(ctx context.Context, account, ip string) (SMSCodeResult, error) {
	if s.sms == nil {
		return SMSCodeResult{}, ErrSMSNotConfigured
	}
	phone, isPhone := lookalikePhone(account)
	if !isPhone {
		return SMSCodeResult{}, ErrPhoneRequired
	}
	ref, err := s.ResolveAccount(ctx, account)
	if err != nil {
		if errors.Is(err, ErrInvalidCredentials) {
			// 未登记：不发送、不透露，返回与原样一致的"已发送"
			return SMSCodeResult{SentTo: MaskPhone(phone), RetryAfter: int(s.rate.Interval.Seconds())}, nil
		}
		return SMSCodeResult{}, err
	}
	if ref.Phone == "" || !ref.PhoneVerified {
		return SMSCodeResult{}, ErrPhoneNotRegistered
	}
	if ref.Status != "active" {
		return SMSCodeResult{}, ErrAccountDisabled
	}
	if ref.ExpiresAt != nil && ref.ExpiresAt.Before(s.now()) {
		return SMSCodeResult{}, ErrAccountDisabled
	}

	if err := s.checkSendRate(ctx, ref.TenantID, phone, ip); err != nil {
		_ = s.logSMS(ctx, ref.TenantID, phone, ip, "rate_limited")
		return SMSCodeResult{}, err
	}
	if err := s.sms.Send(ctx, phone); err != nil {
		_ = s.logSMS(ctx, ref.TenantID, phone, ip, "provider_error")
		return SMSCodeResult{}, mapSMSError(err)
	}
	_ = s.logSMS(ctx, ref.TenantID, phone, ip, "sent")
	return SMSCodeResult{
		SentTo: MaskPhone(phone), RetryAfter: int(s.rate.Interval.Seconds()), TenantID: ref.TenantID,
	}, nil
}

// LoginWithSMS 校验验证码并签发会话。
func (s *Service) LoginWithSMS(ctx context.Context, account, code, ip, ua string) (Tokens, error) {
	if s.sms == nil {
		return Tokens{}, ErrSMSNotConfigured
	}
	phone, isPhone := lookalikePhone(account)
	if !isPhone {
		return Tokens{}, ErrPhoneRequired
	}
	ref, err := s.ResolveAccount(ctx, account)
	if err != nil {
		return Tokens{}, err
	}
	if ref.Phone == "" || !ref.PhoneVerified {
		return Tokens{}, ErrPhoneNotRegistered
	}

	// 同一号码连续输错：短暂拒绝。注意只按号码/ IP 记，不写 app_user.failed_attempts——
	// 否则知道手机号就能把别人的账号锁死（docs/28 的同类问题换个入口重演）。
	if n, _ := s.countSMS(ctx, ref.TenantID, phone, ip, "verify_failed", s.rate.FailWindow); n >= s.rate.FailMax {
		return Tokens{}, &RateLimitError{RetryAfter: int(s.rate.FailWindow.Seconds()),
			Reason: "验证码错误次数过多，请稍后再试"}
	}

	ok, err := s.sms.Check(ctx, phone, strings.TrimSpace(code))
	if err != nil {
		return Tokens{}, mapSMSError(err)
	}
	if !ok {
		_ = s.logSMS(ctx, ref.TenantID, phone, ip, "verify_failed")
		return Tokens{}, ErrCodeInvalid
	}
	_ = s.logSMS(ctx, ref.TenantID, phone, ip, "verify_ok")

	// 验证码校验通过后再读一次账号：发码到输码之间可能被停用、到期或改密。
	// 少了这一步，就会出现"账号已停用，但 5 分钟内发的码还能登进去"。
	var (
		epoch   int
		status  string
		expires *time.Time
		mfa     bool
	)
	err = db.WithTenant(ctx, s.pool, ref.TenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
			SELECT session_epoch, status, expires_at, mfa_required
			  FROM app_user WHERE id = $1 AND deleted_at IS NULL`, ref.UserID).
			Scan(&epoch, &status, &expires, &mfa)
	})
	if err != nil {
		return Tokens{}, ErrAccountDisabled
	}
	if status != "active" || (expires != nil && expires.Before(s.now())) {
		return Tokens{}, ErrAccountDisabled
	}
	if mfa {
		// 短信是"持有因子"。允许它单独登录，等于把双因子降成单因子。
		return Tokens{}, fmt.Errorf("%w: 该账号要求口令登录并完成二次验证", ErrMFARequired)
	}

	return s.createSession(ctx, ref.TenantID, ref.UserID, epoch, ip, ua)
}

// checkSendRate 检查发送频率（号码 + IP）。
func (s *Service) checkSendRate(ctx context.Context, tenantID, phone, ip string) error {
	var last *time.Time
	if err := s.pool.QueryRow(ctx, `
		SELECT max(created_at) FROM sms_send_log
		 WHERE tenant_id = $1 AND phone_hash = $2 AND result = 'sent'`,
		tenantID, s.phoneHash(phone)).Scan(&last); err != nil {
		return err
	}
	if last != nil {
		if wait := s.rate.Interval - s.now().Sub(*last); wait > 0 {
			return &RateLimitError{RetryAfter: int(wait.Seconds()) + 1, Reason: "发送过于频繁，请稍后再试"}
		}
	}
	if n, err := s.countSMS(ctx, tenantID, phone, "", "sent", time.Hour); err != nil {
		return err
	} else if n >= s.rate.PerHour {
		return &RateLimitError{RetryAfter: 600, Reason: "该号码一小时内发送次数过多"}
	}
	if n, err := s.countSMS(ctx, tenantID, phone, "", "sent", 24*time.Hour); err != nil {
		return err
	} else if n >= s.rate.PerDay {
		return &RateLimitError{RetryAfter: 3600, Reason: "该号码今日发送次数已用完"}
	}
	if ip != "" {
		if n, err := s.countSMSByIP(ctx, tenantID, ip, time.Hour); err != nil {
			return err
		} else if n >= s.rate.IPPerHour {
			return &RateLimitError{RetryAfter: 600, Reason: "当前网络发送次数过多"}
		}
	}
	return nil
}

func (s *Service) countSMS(ctx context.Context, tenantID, phone, ip, result string, window time.Duration) (int, error) {
	// 空串表示"不限该维度"：用 ($4 = '' OR ip = $4) 而不是动态拼 SQL，
	// 少一个拼接点就少一类占位符错位（这类错只在特定组合下才炸）。
	var n int
	err := s.pool.QueryRow(ctx, `
		SELECT count(*) FROM sms_send_log
		 WHERE tenant_id = $1 AND phone_hash = $2
		   AND created_at > now() - $3::interval
		   AND ($4 = '' OR ip = $4)
		   AND ($5 = '' OR result = $5)`,
		tenantID, s.phoneHash(phone), window.String(), ip, result).Scan(&n)
	return n, err
}

// countSMSByIP 统计某 IP 的发码次数（跨号码）：换号刷是常见绕过手段。
func (s *Service) countSMSByIP(ctx context.Context, tenantID, ip string, window time.Duration) (int, error) {
	var n int
	err := s.pool.QueryRow(ctx, `
		SELECT count(*) FROM sms_send_log
		 WHERE tenant_id = $1 AND ip = $2 AND result = 'sent'
		   AND created_at > now() - $3::interval`, tenantID, ip, window.String()).Scan(&n)
	return n, err
}

func (s *Service) logSMS(ctx context.Context, tenantID, phone, ip, result string) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO sms_send_log (tenant_id, phone_hash, ip, result)
		VALUES ($1, $2, nullif($3,''), $4)`,
		tenantID, s.phoneHash(phone), ip, result)
	return err
}
