package auth

import (
	"context"
	"errors"
	"strings"

	"docvault/internal/db"

	"github.com/jackc/pgx/v5"
)

// 管理端手机号验证。
//
// 产品口径：管理员录入号码**不强制当场验证**（手上未必有对方的手机，
// 强制会把"先建号、入职后补"卡住），但必须能在成员页事后补验。
// 因此这里有三个动作，且都只作用于"已经存在库里的那个号码"：
//
//	request —— 向已登记的号码发码
//	confirm —— 用收到的码把该号码置为已验证
//	clear   —— 清除号码与验证状态
//
// 换号走 iam.Update（会自动重置验证状态）。
// "验证 A 号却存了 B 号"这类错位，就是靠"验证接口不接受新号码"堵掉的。

// ErrTargetNotFound 表示要操作的目标账号不存在。
var ErrTargetNotFound = errors.New("成员不存在或已被删除")

// phoneOf 读该成员已登记的号码（规范化后的 E.164）。
func (s *Service) phoneOf(ctx context.Context, tenantID, userID string) (string, error) {
	var phone string
	err := db.WithTenant(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
			SELECT COALESCE(phone,'') FROM app_user
			 WHERE id = $1 AND deleted_at IS NULL`, userID).Scan(&phone)
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrTargetNotFound
	}
	if err != nil {
		return "", err
	}
	return phone, nil
}

// RequestPhoneVerifyFor 向该成员已登记的号码发一条验证码。
//
// 与自助换绑共用同一套频控：管理员手快连点、或脚本批量刷新，
// 消耗的是同一条计费通道，没有理由给它另一套更松的限制。
func (s *Service) RequestPhoneVerifyFor(ctx context.Context, tenantID, userID, ip string) (string, error) {
	if s.sms == nil {
		return "", ErrSMSNotConfigured
	}
	phone, err := s.phoneOf(ctx, tenantID, userID)
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(phone) == "" {
		return "", ErrPhoneRequired
	}
	if err := s.checkSendRate(ctx, tenantID, phone, ip); err != nil {
		return "", err
	}
	if err := s.sms.Send(ctx, phone); err != nil {
		// 失败也要落一条：否则频控会把"一直失败"当成没发过，
		// 管理员连点十次就打了十次上游接口。
		_ = s.logSMS(ctx, tenantID, phone, ip, "failed")
		return "", ErrSMSUnavailable
	}
	_ = s.logSMS(ctx, tenantID, phone, ip, "sent")
	return MaskPhone(phone), nil
}

// ConfirmPhoneVerifyFor 校验验证码，通过则把该号码置为已验证。
func (s *Service) ConfirmPhoneVerifyFor(ctx context.Context, tenantID, userID, code string) (string, error) {
	if s.sms == nil {
		return "", ErrSMSNotConfigured
	}
	phone, err := s.phoneOf(ctx, tenantID, userID)
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(phone) == "" {
		return "", ErrPhoneRequired
	}
	if strings.TrimSpace(code) == "" {
		return "", ErrCodeInvalid
	}
	ok, err := s.sms.Check(ctx, phone, code)
	if err != nil {
		return "", ErrSMSUnavailable
	}
	if !ok {
		return "", ErrCodeInvalid
	}
	// 只更新"号码仍是发码时那个"的行：中途被改成别的号时，
	// 这次 PASS 属于旧号，不能给新号盖章。
	if err := db.WithTenant(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `
			UPDATE app_user
			   SET phone_verified_at = now(),
			       phone_source = COALESCE(phone_source, 'manual'),
			       updated_at = now()
			 WHERE id = $1 AND phone = $2 AND deleted_at IS NULL`, userID, phone)
		return e
	}); err != nil {
		return "", err
	}
	return MaskPhone(phone), nil
}

// ClearPhone 清除手机号与验证状态。用于"号码录错了""人离职了"这类收尾。
func (s *Service) ClearPhone(ctx context.Context, tenantID, userID string) error {
	return db.WithTenant(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `
			UPDATE app_user
			   SET phone = NULL, phone_verified_at = NULL, phone_source = NULL, updated_at = now()
			 WHERE id = $1 AND deleted_at IS NULL`, userID)
		return e
	})
}
