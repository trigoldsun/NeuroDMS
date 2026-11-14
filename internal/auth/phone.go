package auth

// 手机号：规范化、掩码、跨租户定位账号、自助绑定。
//
// 手机号在本系统里是**登录凭据**，不是普通资料：
// 能收到某个号码的短信，就等于能登录绑定它的账号。因此这里的三条规则都不能松：
//   1. 只有经过一次验证码校验的号码才算"已验证"，才可用于登录；
//   2. 改号必须有两道凭证（当前口令 + 新号码验证码）；
//   3. 同一租户内号码唯一，避免"一个号对应两个账号"时登录到谁全看查询顺序。

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"docvault/internal/db"
	"docvault/internal/sms"

	"github.com/jackc/pgx/v5"
)

var (
	// ErrAmbiguousAccount 表示该账号（或手机号）存在于多个组织。
	// 不回具体是哪几个组织：那等于给攻击者一个"这个人在哪些公司"的查询接口。
	ErrAmbiguousAccount = errors.New("该账号存在于多个组织，请使用 账号@组织标识 的格式")
	// ErrPhoneNotRegistered 表示账号没有已验证手机号，不能用于小程序登录。
	ErrPhoneNotRegistered = errors.New("该账号未登记并验证手机号，请先在网页端绑定手机号")
	// ErrPhoneRequired 表示这个入口只接受手机号。
	ErrPhoneRequired = errors.New("请使用已登记的手机号登录")
	// ErrPhoneInvalid 表示号码格式不合法。
	ErrPhoneInvalid = errors.New("手机号格式不正确")
	// ErrPhoneTaken 表示号码已被同租户的其他账号占用。
	ErrPhoneTaken = errors.New("该手机号已被其他账号使用")
	// ErrSMSNotConfigured 表示服务端没有配置短信通道。
	ErrSMSNotConfigured = errors.New("短信认证服务未配置，请联系管理员")
	// ErrSMSUnavailable 表示短信通道调用失败。
	ErrSMSUnavailable = errors.New("短信服务暂不可用，请稍后重试或使用口令登录")
)

// SMSProvider 是认证服务需要的短信能力（由 internal/sms 实现）。
type SMSProvider interface {
	Send(ctx context.Context, phone string) error
	Check(ctx context.Context, phone, code string) (bool, error)
}

// SetSMS 注入短信通道。未注入时短信登录一律拒绝（fail-closed）。
func (s *Service) SetSMS(p SMSProvider) { s.sms = p }

// NormalizePhone 把各种写法收敛成 +86 的 E.164。
//
// 接受：13800138000 / +8613800138000 / 008613800138000 / 86 138 0013 8000。
// 只支持中国大陆手机号：短信认证服务目前也只支持国内号码，
// 这里放开国际号只会让用户走进一个必然失败的流程。
func NormalizePhone(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", ErrPhoneInvalid
	}
	repl := strings.NewReplacer(" ", "", "-", "", "(", "", ")", "", "　", "")
	s = repl.Replace(s)
	s = strings.TrimPrefix(s, "+86")
	s = strings.TrimPrefix(s, "0086")
	if len(s) == 13 && strings.HasPrefix(s, "86") {
		s = s[2:]
	}
	if len(s) != 11 || s[0] != '1' || s[1] < '3' || s[1] > '9' {
		return "", ErrPhoneInvalid
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return "", ErrPhoneInvalid
		}
	}
	return "+86" + s, nil
}

// MaskPhone 返回 138****8000。审计、列表、日志一律用它。
func MaskPhone(e164 string) string {
	s := strings.TrimPrefix(strings.TrimSpace(e164), "+86")
	if len(s) != 11 {
		if s == "" {
			return ""
		}
		return "***"
	}
	return s[:3] + "****" + s[7:]
}

var tenantSlugRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,62}$`)

// AccountRef 是登录前解析出的账号归属。
type AccountRef struct {
	UserID        string
	TenantID      string
	TenantSlug    string
	Username      string
	Phone         string
	PhoneVerified bool
	Status        string
	ExpiresAt     *time.Time
}

// lookalikePhone 判断输入看起来是不是手机号（用于区分"号码"与"用户名"）。
func lookalikePhone(raw string) (string, bool) {
	p, err := NormalizePhone(raw)
	return p, err == nil
}

// ResolveAccount 把用户输入的账号定位到唯一租户。
//
// 支持四种写法：username、username@tenant、phone、phone@tenant。
// 不带 @ 时会跨租户查；命中多个租户就返回 ErrAmbiguousAccount，
// 让用户补 @tenant，而不是由服务端"猜一个"——猜错会把口令校验导向别的组织，
// 用户只会看到"口令不对"。
func (s *Service) ResolveAccount(ctx context.Context, raw string) (AccountRef, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return AccountRef{}, ErrInvalidCredentials
	}

	// 手机号（可能带 @tenant）
	if phone, ok := lookalikePhone(raw); ok {
		return s.resolvePhone(ctx, "", phone, raw)
	}
	if at := strings.LastIndexByte(raw, '@'); at > 0 {
		name, slug := raw[:at], strings.ToLower(raw[at+1:])
		if tenantSlugRe.MatchString(slug) && s.tenantExists(ctx, slug) {
			// 号码@租户：前缀按号码处理
			if phone, ok := lookalikePhone(name); ok {
				return s.resolvePhone(ctx, slug, phone, raw)
			}
			return s.resolveUsername(ctx, slug, name)
		}
	}
	return s.resolveUsername(ctx, "", raw)
}

func (s *Service) tenantExists(ctx context.Context, slug string) bool {
	var one int
	err := s.pool.QueryRow(ctx, `
		SELECT 1 FROM tenant
		 WHERE slug = $1 AND deleted_at IS NULL
		   AND status IN ('active','trial','readonly')`, slug).Scan(&one)
	return err == nil
}

func (s *Service) resolveUsername(ctx context.Context, slug, username string) (AccountRef, error) {
	q := `
		SELECT u.id::text, t.id::text, t.slug, u.username, COALESCE(u.phone,''), u.phone_verified_at,
		       u.status, u.expires_at
		  FROM app_user u
		  JOIN tenant t ON t.id = u.tenant_id
		 WHERE u.deleted_at IS NULL AND t.deleted_at IS NULL
		   AND t.status IN ('active','trial','readonly')
		   AND lower(u.username) = lower($1)`
	args := []any{username}
	if slug != "" {
		q += ` AND t.slug = $2`
		args = append(args, slug)
	}
	// 同租户内可能同时有本地与域账号：排序只影响"取哪一行做展示"，
	// 真正的身份校验仍由 Login 的 mode 决定。
	q += ` ORDER BY CASE u.source WHEN 'local' THEN 0 ELSE 1 END, t.slug`
	return s.scanAccountRefs(ctx, q, args, slug == "", username)
}

func (s *Service) resolvePhone(ctx context.Context, slug, phone, raw string) (AccountRef, error) {
	q := `
		SELECT u.id::text, t.id::text, t.slug, u.username, COALESCE(u.phone,''), u.phone_verified_at,
		       u.status, u.expires_at
		  FROM app_user u
		  JOIN tenant t ON t.id = u.tenant_id
		 WHERE u.deleted_at IS NULL AND t.deleted_at IS NULL
		   AND t.status IN ('active','trial','readonly')
		   AND u.phone = $1`
	args := []any{phone}
	if slug != "" {
		q += ` AND t.slug = $2`
		args = append(args, slug)
	}
	q += ` ORDER BY t.slug`
	return s.scanAccountRefs(ctx, q, args, slug == "", raw)
}

func (s *Service) scanAccountRefs(ctx context.Context, q string, args []any, detectAmbiguous bool, raw string) (AccountRef, error) {
	rows, err := s.pool.Query(ctx, q, args...)
	if err != nil {
		return AccountRef{}, err
	}
	defer rows.Close()

	var (
		refs  []AccountRef
		slugs = map[string]bool{}
	)
	for rows.Next() {
		var (
			ref      AccountRef
			phone    string
			verified *time.Time
		)
		if err := rows.Scan(&ref.UserID, &ref.TenantID, &ref.TenantSlug, &ref.Username, &phone, &verified,
			&ref.Status, &ref.ExpiresAt); err != nil {
			return AccountRef{}, err
		}
		ref.Phone = phone
		ref.PhoneVerified = verified != nil
		refs = append(refs, ref)
		slugs[ref.TenantSlug] = true
	}
	if err := rows.Err(); err != nil {
		return AccountRef{}, err
	}
	if len(refs) == 0 {
		// 不区分"账号不存在"与"组织不存在"：两者都是凭据错误的同一种表现
		return AccountRef{}, ErrInvalidCredentials
	}
	if detectAmbiguous && len(slugs) > 1 {
		return AccountRef{}, fmt.Errorf("%w（%s）", ErrAmbiguousAccount, maskAccount(raw))
	}
	return refs[0], nil
}

// maskAccount 在错误提示里回显用户输入时做遮挡，避免把完整号码写进响应。
func maskAccount(raw string) string {
	if phone, ok := lookalikePhone(raw); ok {
		return MaskPhone(phone)
	}
	return raw
}

// phoneHash 用于频控与日志：不存明文号码。
func (s *Service) phoneHash(phone string) string {
	mac := hmac.New(sha256.New, s.secret)
	mac.Write([]byte(phone))
	return hex.EncodeToString(mac.Sum(nil))
}

// RequestPhoneChange 校验当前口令后，向新号码发一条验证码。
//
// 两道凭证的第一道在这里（口令），第二道在 ConfirmPhoneChange（验证码）。
// 少任何一道都会变成"拿到会话就能换号"或"别人邮箱/号码收到码就能改这个账号"。
func (s *Service) RequestPhoneChange(ctx context.Context, tenantID, userID, newPhone, password string) (string, error) {
	phone, err := NormalizePhone(newPhone)
	if err != nil {
		return "", err
	}
	if s.sms == nil {
		return "", ErrSMSNotConfigured
	}
	if strings.TrimSpace(password) == "" {
		// 空口令不能走"跳过校验"，必须明确拒绝
		return "", ErrInvalidCredentials
	}

	var (
		username string
		pwHash   *string
		source   string
	)
	err = db.WithTenant(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
			SELECT username, password_hash, source FROM app_user
			 WHERE id = $1 AND deleted_at IS NULL`, userID).Scan(&username, &pwHash, &source)
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", ErrSessionInvalid
		}
		return "", err
	}

	// 本地账号验本地口令；域账号去目录验（本地没有它的散列）。
	if source == "ldap" {
		if s.dir == nil {
			return "", ErrDirectoryNotConfigured
		}
		if _, disabled, derr := s.dir.Authenticate(ctx, tenantID, username, password); derr != nil {
			return "", translateDirectoryError(derr)
		} else if disabled {
			return "", ErrDomainDisabledInDir
		}
	} else {
		if pwHash == nil || *pwHash == "" {
			return "", ErrInvalidCredentials
		}
		if err := VerifyPassword(*pwHash, password); err != nil {
			return "", ErrInvalidCredentials
		}
	}

	// 号码占用检查放在发码之前：让用户立刻知道"这个号已经被别人用了"，
	// 而不是收码、输码、最后才报错。
	var exists int
	if err := db.WithTenant(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
			SELECT 1 FROM app_user
			 WHERE tenant_id = $1 AND phone = $2 AND id <> $3 AND deleted_at IS NULL`,
			tenantID, phone, userID).Scan(&exists)
	}); err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return "", err
	}
	if exists == 1 {
		return "", ErrPhoneTaken
	}

	if err := s.sms.Send(ctx, phone); err != nil {
		return "", mapSMSError(err)
	}
	return MaskPhone(phone), nil
}

// ConfirmPhoneChange 校验新号码的验证码并落库。
func (s *Service) ConfirmPhoneChange(ctx context.Context, tenantID, userID, newPhone, code string) (string, error) {
	phone, err := NormalizePhone(newPhone)
	if err != nil {
		return "", err
	}
	if s.sms == nil {
		return "", ErrSMSNotConfigured
	}
	ok, err := s.sms.Check(ctx, phone, strings.TrimSpace(code))
	if err != nil {
		return "", mapSMSError(err)
	}
	if !ok {
		return "", ErrCodeInvalid
	}
	var exists int
	if err := db.WithTenant(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		if e := tx.QueryRow(ctx, `
			SELECT 1 FROM app_user
			 WHERE tenant_id = $1 AND phone = $2 AND id <> $3 AND deleted_at IS NULL`,
			tenantID, phone, userID).Scan(&exists); e != nil && !errors.Is(e, pgx.ErrNoRows) {
			return e
		}
		if exists == 1 {
			return ErrPhoneTaken
		}
		_, e := tx.Exec(ctx, `
			UPDATE app_user
			   SET phone = $2, phone_verified_at = now(), updated_at = now()
			 WHERE id = $1 AND tenant_id = $3`, userID, phone, tenantID)
		return e
	}); err != nil {
		return "", err
	}
	return MaskPhone(phone), nil
}

// mapSMSError 把通道错误收敛成认证层的稳定错误，供 HTTP 映射。
func mapSMSError(err error) error {
	switch {
	case errors.Is(err, sms.ErrNotConfigured):
		return ErrSMSNotConfigured
	case errors.Is(err, sms.ErrUnavailable):
		return fmt.Errorf("%w: %s", ErrSMSUnavailable, err.Error())
	default:
		return err
	}
}
