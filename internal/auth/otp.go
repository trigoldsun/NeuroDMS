package auth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"

	"docvault/internal/db"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// 一次性验证码。用于外部用户登录二次验证与邮件验证。
//
// 三个约束缺一不可：
//  1. 有有效期（默认 10 分钟）——长期有效的验证码等于没有验证码；
//  2. 有尝试次数上限——6 位数字只有 100 万种，不限次数可被穷举；
//  3. 有签发频率上限——否则会被当成短信/邮件轰炸机，也可能被用来刷爆配额。
var (
	ErrCodeInvalid    = errors.New("验证码不正确或已失效")
	ErrTooManyCodes   = errors.New("验证码请求过于频繁，请稍后再试")
	ErrMFARequired    = errors.New("需要二次验证")
	ErrChallengeStale = errors.New("验证会话已失效，请重新登录")
)

// OTPConfig 是验证码策略。
type OTPConfig struct {
	Length       int           // 位数，默认 6
	TTL          time.Duration // 有效期，默认 10 分钟
	MaxAttempts  int           // 单码允许错误次数，默认 5
	MaxPerWindow int           // 窗口内最多签发数，默认 5
	Window       time.Duration // 频率窗口，默认 10 分钟
}

// DefaultOTPConfig 给出保守默认值。
func DefaultOTPConfig() OTPConfig {
	return OTPConfig{Length: 6, TTL: 10 * time.Minute, MaxAttempts: 5, MaxPerWindow: 5, Window: 10 * time.Minute}
}

// OTPStore 负责签发与校验验证码。
type OTPStore struct {
	pool   *pgxpool.Pool
	secret []byte
	cfg    OTPConfig
	now    func() time.Time
}

// NewOTPStore 构造验证码存储。
func NewOTPStore(pool *pgxpool.Pool, secret []byte, cfg OTPConfig) *OTPStore {
	if cfg.Length <= 0 {
		cfg.Length = 6
	}
	if cfg.TTL <= 0 {
		cfg.TTL = 10 * time.Minute
	}
	if cfg.MaxAttempts <= 0 {
		cfg.MaxAttempts = 5
	}
	if cfg.MaxPerWindow <= 0 {
		cfg.MaxPerWindow = 5
	}
	if cfg.Window <= 0 {
		cfg.Window = 10 * time.Minute
	}
	return &OTPStore{pool: pool, secret: secret, cfg: cfg, now: time.Now}
}

// Issue 生成一个验证码并入库（只存 HMAC），返回明文供发送。
func (s *OTPStore) Issue(ctx context.Context, tenantID, subject, purpose string) (string, time.Time, error) {
	if subject == "" {
		return "", time.Time{}, errors.New("验证主体为空")
	}

	var recent int
	err := db.WithTenant(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
			SELECT count(*) FROM otp_code
			 WHERE subject = $1 AND purpose = $2 AND created_at > now() - $3::interval`,
			subject, purpose, s.cfg.Window.String()).Scan(&recent)
	})
	if err != nil {
		return "", time.Time{}, err
	}
	if recent >= s.cfg.MaxPerWindow {
		return "", time.Time{}, ErrTooManyCodes
	}

	code, err := randomDigits(s.cfg.Length)
	if err != nil {
		return "", time.Time{}, err
	}
	expires := s.now().Add(s.cfg.TTL)
	hash := s.hash(tenantID, subject, purpose, code)

	err = db.WithTenant(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `
			INSERT INTO otp_code (id, tenant_id, subject, purpose, code_hash, expires_at)
			VALUES (gen_random_uuid(), $1, $2, $3, $4, $5)`,
			tenantID, subject, purpose, hash, expires)
		return e
	})
	if err != nil {
		return "", time.Time{}, err
	}
	return code, expires, nil
}

// Verify 校验验证码。成功即消费（一码一次）。
func (s *OTPStore) Verify(ctx context.Context, tenantID, subject, purpose, code string) error {
	if code == "" {
		return ErrCodeInvalid
	}
	want := s.hash(tenantID, subject, purpose, code)

	var lastID string
	var lastHash []byte
	var attempts int
	var expired bool

	err := db.WithTenant(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		// 取最新一条未消费的码：旧码不应能覆盖新码，
		// 否则"先请求 N 次再试最早的码"会让频率限制失去意义
		err := tx.QueryRow(ctx, `
			SELECT id::text, code_hash, attempts, expires_at <= now()
			  FROM otp_code
			 WHERE subject = $1 AND purpose = $2 AND consumed_at IS NULL
			 ORDER BY created_at DESC LIMIT 1
			 FOR UPDATE`, subject, purpose).
			Scan(&lastID, &lastHash, &attempts, &expired)
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrCodeInvalid
		}
		return err
	})
	if err != nil {
		return err
	}

	if expired || attempts >= s.cfg.MaxAttempts {
		return ErrCodeInvalid
	}

	if subtle.ConstantTimeCompare(lastHash, want) != 1 {
		// 错误计数必须落库：只在内存里计，重启或多实例就绕过了
		_ = db.WithTenant(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
			_, e := tx.Exec(ctx, `UPDATE otp_code SET attempts = attempts + 1 WHERE id = $1`, lastID)
			return e
		})
		return ErrCodeInvalid
	}

	// 原子消费：并发提交同一个正确码时只有一个能把 consumed_at 写上
	var ok bool
	err = db.WithTenant(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		ct, e := tx.Exec(ctx,
			`UPDATE otp_code SET consumed_at = now() WHERE id = $1 AND consumed_at IS NULL`, lastID)
		if e != nil {
			return e
		}
		ok = ct.RowsAffected() == 1
		return nil
	})
	if err != nil {
		return err
	}
	if !ok {
		return ErrCodeInvalid
	}
	return nil
}

func (s *OTPStore) hash(tenantID, subject, purpose, code string) []byte {
	mac := hmac.New(sha256.New, s.secret)
	fmt.Fprintf(mac, "%s|%s|%s|%s", tenantID, subject, purpose, code)
	return mac.Sum(nil)
}

func randomDigits(n int) (string, error) {
	max := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(n)), nil)
	v, err := rand.Int(rand.Reader, max)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%0*s", n, v.String()), nil
}

// ---------------- 二次验证挑战 ----------------

// MFAClaims 是"口令已通过、待二次验证"的短期凭据。
//
// 它不能换取任何业务数据，只能换一次验证码校验机会——
// 把它做成访问令牌的变体会让"未通过二次验证的人拿到可用令牌"，
// 那是最危险的实现捷径。
type MFAClaims struct {
	UserID    string
	TenantID  string
	Purpose   string // 验证码投递到的地址（邮箱或手机号）
	Epoch     int
	ExpiresAt time.Time
}

// SignChallenge 签发二次验证挑战。
func SignChallenge(secret []byte, c MFAClaims) (string, error) {
	if len(secret) < 32 {
		return "", errors.New("签名密钥长度不足 32 字节")
	}
	h, _ := json.Marshal(header{Alg: "HS256", Typ: "JWT"})
	p, _ := json.Marshal(payload{
		Sub: c.UserID, Tid: c.TenantID, Sid: c.Purpose, Ep: c.Epoch,
		Typ: "mfa", Iat: time.Now().Unix(), Exp: c.ExpiresAt.Unix(),
	})
	input := enc(h) + "." + enc(p)
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(input))
	return input + "." + enc(mac.Sum(nil)), nil
}

// ParseChallenge 校验并解析挑战。
func ParseChallenge(secret []byte, token string) (MFAClaims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return MFAClaims{}, ErrChallengeStale
	}
	hb, err := dec(parts[0])
	if err != nil {
		return MFAClaims{}, ErrChallengeStale
	}
	var h header
	if err := json.Unmarshal(hb, &h); err != nil || h.Alg != "HS256" {
		return MFAClaims{}, ErrChallengeStale
	}
	sig, err := dec(parts[2])
	if err != nil {
		return MFAClaims{}, ErrChallengeStale
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(parts[0] + "." + parts[1]))
	if subtle.ConstantTimeCompare(sig, mac.Sum(nil)) != 1 {
		return MFAClaims{}, ErrChallengeStale
	}
	pb, err := dec(parts[1])
	if err != nil {
		return MFAClaims{}, ErrChallengeStale
	}
	var p payload
	if err := json.Unmarshal(pb, &p); err != nil || p.Typ != "mfa" {
		return MFAClaims{}, ErrChallengeStale
	}
	if !time.Unix(p.Exp, 0).After(time.Now()) {
		return MFAClaims{}, ErrChallengeStale
	}
	return MFAClaims{
		UserID: p.Sub, TenantID: p.Tid, Purpose: p.Sid, Epoch: p.Ep,
		ExpiresAt: time.Unix(p.Exp, 0),
	}, nil
}
