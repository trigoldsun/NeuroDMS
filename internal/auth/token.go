package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// 令牌错误分类。调用方据此决定返回 401 还是触发重新登录流程。
var (
	ErrTokenMalformed = errors.New("令牌格式非法")
	ErrTokenSignature = errors.New("令牌签名不匹配")
	ErrTokenExpired   = errors.New("令牌已过期")
	ErrTokenType      = errors.New("令牌类型不符")
)

const (
	tokenTypeAccess = "access"
)

// Claims 是访问令牌载荷。
// 刻意保持精简：授权判定依赖数据库中的 ACE，而不是把权限塞进令牌——
// 令牌一旦签发就无法撤回，权限写进令牌会导致"改了权限但旧令牌仍然放行"。
type Claims struct {
	Subject   string // user id
	TenantID  string
	SessionID string
	Epoch     int
	IssuedAt  time.Time
	ExpiresAt time.Time
}

type header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

type payload struct {
	Sub string `json:"sub"`
	Tid string `json:"tid"`
	Sid string `json:"sid"`
	Ep  int    `json:"ep"`
	Typ string `json:"typ"`
	Iat int64  `json:"iat"`
	Exp int64  `json:"exp"`
}

// SignAccess 生成 HS256 访问令牌。
func SignAccess(secret []byte, c Claims) (string, error) {
	if len(secret) < 32 {
		return "", errors.New("签名密钥长度不足 32 字节")
	}
	h, err := json.Marshal(header{Alg: "HS256", Typ: "JWT"})
	if err != nil {
		return "", err
	}
	p, err := json.Marshal(payload{
		Sub: c.Subject, Tid: c.TenantID, Sid: c.SessionID, Ep: c.Epoch,
		Typ: tokenTypeAccess,
		Iat: c.IssuedAt.Unix(), Exp: c.ExpiresAt.Unix(),
	})
	if err != nil {
		return "", err
	}

	signingInput := enc(h) + "." + enc(p)
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(signingInput))
	return signingInput + "." + enc(mac.Sum(nil)), nil
}

// ParseAccess 校验并解析访问令牌。
func ParseAccess(secret []byte, token string) (Claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return Claims{}, ErrTokenMalformed
	}
	hb, err := dec(parts[0])
	if err != nil {
		return Claims{}, ErrTokenMalformed
	}
	var h header
	if err := json.Unmarshal(hb, &h); err != nil {
		return Claims{}, ErrTokenMalformed
	}
	// 只接受 HS256：拒绝 "none" 与算法混淆攻击
	if h.Alg != "HS256" {
		return Claims{}, ErrTokenSignature
	}

	sig, err := dec(parts[2])
	if err != nil {
		return Claims{}, ErrTokenMalformed
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(parts[0] + "." + parts[1]))
	if subtle.ConstantTimeCompare(sig, mac.Sum(nil)) != 1 {
		return Claims{}, ErrTokenSignature
	}

	pb, err := dec(parts[1])
	if err != nil {
		return Claims{}, ErrTokenMalformed
	}
	var p payload
	if err := json.Unmarshal(pb, &p); err != nil {
		return Claims{}, ErrTokenMalformed
	}
	if p.Typ != tokenTypeAccess {
		return Claims{}, ErrTokenType
	}

	exp := time.Unix(p.Exp, 0)
	if !exp.After(time.Now()) {
		return Claims{}, ErrTokenExpired
	}
	return Claims{
		Subject:   p.Sub,
		TenantID:  p.Tid,
		SessionID: p.Sid,
		Epoch:     p.Ep,
		IssuedAt:  time.Unix(p.Iat, 0),
		ExpiresAt: exp,
	}, nil
}

// NewRefreshToken 生成刷新令牌，返回明文与入库用的摘要。
// 明文只在响应中出现一次；数据库只存摘要，库被读走也无法直接冒用。
func NewRefreshToken() (token string, hash []byte, err error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", nil, err
	}
	token = enc(b)
	sum := sha256.Sum256([]byte(token))
	return token, sum[:], nil
}

// HashRefresh 计算刷新令牌摘要，用于查库比对。
func HashRefresh(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}

func enc(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func dec(s string) ([]byte, error) { return base64.RawURLEncoding.DecodeString(s) }
