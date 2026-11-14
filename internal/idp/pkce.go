package idp

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
)

// PKCE（RFC 7636）：公共客户端必须用 S256，否则授权码可被截获后重放。

// NewCodeVerifier 生成 43~128 字符的随机 verifier（这里固定 32 字节 -> 43 字符）。
func NewCodeVerifier() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// NewRandom 生成指定字节数的 URL-safe 随机串（用于 state / nonce）。
func NewRandom(n int) (string, error) {
	if n <= 0 {
		n = 32
	}
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func codeChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
