// Package auth 实现口令、令牌与会话。
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Argon2id 参数：按 OWASP 建议取 m=64MiB、t=3、p=4。
// 参数随哈希串一起存储，后续调参不影响老口令校验。
const (
	argonMemory  = 64 * 1024 // KiB
	argonTime    = 3
	argonThreads = 4
	argonKeyLen  = 32
	argonSaltLen = 16
)

// ErrPasswordMismatch 表示口令不匹配。
var ErrPasswordMismatch = errors.New("口令不匹配")

// HashPassword 生成编码串：$argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>
func HashPassword(plain string) (string, error) {
	salt := make([]byte, argonSaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("生成盐失败: %w", err)
	}
	sum := argon2.IDKey([]byte(plain), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argonMemory, argonTime, argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(sum)), nil
}

// VerifyPassword 校验口令。参数从编码串解析，支持未来调参后的平滑升级。
func VerifyPassword(encoded, plain string) error {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return errors.New("哈希格式非法")
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return errors.New("哈希版本段非法")
	}
	var mem, iter uint32
	var par uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &mem, &iter, &par); err != nil {
		return errors.New("哈希参数段非法")
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return errors.New("盐解码失败")
	}
	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return errors.New("摘要解码失败")
	}

	got := argon2.IDKey([]byte(plain), salt, iter, mem, par, uint32(len(want)))
	// 常量时间比较，避免通过响应时间推测前缀匹配长度
	if subtle.ConstantTimeCompare(got, want) != 1 {
		return ErrPasswordMismatch
	}
	return nil
}

// NeedsRehash 判断已有哈希是否使用了低于当前基线的参数。
// 登录成功后可据此静默升级，不需要强制用户改密。
func NeedsRehash(encoded string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 {
		return true
	}
	var mem, iter uint32
	var par uint8
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &mem, &iter, &par); err != nil {
		return true
	}
	return mem < argonMemory || iter < argonTime || par < argonThreads
}

// dummyHash 用于"用户不存在"时也执行一次等价开销的校验，
// 避免通过响应时间差判断账号是否存在。
var dummyHash string

func init() {
	h, err := HashPassword("docvault-dummy-password-for-timing")
	if err != nil {
		panic("初始化占位哈希失败: " + err.Error())
	}
	dummyHash = h
}

// BurnTime 在账号不存在时调用，使失败路径耗时与正常校验接近。
func BurnTime(plain string) {
	_ = VerifyPassword(dummyHash, plain)
}
