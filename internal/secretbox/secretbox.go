// Package secretbox 提供"落库前加密"的最小实现（AES-256-GCM）。
//
// 用途单一：租户自有域名的**证书私钥**。
//
// 为什么必须加密：私钥会随 pg_dump 进备份、随只读副本进分析库、随 DBA 的
// 一次 SELECT 出现在终端里。明文存储意味着"任何一个能读备份的人都能
// 冒充该租户的域名"——这比泄露一份文档严重得多。
//
// 密钥来自 DOCVAULT_SECRET_KEY（base64 的 32 字节）。未配置时 Encrypt 直接报错，
// 上层据此拒绝"上传证书"这个操作——宁可功能不可用，也不静默降级为明文。
package secretbox

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
)

// ErrNoKey 表示未配置密钥。
var ErrNoKey = errors.New("未配置加密密钥（DOCVAULT_SECRET_KEY），涉及私钥的功能不可用")

// ErrCorrupt 表示密文无法解开（密钥变了或数据被改过）。
var ErrCorrupt = errors.New("密文无法解密（密钥不匹配或数据损坏）")

// Box 是加解密器。零值不可用，必须用 New 构造。
type Box struct {
	aead cipher.AEAD
}

// New 用 base64 编码的 32 字节密钥构造。
func New(keyB64 string) (*Box, error) {
	if keyB64 == "" {
		return nil, ErrNoKey
	}
	raw, err := base64.StdEncoding.DecodeString(keyB64)
	if err != nil {
		return nil, fmt.Errorf("DOCVAULT_SECRET_KEY 不是合法 base64: %w", err)
	}
	if len(raw) != 32 {
		return nil, fmt.Errorf("DOCVAULT_SECRET_KEY 需为 32 字节（当前 %d）", len(raw))
	}
	block, err := aes.NewCipher(raw)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Box{aead: aead}, nil
}

// Available 报告是否可用（用于"能不能上传证书"的判断）。
func (b *Box) Available() bool { return b != nil && b.aead != nil }

// Encrypt 返回 nonce||ciphertext。附加数据（aad）绑定上下文，
// 例如租户 ID + 域名：把 A 租户的密文复制到 B 租户的行里会解不开。
func (b *Box) Encrypt(plain []byte, aad string) ([]byte, error) {
	if !b.Available() {
		return nil, ErrNoKey
	}
	nonce := make([]byte, b.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	out := b.aead.Seal(nonce, nonce, plain, []byte(aad))
	return out, nil
}

// Decrypt 是 Encrypt 的逆操作。
func (b *Box) Decrypt(sealed []byte, aad string) ([]byte, error) {
	if !b.Available() {
		return nil, ErrNoKey
	}
	ns := b.aead.NonceSize()
	if len(sealed) <= ns {
		return nil, ErrCorrupt
	}
	plain, err := b.aead.Open(nil, sealed[:ns], sealed[ns:], []byte(aad))
	if err != nil {
		return nil, ErrCorrupt
	}
	return plain, nil
}
