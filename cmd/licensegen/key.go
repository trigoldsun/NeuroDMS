package main

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
)

// PKCS8 + PEM 是 OpenSSL / ssh-keygen 都能处理的格式，
// 比裸 32 字节更不容易被误当成随机数据删掉。
const keyPEMType = "PRIVATE KEY"

func marshalPKCS8(priv ed25519.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: keyPEMType, Bytes: der}), nil
}

func parsePKCS8(data []byte) (ed25519.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("不是 PEM 格式")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	priv, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("不是 Ed25519 私钥（请用 licensegen -gen 生成）")
	}
	return priv, nil
}
