package secretbox

import (
	"bytes"
	"encoding/base64"
	"errors"
	"testing"
)

func key(t *testing.T) string {
	t.Helper()
	return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))
}

func TestRoundTrip(t *testing.T) {
	box, err := New(key(t))
	if err != nil {
		t.Fatal(err)
	}
	plain := []byte("-----BEGIN PRIVATE KEY-----\nsecret\n-----END PRIVATE KEY-----")
	sealed, err := box.Encrypt(plain, "cert:t1|a.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, []byte("PRIVATE KEY")) {
		t.Fatal("密文里不应出现明文片段")
	}
	out, err := box.Decrypt(sealed, "cert:t1|a.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, plain) {
		t.Fatal("解密结果与原文不一致")
	}
}

// AAD 绑定：把 A 租户的密文搬到 B 的行里必须解不开。
// 这条防的是"通过改 tenant_id 把别人的私钥变成自己的"。
func TestAADBindsTenantAndHost(t *testing.T) {
	box, _ := New(key(t))
	sealed, err := box.Encrypt([]byte("k"), "cert:t1|a.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := box.Decrypt(sealed, "cert:t2|a.example.com"); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("换租户应解不开，实际 %v", err)
	}
	if _, err := box.Decrypt(sealed, "cert:t1|b.example.com"); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("换域名应解不开，实际 %v", err)
	}
}

func TestNoKey(t *testing.T) {
	if _, err := New(""); !errors.Is(err, ErrNoKey) {
		t.Fatalf("空密钥应返回 ErrNoKey，实际 %v", err)
	}
	// 长度不对也不能"凑合用"
	short := base64.StdEncoding.EncodeToString([]byte("too-short"))
	if _, err := New(short); err == nil {
		t.Fatal("密钥长度不足应报错")
	}
	// 零值 Box 必须安全失败，而不是 panic
	var b Box
	if b.Available() {
		t.Fatal("零值不应可用")
	}
	if _, err := b.Encrypt([]byte("x"), ""); !errors.Is(err, ErrNoKey) {
		t.Fatalf("零值加密应返回 ErrNoKey，实际 %v", err)
	}
}

// 每次加密的 nonce 必须不同（同一明文两次加密结果不同）。
func TestNonceVaries(t *testing.T) {
	box, _ := New(key(t))
	a, _ := box.Encrypt([]byte("same"), "")
	b, _ := box.Encrypt([]byte("same"), "")
	if bytes.Equal(a, b) {
		t.Fatal("两次加密结果相同说明 nonce 复用，GCM 下会泄露明文异或")
	}
}
