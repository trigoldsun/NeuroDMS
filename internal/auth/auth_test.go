package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestPasswordRoundTrip(t *testing.T) {
	h, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(h, "$argon2id$") {
		t.Fatalf("编码串前缀不符: %s", h)
	}
	if err := VerifyPassword(h, "correct horse battery staple"); err != nil {
		t.Fatalf("正确口令应通过: %v", err)
	}
	if err := VerifyPassword(h, "wrong password"); err != ErrPasswordMismatch {
		t.Fatalf("错误口令应返回 mismatch，实际 %v", err)
	}
}

func TestPasswordSaltIsRandom(t *testing.T) {
	a, _ := HashPassword("same")
	b, _ := HashPassword("same")
	if a == b {
		t.Fatal("相同口令两次哈希必须不同（加盐）")
	}
}

func TestVerifyRejectsMalformed(t *testing.T) {
	for _, bad := range []string{"", "plaintext", "$argon2i$v=19$m=1,t=1,p=1$aa$bb", "$argon2id$v=19$m=x$aa$bb"} {
		if err := VerifyPassword(bad, "x"); err == nil {
			t.Fatalf("非法哈希应报错: %q", bad)
		}
	}
}

func TestNeedsRehash(t *testing.T) {
	h, _ := HashPassword("x")
	if NeedsRehash(h) {
		t.Fatal("当前参数生成的哈希不应需要重算")
	}
	weak := "$argon2id$v=19$m=8192,t=1,p=1$YWJjZGVmZ2hpamtsbW5vcA$YWJjZGVmZ2hpamtsbW5vcA"
	if !NeedsRehash(weak) {
		t.Fatal("弱参数应触发重算")
	}
}

func TestAccessTokenRoundTrip(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	now := time.Now()
	c := Claims{
		Subject: "u1", TenantID: "t1", SessionID: "s1", Epoch: 3,
		IssuedAt: now, ExpiresAt: now.Add(15 * time.Minute),
	}
	tok, err := SignAccess(secret, c)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseAccess(secret, tok)
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if got.Subject != "u1" || got.TenantID != "t1" || got.SessionID != "s1" || got.Epoch != 3 {
		t.Fatalf("载荷不符: %+v", got)
	}
}

func TestAccessTokenRejectsWrongSecret(t *testing.T) {
	tok, _ := SignAccess([]byte("0123456789abcdef0123456789abcdef"), Claims{
		Subject: "u1", ExpiresAt: time.Now().Add(time.Minute),
	})
	if _, err := ParseAccess([]byte("ffffffffffffffffffffffffffffffff"), tok); err != ErrTokenSignature {
		t.Fatalf("换密钥应验签失败，实际 %v", err)
	}
}

func TestAccessTokenRejectsExpired(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	tok, _ := SignAccess(secret, Claims{
		Subject: "u1", IssuedAt: time.Now().Add(-2 * time.Hour), ExpiresAt: time.Now().Add(-time.Hour),
	})
	if _, err := ParseAccess(secret, tok); err != ErrTokenExpired {
		t.Fatalf("过期令牌应被拒，实际 %v", err)
	}
}

func TestAccessTokenRejectsTamperedPayload(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	tok, _ := SignAccess(secret, Claims{Subject: "u1", Epoch: 1, ExpiresAt: time.Now().Add(time.Hour)})
	parts := strings.Split(tok, ".")

	// 把载荷里的 epoch 改成 99，签名不变 —— 必须被拒
	raw, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var p payload
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatal(err)
	}
	p.Ep = 99
	forged, _ := json.Marshal(p)
	parts[1] = base64.RawURLEncoding.EncodeToString(forged)

	if _, err := ParseAccess(secret, strings.Join(parts, ".")); err != ErrTokenSignature {
		t.Fatalf("篡改载荷应验签失败，实际 %v", err)
	}
}

// alg=none 是经典的算法混淆攻击：必须显式拒绝。
func TestAccessTokenRejectsNoneAlgorithm(t *testing.T) {
	secret := []byte("0123456789abcdef0123456789abcdef")
	hdr := `{"alg":"none","typ":"JWT"}`
	pl := `{"sub":"admin","exp":9999999999,"typ":"access"}`
	tok := base64.RawURLEncoding.EncodeToString([]byte(hdr)) + "." +
		base64.RawURLEncoding.EncodeToString([]byte(pl)) + "."
	if _, err := ParseAccess(secret, tok); err == nil {
		t.Fatal("alg=none 必须被拒绝")
	}
}

func TestSignRejectsShortSecret(t *testing.T) {
	if _, err := SignAccess([]byte("short"), Claims{Subject: "u1"}); err == nil {
		t.Fatal("密钥过短应报错")
	}
}

func TestRefreshTokenUniqueAndHashed(t *testing.T) {
	a, ha, err := NewRefreshToken()
	if err != nil {
		t.Fatal(err)
	}
	b, hb, _ := NewRefreshToken()
	if a == b {
		t.Fatal("两次生成的刷新令牌不应相同")
	}
	if string(ha) == string(hb) {
		t.Fatal("摘要不应相同")
	}
	// 摘要必须可由明文重算得到，否则无法查库
	if string(HashRefresh(a)) != string(ha) {
		t.Fatal("摘要重算不一致")
	}
	// 摘要不等于明文本身
	if hmac.Equal(ha, []byte(a)) {
		t.Fatal("不可将明文当摘要存储")
	}
	_ = sha256.Size
}
