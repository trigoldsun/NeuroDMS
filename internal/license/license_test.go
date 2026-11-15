package license

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func newKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func signBlob(t *testing.T, priv ed25519.PrivateKey, p Payload) string {
	t.Helper()
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(priv, raw)
	return base64.RawURLEncoding.EncodeToString(raw) + "." +
		base64.RawURLEncoding.EncodeToString(sig)
}

func basePayload() Payload {
	return Payload{
		V: Version, LicenseID: "DV-1", Customer: "测试客户",
		Edition: "business", Capabilities: []string{"*"}, Seats: 0,
	}
}

func TestVerifyAndCheck(t *testing.T) {
	pub, priv := newKey(t)
	blob := signBlob(t, priv, basePayload())

	p, err := Verify(pub, blob)
	if err != nil {
		t.Fatalf("应验签通过: %v", err)
	}
	if p.Customer != "测试客户" || !p.AllCaps() {
		t.Fatalf("解析结果不对: %+v", p)
	}
	if _, has, _ := p.Expiry(); has {
		t.Fatal("没填 expiresAt 应视为永久")
	}
	if err := Check(p, "", time.Now()); err != nil {
		t.Fatalf("不绑机器 + 永久，应始终有效: %v", err)
	}
}

func TestVerifyRejectsTamperedPayload(t *testing.T) {
	pub, priv := newKey(t)
	blob := signBlob(t, priv, basePayload())

	// 把 payload 改一位（换客户名）后重新拼签名：必须失败。
	parts := strings.Split(blob, ".")
	raw, _ := base64.RawURLEncoding.DecodeString(parts[0])
	var p Payload
	_ = json.Unmarshal(raw, &p)
	p.Customer = "别人公司"
	bad, _ := json.Marshal(p)
	tampered := base64.RawURLEncoding.EncodeToString(bad) + "." + parts[1]

	if _, err := Verify(pub, tampered); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("改过内容应报 ErrBadSignature，实际 %v", err)
	}
}

func TestVerifyRejectsOtherKey(t *testing.T) {
	_, priv := newKey(t)
	otherPub, _ := newKey(t)
	blob := signBlob(t, priv, basePayload())
	if _, err := Verify(otherPub, blob); !errors.Is(err, ErrBadSignature) {
		t.Fatalf("换公钥应失败，实际 %v", err)
	}
}

func TestMalformed(t *testing.T) {
	pub, _ := newKey(t)
	for _, s := range []string{"", "abc", "a.b.c", "!!!.???"} {
		if _, err := Verify(pub, s); err == nil {
			t.Fatalf("%q 应被拒绝", s)
		}
	}
}

func TestWrongVersion(t *testing.T) {
	pub, priv := newKey(t)
	p := basePayload()
	p.V = 99
	if _, err := Verify(pub, signBlob(t, priv, p)); !errors.Is(err, ErrMalformed) {
		t.Fatalf("版本不符应报 ErrMalformed，实际 %v", err)
	}
}

// 指纹不匹配必须先于"已过期"报出来：否则客户会去翻购买记录，
// 而实际要做的是申请换发。
func TestCheckPrefersInstanceMismatch(t *testing.T) {
	pub, priv := newKey(t)
	p := basePayload()
	p.InstanceID = "11111111-1111-1111-1111-111111111111"
	p.ExpiresAt = "2020-01-01T00:00:00Z"
	got, err := Verify(pub, signBlob(t, priv, p))
	if err != nil {
		t.Fatal(err)
	}
	err = Check(got, "22222222-2222-2222-2222-222222222222", time.Now())
	if !errors.Is(err, ErrWrongInstance) {
		t.Fatalf("应报指纹不匹配，实际 %v", err)
	}
	// 指纹对上才谈到期
	err = Check(got, p.InstanceID, time.Now())
	if !errors.Is(err, ErrExpired) {
		t.Fatalf("应报已过期，实际 %v", err)
	}
}

// 到期日当天仍然有效：签发工具把日期补到 23:59:59，
// 这里验证"最后一刻"的判断边界。
func TestExpiryLastSecond(t *testing.T) {
	p := basePayload()
	p.ExpiresAt = "2027-01-01T23:59:59Z"
	exp, has, err := p.Expiry()
	if err != nil || !has {
		t.Fatalf("解析到期失败: %v", err)
	}
	if !time.Date(2027, 1, 1, 23, 59, 58, 0, time.UTC).Before(exp) {
		t.Fatal("到期前一秒应仍在有效期内")
	}
	if time.Date(2027, 1, 2, 0, 0, 0, 0, time.UTC).Before(exp) {
		t.Fatal("到期后一秒不应在有效期内")
	}
}

func TestParsePublicKeyFormats(t *testing.T) {
	pub, _ := newKey(t)
	raw := []byte(pub)
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding,
	} {
		if _, err := ParsePublicKey(enc.EncodeToString(raw)); err != nil {
			t.Fatalf("应接受这种编码: %v", err)
		}
	}
	if _, err := ParsePublicKey(""); !errors.Is(err, ErrNoPublicKey) {
		t.Fatalf("空公钥应报 ErrNoPublicKey，实际 %v", err)
	}
	if _, err := ParsePublicKey("AAAA"); err == nil {
		t.Fatal("长度不对应报错")
	}
}
