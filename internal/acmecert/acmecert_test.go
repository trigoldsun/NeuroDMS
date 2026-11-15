package acmecert

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	"docvault/internal/secretbox"
)

func TestParseMode(t *testing.T) {
	cases := []struct {
		in   string
		want Mode
		bad  bool
	}{
		{"", ModeOff, false},
		{"off", ModeOff, false},
		{" OFF ", ModeOff, false},
		{"http01", ModeHTTP01, false},
		{"HTTP01", ModeHTTP01, false},
		{"dns01", ModeDNS01, false},
		// 拼错必须报错而不是当 off：静默降级的后果是"以为开了自动续期"。
		{"http-01", ModeOff, true},
		{"manual", ModeOff, true},
	}
	for _, c := range cases {
		got, err := ParseMode(c.in)
		if c.bad {
			if err == nil {
				t.Fatalf("ParseMode(%q) 应报错，实际得到 %q", c.in, got)
			}
			continue
		}
		if err != nil {
			t.Fatalf("ParseMode(%q) 意外报错: %v", c.in, err)
		}
		if got != c.want {
			t.Fatalf("ParseMode(%q) = %q，期望 %q", c.in, got, c.want)
		}
	}
}

func TestStatusOffExplainsWhatToDo(t *testing.T) {
	s := New(nil, nil, Config{Mode: ModeOff}, nil)
	st := s.Status()
	if st.Enabled || st.Available {
		t.Fatal("off 模式不应显示为可用")
	}
	// 提示必须包含"谁能做"，否则实施人员只能来问我们。
	if !strings.Contains(st.Reason, "托管") {
		t.Fatalf("off 的说明应指出证书由谁托管，实际: %s", st.Reason)
	}
}

func TestStatusWithoutSecretKey(t *testing.T) {
	// main 里 secretbox.New 失败时 box 就是 nil，这里按真实装配构造。
	s := New(nil, nil, Config{Mode: ModeHTTP01}, nil)
	st := s.Status()
	if st.Available {
		t.Fatal("没有 DOCVAULT_SECRET_KEY 时不能显示可用（私钥无处安放）")
	}
	if !strings.Contains(st.Reason, "DOCVAULT_SECRET_KEY") {
		t.Fatalf("应明确指出缺哪个配置，实际: %s", st.Reason)
	}
}

func TestStatusReportsChallengeAddr(t *testing.T) {
	box := testBox(t)
	s := New(nil, box, Config{Mode: ModeHTTP01, HTTP01Addr: ":8080"}, nil)
	st := s.Status()
	if !st.Available || st.ChallengeAt != ":8080" {
		t.Fatalf("http01 应显示可用与挑战端口，实际 %+v", st)
	}
	if st.Staging {
		t.Fatal("默认应是生产目录，不是 staging")
	}
}

func TestStagingDetected(t *testing.T) {
	s := New(nil, testBox(t), Config{Mode: ModeHTTP01, DirectoryURL: StagingDirectory}, nil)
	if !s.Status().Staging {
		t.Fatal("staging 目录应被标记出来（防止测试证书误用于生产）")
	}
}

func TestCSRContainsSAN(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := csrFor("docs.example.com", priv)
	if err != nil {
		t.Fatal(err)
	}
	req, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatal(err)
	}
	if err := req.CheckSignature(); err != nil {
		t.Fatalf("CSR 签名无效: %v", err)
	}
	if len(req.DNSNames) != 1 || req.DNSNames[0] != "docs.example.com" {
		t.Fatalf("SAN 不对: %v", req.DNSNames)
	}
	// ACME 只认 SAN；CN 留空是刻意的（某些 CA 会额外校验 CN）。
	if req.Subject.CommonName != "" {
		t.Fatalf("CN 应为空，实际 %q", req.Subject.CommonName)
	}
}

func TestCertPEMBundlesChain(t *testing.T) {
	// 用两段假 DER 验证"链的每一段都单独一个 PEM 块"，
	// 否则浏览器会报"证书链不完整"，而这种故障在 curl 下看不出来。
	out := certPEM([][]byte{{1, 2, 3}, {4, 5}})
	if n := strings.Count(out, "BEGIN CERTIFICATE"); n != 2 {
		t.Fatalf("应有 2 个 PEM 块，实际 %d:\n%s", n, out)
	}
	block, _ := pem.Decode([]byte(out))
	if block == nil || len(block.Bytes) != 3 {
		t.Fatal("第一段 PEM 内容不对")
	}
}

func TestRenewDueInOffMode(t *testing.T) {
	s := New(nil, nil, Config{Mode: ModeOff}, nil)
	// off 模式下续期必须直接返回，且不能去碰数据库（pool 为 nil）。
	ok, failed := s.RenewDue(context.Background())
	if ok != 0 || failed != 0 {
		t.Fatalf("off 模式不应续期，实际 ok=%d failed=%d", ok, failed)
	}
}

func TestTruncate(t *testing.T) {
	if got := truncate("abcdef", 3); got != "abc…" {
		t.Fatalf("截断结果不对: %q", got)
	}
	if got := truncate("ab", 3); got != "ab" {
		t.Fatalf("短串不应被改: %q", got)
	}
}

func TestRenewBeforeDefault(t *testing.T) {
	s := New(nil, nil, Config{Mode: ModeHTTP01}, nil)
	if s.cfg.RenewBefore != 30*24*time.Hour {
		t.Fatalf("默认续期窗口应 30 天，实际 %v", s.cfg.RenewBefore)
	}
	if s.cfg.HTTP01Addr != ":80" {
		t.Fatalf("默认挑战端口应 :80，实际 %s", s.cfg.HTTP01Addr)
	}
}

// testBox 构造一个可用的加密盒（32 字节密钥）。
func testBox(t *testing.T) *secretbox.Box {
	t.Helper()
	// 密钥是 base64 编码的 32 字节，不是任意 32 个字符。
	b, err := secretbox.New(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte("k"), 32)))
	if err != nil {
		t.Fatalf("构造加密盒失败: %v", err)
	}
	return b
}
