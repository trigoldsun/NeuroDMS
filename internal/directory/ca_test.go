package directory

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// 写一张自签证书到临时文件，模拟企业根 CA。
func writeSelfSignedCA(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-root-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// CA 文件应在启动时加载并校验格式：写错了要立刻报错，而不是等第一次登录。
func TestCACertFileLoadedAtStartup(t *testing.T) {
	ca := writeSelfSignedCA(t)

	d, err := NewLDAP(context.Background(), LDAPConfig{
		URL: "ldaps://192.0.2.10:636", BaseDN: "DC=example,DC=com",
		CACertFile: ca, TLSName: "dc.example.com", Timeout: 300_000_000,
	})
	if err == nil {
		// 地址不可达，但至少证明 CA 加载没挡住启动
		if d == nil {
			t.Fatal("返回对象为空")
		}
		return
	}
	// 只允许"连不上"这类网络错误，不允许 CA 解析错误
	if strings.Contains(err.Error(), "CA") {
		t.Fatalf("合法 CA 不应报错: %v", err)
	}
}

func TestCACertFileInvalidIsRejected(t *testing.T) {
	bad := filepath.Join(t.TempDir(), "bad.pem")
	if err := os.WriteFile(bad, []byte("not a certificate"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := NewLDAP(context.Background(), LDAPConfig{
		URL: "ldaps://192.0.2.10:636", BaseDN: "DC=example,DC=com", CACertFile: bad,
	})
	if err == nil || !strings.Contains(err.Error(), "PEM") {
		t.Fatalf("非 PEM 的 CA 文件应被拒绝，实际 %v", err)
	}

	if _, err := NewLDAP(context.Background(), LDAPConfig{
		URL: "ldaps://192.0.2.10:636", BaseDN: "DC=example,DC=com",
		CACertFile: filepath.Join(t.TempDir(), "missing.pem"),
	}); err == nil {
		t.Fatal("CA 文件不存在应报错")
	}
}

// TLSName 必须覆盖 URL 里的主机名，否则"按 IP 连、按 DNS 名校验"无法实现。
func TestTLSNameOverridesServerName(t *testing.T) {
	ca := writeSelfSignedCA(t)
	d := &LDAPDirectory{cfg: LDAPConfig{
		URL: "ldaps://192.168.1.10:636", CACertFile: ca, TLSName: "dc.corp.example",
	}}
	cfg := d.tlsConfig()
	if cfg.ServerName != "dc.corp.example" {
		t.Fatalf("ServerName 应为显式指定的名称，实际 %s", cfg.ServerName)
	}
	if cfg.InsecureSkipVerify {
		t.Fatal("配置了 CA 就不应跳过校验")
	}

	// 未指定 TLSName 时回落到 URL 主机名
	d2 := &LDAPDirectory{cfg: LDAPConfig{URL: "ldaps://dc.corp.example:636"}}
	if got := d2.tlsConfig().ServerName; got != "dc.corp.example" {
		t.Fatalf("应回落到 URL 主机名，实际 %s", got)
	}
}
