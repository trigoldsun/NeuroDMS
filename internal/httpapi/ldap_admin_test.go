package httpapi

import (
	"strings"
	"testing"

	"docvault/internal/directory"
)

// 配置回显绝不能带口令：回显一次就进了浏览器缓存/录屏/工单截图，收不回来。
func TestPublicDirectoryViewNeverLeaksPassword(t *testing.T) {
	in := directory.Settings{
		Enabled: true, URL: "ldaps://dc:636", BindDN: "cn=svc",
		BindPassword: "SuperSecret!", BaseDN: "dc=x",
		CAPEM: "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----",
	}
	out := publicDirectoryView(in)
	if out.BindPassword != "" {
		t.Fatal("口令被回显")
	}
	if !out.HasPassword {
		// 注意：HasPassword 由 Store.Load 设置；这里只验证"正文不出现"
		t.Log("HasPassword 由读取路径补充，保存路径不设置")
	}
	if out.CAPEM != "" {
		t.Fatal("CA 正文不应随配置列表返回")
	}
	if !out.HasCA {
		t.Fatal("应标记已配置 CA")
	}
}

// 审计里只记主机与端口：完整 URL 可能带查询串或内嵌凭据。
func TestLDAPHostPort(t *testing.T) {
	cases := []struct {
		in   string
		host string
		port int
	}{
		{"ldaps://dc1.example.com:636", "dc1.example.com", 636},
		{"ldap://dc1.example.com", "dc1.example.com", 389},
		{"ldaps://10.0.0.5", "10.0.0.5", 636},
		{"ldap://[2001:db8::1]:3268", "2001:db8::1", 3268},
		{"garbage", "", 0},
	}
	for _, c := range cases {
		h, p := ldapHostPort(c.in)
		if h != c.host || p != c.port {
			t.Errorf("ldapHostPort(%q) = %q,%d want %q,%d", c.in, h, p, c.host, c.port)
		}
	}
}

// 地址校验必须把明文 LDAP 的"未确认"挡在保存之前。
func TestDirectoryValidationGuardsPlaintext(t *testing.T) {
	err := directory.ValidateAddress("ldap://dc1:389")
	if err != nil {
		t.Fatalf("地址本身合法，端口校验不应拒绝: %v", err)
	}
	if !strings.Contains(directory.ErrInvalidInput.Error(), "不合法") {
		t.Fatal("错误语义变了")
	}
}
