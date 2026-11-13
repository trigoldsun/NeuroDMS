package directory

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func baseSettings() Settings {
	return Settings{
		Enabled: true,
		URL:     "ldaps://dc1.example.com:636",
		BaseDN:  "DC=example,DC=com",
		ADMode:  true,
	}
}

// 地址是防 SSRF 的第一层：scheme、端口、链路本地都要挡住。
func TestValidateAddress(t *testing.T) {
	ok := []string{
		"ldaps://dc1.example.com:636",
		"ldap://10.0.0.5:389",
		"ldap://dc1:3268",
		"ldaps://[2001:db8::1]:636",
	}
	for _, u := range ok {
		if err := ValidateAddress(u); err != nil {
			t.Errorf("%s 应通过，实际 %v", u, err)
		}
	}

	bad := map[string]string{
		"http://dc1.example.com":      "scheme",
		"ldap://dc1.example.com:3389": "端口",
		"ldap://":                     "主机",
		"169.254.169.254":             "scheme",
		"ldap://169.254.169.254:389":  "链路本地",
		"ldaps://[fe80::1]:636":       "链路本地",
	}
	for u, want := range bad {
		err := ValidateAddress(u)
		if err == nil {
			t.Errorf("%s 应被拒绝", u)
			continue
		}
		if !strings.Contains(err.Error(), want) && !errors.Is(err, ErrInvalidInput) {
			t.Errorf("%s 的错误应提到 %q，实际 %v", u, want, err)
		}
	}
	if err := ValidateAddress("ldap://169.254.169.254:389"); err == nil ||
		!strings.Contains(err.Error(), "链路本地") {
		t.Errorf("必须明确拒绝云元数据地址，实际 %v", err)
	}
}

// 停用状态允许保存半成品：管理员常常先存草稿、再补细节。
func TestValidateAllowsDraftWhenDisabled(t *testing.T) {
	if err := Validate(context.Background(), nil, "", Settings{Enabled: false}); err != nil {
		t.Fatalf("停用时不应校验内容: %v", err)
	}
}

func TestValidateRejectsIncomplete(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*Settings)
		want string
	}{
		{"缺 BaseDN", func(s *Settings) { s.BaseDN = "" }, "BaseDN"},
		{"明文未确认", func(s *Settings) { s.URL = "ldap://dc1:389" }, "明文"},
		{"认证过滤器缺占位符", func(s *Settings) { s.UserFilter = "(objectClass=user)" }, "%s"},
		{"同步过滤器含占位符", func(s *Settings) { s.SyncFilter = "(&(objectClass=user)(sAMAccountName=%s))" }, "不能包含"},
		{"CA 非 PEM", func(s *Settings) { s.CAPEM = "not a cert" }, "PEM"},
		{"同步间隔越界", func(s *Settings) { s.SyncIntervalMinutes = 2000 }, "1440"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := baseSettings()
			c.mut(&s)
			err := Validate(context.Background(), nil, "", s)
			if err == nil {
				t.Fatalf("应被拒绝")
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Fatalf("错误信息应提到 %q，实际 %v", c.want, err)
			}
		})
	}
}

// 明文绑定只有在显式允许时才放行（域口令不能无声地过明文链路）。
func TestValidateAllowsPlaintextOnlyWhenConfirmed(t *testing.T) {
	s := baseSettings()
	s.URL = "ldap://dc1.example.com:389"
	s.AllowPlaintext = true
	if err := Validate(context.Background(), nil, "", s); err != nil {
		t.Fatalf("显式允许明文时应通过: %v", err)
	}
}

// 过滤器留空要按模式补默认值，否则界面上"填了一半"会让认证永远搜不到人。
func TestNormalizeFillsFilterDefaults(t *testing.T) {
	ad := normalize(Settings{ADMode: true})
	if !strings.Contains(ad.UserFilter, "sAMAccountName=%s") {
		t.Fatalf("AD 模式默认认证过滤器不对: %q", ad.UserFilter)
	}
	if strings.Contains(ad.SyncFilter, "%s") {
		t.Fatalf("同步过滤器不应含占位符: %q", ad.SyncFilter)
	}
	if !strings.Contains(ad.SyncFilter, "objectCategory=person") {
		t.Fatalf("AD 同步必须排除计算机账号: %q", ad.SyncFilter)
	}

	ldapCfg := normalize(Settings{})
	if !strings.Contains(ldapCfg.UserFilter, "uid=%s") {
		t.Fatalf("通用 LDAP 默认认证过滤器不对: %q", ldapCfg.UserFilter)
	}

	// 排除账号去空去重
	ex := normalize(Settings{ExcludeAccounts: []string{" krbtgt ", "", "KRBTGT", "svc"}})
	if len(ex.ExcludeAccounts) != 2 {
		t.Fatalf("排除账号应去重去空，实际 %v", ex.ExcludeAccounts)
	}
}

// 配置到客户端的映射不能漏字段（漏一个就是"界面配了但没生效"）。
func TestToLDAPConfigMapsEverything(t *testing.T) {
	s := Settings{
		URL: "ldaps://dc:636", StartTLS: false, InsecureSkipVerify: true,
		CAPEM: "-----BEGIN CERTIFICATE-----", TLSName: "DC.example.com",
		BindDN: "cn=svc", BindPassword: "p", BaseDN: "dc=x",
		UserFilter: "u=%s", SyncFilter: "u=*", GroupFilter: "g=*",
		ADMode: true, AllowPlaintext: false,
	}
	c := s.ToLDAPConfig()
	if c.URL != s.URL || c.CACertFile != "" || string(c.CAPEM) != s.CAPEM ||
		c.TLSName != s.TLSName || c.BindDN != s.BindDN || c.BindPassword != s.BindPassword ||
		c.BaseDN != s.BaseDN || c.UserFilter != s.UserFilter ||
		c.SyncUserFilter != s.SyncFilter || c.GroupFilter != s.GroupFilter || !c.ADMode {
		t.Fatalf("映射不完整: %+v", c)
	}
}

// 口令必须能从请求体解析进来，且永远不能序列化出去。
//
// 回归背景：字段曾被标成 json:"-"，请求里的 bindPassword 根本没被解析，
// 保存后 hasPassword 一直是 false——界面显示"已保存"，实际口令丢了，
// 只有等第一次真实登录失败才会发现。
func TestBindPasswordParsedButNeverSerialized(t *testing.T) {
	var s Settings
	if err := json.Unmarshal([]byte(`{"bindDn":"cn=svc","bindPassword":"pw-123"}`), &s); err != nil {
		t.Fatal(err)
	}
	if s.BindPassword != "pw-123" {
		t.Fatalf("口令未被解析: %q", s.BindPassword)
	}
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), "pw-123") {
		t.Fatalf("口令被序列化出去: %s", b)
	}
	if strings.Contains(string(b), "bindPassword") {
		t.Fatalf("响应里不应出现 bindPassword 字段: %s", b)
	}
}
