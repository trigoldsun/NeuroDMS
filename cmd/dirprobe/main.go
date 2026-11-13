// Command dirprobe 探测 LDAP/AD 目录：连通性、命名上下文、绑定结果、属性映射。
//
// 为什么需要它：域账号登录失败时，问题可能在网络、证书、绑定 DN、属性名、
// 嵌套组…… 靠看服务日志只能看到"凭据不正确"，无法定位。这个命令把每一步单独打出来。
//
// 只读：不做任何写入，也不会修改目录。
package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

func main() {
	var (
		url        = flag.String("url", "ldap://127.0.0.1:389", "目录地址，ldap:// 或 ldaps://")
		starttls   = flag.Bool("starttls", false, "在 ldap:// 上升级 TLS")
		insecure   = flag.Bool("insecure", false, "跳过证书校验（仅内网自签）")
		bindDN     = flag.String("bind", "", "服务账号 DN")
		password   = flag.String("pass", "", "服务账号口令")
		baseDN     = flag.String("base", "", "Base DN（留空则从 rootDSE 读取）")
		user       = flag.String("user", "", "要测试认证的用户（sAMAccountName 或 uid）")
		userPass   = flag.String("userpass", "", "该用户的口令（用于验证绑定认证链路）")
		filter     = flag.String("filter", "", "自定义用户过滤条件，%s 为用户名占位")
		allowPlain = flag.Bool("allow-plaintext", false, "允许在明文连接上做简单绑定（仅实验网）")
		groupName  = flag.String("group", "", "要查看成员的组名（cn），用于确认嵌套关系")
		saveCA     = flag.String("save-ca", "", "把 AD 中的根 CA 证书导出为 PEM 文件（用于客户端信任配置）")
		caFile     = flag.String("ca", "", "用指定的 CA 证书校验服务端（替代 -insecure）")
		tlsName    = flag.String("tls-name", "", "证书校验使用的名称（按 IP 连、证书只有 DNS SAN 时必填）")
	)
	flag.Parse()

	if !*allowPlain && !*starttls && !strings.HasPrefix(*url, "ldaps://") {
		fail("地址未加密：域口令会以明文传输。生产请给域控装 LDAP 证书；实验网请显式加 -allow-plaintext")
	}
	if *allowPlain && !*starttls && !strings.HasPrefix(*url, "ldaps://") {
		fmt.Println("!! 警告：正在明文连接上做简单绑定，口令会经过网络，仅限实验环境")
	}

	fmt.Println("== 1. 连接 ==")
	dialer := &net.Dialer{Timeout: 8 * time.Second}
	opts := []ldap.DialOpt{ldap.DialWithDialer(dialer)}
	tlsCfg, err := tlsConfig(*insecure, *caFile, *tlsName, *url)
	if err != nil {
		fail("加载 CA 失败: %v", err)
	}
	if strings.HasPrefix(*url, "ldaps://") {
		opts = append(opts, ldap.DialWithTLSConfig(tlsCfg))
	}
	conn, err := ldap.DialURL(*url, opts...)
	if err != nil {
		fail("连接失败: %v", err)
	}
	defer conn.Close()
	fmt.Println("   OK", *url)

	if *starttls {
		if err := conn.StartTLS(tlsCfg); err != nil {
			fail("StartTLS 失败: %v", err)
		}
		fmt.Println("   StartTLS 已升级")
	}

	fmt.Println("== 2. 读 rootDSE（匿名）==")
	base := *baseDN
	res, err := conn.Search(ldap.NewSearchRequest("", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 10, false,
		"(objectClass=*)",
		[]string{"defaultNamingContext", "rootDomainNamingContext", "dnsHostName", "supportedLDAPVersion"}, nil))
	if err != nil {
		fmt.Println("   匿名读取被拒绝（不少 AD 默认禁止匿名）:", err)
	} else if len(res.Entries) > 0 {
		e := res.Entries[0]
		fmt.Println("   dnsHostName          :", e.GetAttributeValue("dnsHostName"))
		fmt.Println("   defaultNamingContext :", e.GetAttributeValue("defaultNamingContext"))
		fmt.Println("   supportedLDAPVersion :", e.GetAttributeValues("supportedLDAPVersion"))
		if base == "" {
			base = e.GetAttributeValue("defaultNamingContext")
		}
	}
	if base == "" {
		fail("无法确定 Base DN，请用 -base 指定")
	}
	fmt.Println("   使用 Base DN:", base)

	fmt.Println("== 3. 服务账号绑定 ==")
	if *bindDN == "" {
		fmt.Println("   跳过（未提供 -bind）")
	} else if err := conn.Bind(*bindDN, *password); err != nil {
		fail("绑定失败: %v", err)
	} else {
		fmt.Println("   OK", *bindDN)
	}

	if *user != "" {
		fmt.Println("== 4. 搜索用户 ==")
		f := *filter
		if f == "" {
			f = "(&(objectClass=user)(sAMAccountName=%s))"
		}
		req := ldap.NewSearchRequest(base, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 5, 10, false,
			fmt.Sprintf(f, ldap.EscapeFilter(*user)),
			[]string{"sAMAccountName", "displayName", "mail", "objectGUID", "objectSid",
				"distinguishedName", "userAccountControl", "memberOf", "department", "uSNChanged"}, nil)
		ures, err := conn.Search(req)
		if err != nil {
			fail("搜索失败: %v", err)
		}
		if len(ures.Entries) == 0 {
			fail("未找到用户 %q（检查过滤条件与 Base DN）", *user)
		}
		if len(ures.Entries) > 1 {
			fmt.Printf("   注意：命中 %d 条，只用第一条\n", len(ures.Entries))
		}
		e := ures.Entries[0]
		fmt.Println("   DN         :", e.DN)
		for _, attr := range []string{"sAMAccountName", "displayName", "mail", "department", "uSNChanged"} {
			fmt.Printf("   %-12s: %s\n", attr, e.GetAttributeValue(attr))
		}
		guid := e.GetAttributeValue("objectGUID")
		fmt.Printf("   objectGUID : %x（原始字节，需转成十六进制字符串做外部标识）\n", []byte(guid))
		fmt.Println("   memberOf   :", len(e.GetAttributeValues("memberOf")), "个直接组")
		if uac := e.GetAttributeValue("userAccountControl"); uac != "" {
			fmt.Println("   userAccountControl:", uac, "（bit1=0x2 表示账号已禁用）")
		}

		fmt.Println("== 5. 用该用户口令绑定（验证认证链路）==")
		if *userPass == "" {
			fmt.Println("   跳过（未提供 -userpass）")
		} else {
			uc, err := ldap.DialURL(*url, opts...)
			if err != nil {
				fail("二次连接失败: %v", err)
			}
			defer uc.Close()
			if *starttls {
				if err := uc.StartTLS(tlsCfg); err != nil {
					fail("二次 StartTLS 失败: %v", err)
				}
			}
			if err := uc.Bind(e.DN, *userPass); err != nil {
				fail("用户绑定失败（口令错或被锁）: %v", err)
			}
			fmt.Println("   OK：该用户可用此 DN + 口令登录")
		}
	}
	if *groupName != "" {
		fmt.Println("== 6. 查看组成员（用于确认嵌套组）==")
		req := ldap.NewSearchRequest(base, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 5, 10, false,
			"(cn="+ldap.EscapeFilter(*groupName)+")",
			[]string{"cn", "distinguishedName", "member", "objectClass"}, nil)
		gres, err := conn.Search(req)
		if err != nil {
			fail("查询组失败: %v", err)
		}
		if len(gres.Entries) == 0 {
			fail("未找到组 %q", *groupName)
		}
		g := gres.Entries[0]
		members := g.GetAttributeValues("member")
		fmt.Printf("   %s（DN=%s）直接成员 %d 个\n", g.GetAttributeValue("cn"), g.DN, len(members))
		for _, m := range members {
			kind := "用户/其它"
			if strings.Contains(strings.ToUpper(m), "CN=") && strings.Contains(strings.ToUpper(m), "OU=GROUPS") {
				kind = "可能是组"
			}
			fmt.Println("   -", m, "["+kind+"]")
		}
	}

	if *saveCA != "" {
		fmt.Println("== 7. 从 AD 导出根 CA ==")
		if err := exportCA(conn, base, *saveCA); err != nil {
			fail("导出失败: %v", err)
		}
	}

	fmt.Println("\n探测结束，全部步骤通过。")
}

// exportCA 从 AD 的配置分区读取企业 CA 的根证书并写成 PEM。
//
// 为什么从 AD 取而不是从服务器导出文件：AD 本身就是企业 CA 的证书分发点
// （CN=Certification Authorities），取到的就是域内所有机器实际信任的那张，
// 不用登服务器、也不用猜文件名。NTAuthCertificates 里同时保存了一份，
// 用于"哪些 CA 签发的证书可用于域认证"。
func exportCA(conn *ldap.Conn, baseDN, outPath string) error {
	configDN, err := configNamingContext(baseDN)
	if err != nil {
		return err
	}
	bases := []struct {
		dn     string
		filter string
	}{
		// 证书分发点在 CN=Public Key Services,CN=Services,CN=Configuration,...
		// 少写这一段会得到 NO_OBJECT，看起来像"域里没有 CA"，实际只是路径不对
		{"CN=Certification Authorities,CN=Public Key Services,CN=Services," + configDN,
			"(objectClass=certificationAuthority)"},
		{"CN=NTAuthCertificates,CN=Public Key Services,CN=Services," + configDN,
			"(objectClass=*)"},
	}

	var pemOut []byte
	seen := map[string]bool{}
	for _, b := range bases {
		res, err := conn.Search(ldap.NewSearchRequest(b.dn, ldap.ScopeBaseObject, ldap.NeverDerefAliases,
			1, 10, false, b.filter, []string{"cn", "cACertificate"}, nil))
		if err != nil {
			fmt.Printf("   跳过 %s: %v\n", b.dn, err)
			continue
		}
		for _, e := range res.Entries {
			for _, der := range e.GetRawAttributeValues("cACertificate") {
				cert, err := x509.ParseCertificate(der)
				if err != nil {
					continue
				}
				if seen[cert.Subject.String()] {
					continue
				}
				seen[cert.Subject.String()] = true
				fmt.Printf("   CA: %s（有效期至 %s）\n",
					cert.Subject.String(), cert.NotAfter.Format("2006-01-02"))
				pemOut = append(pemOut, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
			}
		}
	}
	if len(pemOut) == 0 {
		return errors.New("未在 AD 中找到 CA 证书（该域可能使用独立 CA，需手工导出）")
	}
	if err := os.WriteFile(outPath, pemOut, 0o600); err != nil {
		return err
	}
	fmt.Printf("   已写入 %s（%d 张证书）\n", outPath, len(seen))
	return nil
}

// hostFromURL 从 ldap(s)://host:port 里取出主机名。
func hostFromURL(raw string) string {
	s := raw
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.Index(s, "/"); i >= 0 {
		s = s[:i]
	}
	if i := strings.LastIndex(s, ":"); i > 0 {
		s = s[:i]
	}
	return s
}

// configNamingContext 由域 DN 推导配置分区 DN：DC=a,DC=b → CN=Configuration,DC=a,DC=b
func configNamingContext(baseDN string) (string, error) {
	// 找到第一个 DC= 的位置，把前面可能的 OU/CN 去掉
	if i := strings.Index(strings.ToUpper(baseDN), "DC="); i >= 0 {
		return "CN=Configuration," + baseDN[i:], nil
	}
	return "", errors.New("Base DN 不是域根（应以 DC= 开头）")
}

// tlsConfig 组装 TLS 配置。
//
// 优先用调用方提供的 CA 文件做**真正的校验**；只有在明确 -insecure 时才跳过。
// 跳过校验是排障手段，不是部署方案：不校验就等于任何人都能冒充域控收走域口令。
func tlsConfig(insecure bool, caFile, tlsName, url string) (*tls.Config, error) {
	name := tlsName
	if name == "" {
		name = hostFromURL(url)
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: insecure, ServerName: name}
	if caFile != "" {
		raw, err := os.ReadFile(caFile)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(raw) {
			return nil, fmt.Errorf("%s 中没有可用的 PEM 证书", caFile)
		}
		cfg.RootCAs = pool
		cfg.InsecureSkipVerify = false
	}
	return cfg, nil
}

func fail(format string, args ...any) {
	fmt.Printf("   FAIL: "+format+"\n", args...)
	os.Exit(1)
}
