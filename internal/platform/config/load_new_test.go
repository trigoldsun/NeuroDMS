package config

import "testing"

// 这条用例针对一类真实事故：Config 结构体加了字段，但 Load 忘了读环境变量——
// 编译通过、测试通过、功能静默失效，只有线上"配置了却没生效"时才被发现。
// 所以这里逐个断言"写了环境变量，Config 里必须看到"。
func TestLoadReadsEveryNewOption(t *testing.T) {
	env := map[string]string{
		"DOCVAULT_PREVIEW_ENABLED":          "0",
		"DOCVAULT_PREVIEW_DIR":              "/tmp/prev",
		"DOCVAULT_PUBLIC_URL":               "https://dms.example.com",
		"DOCVAULT_ONLYOFFICE_URL":           "http://onlyoffice:8080",
		"DOCVAULT_ONLYOFFICE_JWT_SECRET":    "office-secret",
		"DOCVAULT_ONLYOFFICE_ALLOWED_HOSTS": "onlyoffice, docs.internal",
		"DOCVAULT_MEDIA_ENABLED":            "0",
		"DOCVAULT_MEDIA_DIR":                "/tmp/media",
		"DOCVAULT_MEDIA_CONCURRENCY":        "3",
		"DOCVAULT_ANCHOR_SECRET":            "anchor-secret",
		"DOCVAULT_LDAP_URL":                 "ldaps://dc1:636",
		"DOCVAULT_LDAP_BASE_DN":             "DC=example,DC=com",
		"DOCVAULT_LDAP_BIND_DN":             "CN=svc,DC=example,DC=com",
		"DOCVAULT_LDAP_BIND_PASSWORD":       "svc-pass",
		"DOCVAULT_LDAP_AD_MODE":             "1",
		"DOCVAULT_LDAP_SYNC_FILTER":         "(&(objectClass=user)(objectCategory=person))",
		"DOCVAULT_LDAP_EXCLUDE_ACCOUNTS":    "krbtgt, svc_backup",
		"DOCVAULT_LDAP_INSECURE":            "1",
		"DOCVAULT_SMTP_HOST":                "smtp.example.com",
		"DOCVAULT_SMTP_PORT":                "2525",
		"DOCVAULT_SMTP_FROM":                "noreply@example.com",
		"DOCVAULT_SMTP_TLS":                 "tls",
		"DOCVAULT_GRAPH_TENANT_ID":          "tid",
		"DOCVAULT_GRAPH_CLIENT_ID":          "cid",
		"DOCVAULT_GRAPH_CLIENT_SECRET":      "csecret",
		"DOCVAULT_GRAPH_SENDER":             "dms@example.com",
		"DOCVAULT_METRICS_TOKEN":            "metrics-token-1",
		"DOCVAULT_PLATFORM_TOKEN":           "platform-token-1",
	}
	cfg, err := Load(func(k string) string { return env[k] })
	if err != nil {
		t.Fatalf("配置加载失败: %v", err)
	}

	checks := []struct {
		name string
		got  any
		want any
	}{
		{"PreviewEnabled", cfg.PreviewEnabled, false},
		{"PreviewDir", cfg.PreviewDir, "/tmp/prev"},
		{"OfficePublicURL", cfg.OfficePublicURL, "https://dms.example.com"},
		{"OfficeURL", cfg.OfficeURL, "http://onlyoffice:8080"},
		{"OfficeJWTSecret", cfg.OfficeJWTSecret, "office-secret"},
		{"MediaEnabled", cfg.MediaEnabled, false},
		{"MediaDir", cfg.MediaDir, "/tmp/media"},
		{"MediaConcurrency", cfg.MediaConcurrency, 3},
		{"AnchorSecret", cfg.AnchorSecret, "anchor-secret"},
		{"LDAPURL", cfg.LDAPURL, "ldaps://dc1:636"},
		{"LDAPBaseDN", cfg.LDAPBaseDN, "DC=example,DC=com"},
		{"LDAPBindDN", cfg.LDAPBindDN, "CN=svc,DC=example,DC=com"},
		{"LDAPBindPassword", cfg.LDAPBindPassword, "svc-pass"},
		{"LDAPADMode", cfg.LDAPADMode, true},
		{"LDAPSyncFilter", cfg.LDAPSyncFilter, "(&(objectClass=user)(objectCategory=person))"},
		{"LDAPInsecure", cfg.LDAPInsecure, true},
		{"SMTPHost", cfg.SMTPHost, "smtp.example.com"},
		{"SMTPPort", cfg.SMTPPort, 2525},
		{"SMTPFrom", cfg.SMTPFrom, "noreply@example.com"},
		{"SMTPTLS", cfg.SMTPTLS, "tls"},
		{"GraphTenantID", cfg.GraphTenantID, "tid"},
		{"GraphClientID", cfg.GraphClientID, "cid"},
		{"GraphClientSecret", cfg.GraphClientSecret, "csecret"},
		{"GraphSender", cfg.GraphSender, "dms@example.com"},
		// 曾经漏读的两个字段（配了不生效，且故障完全静默）
		{"MetricsToken", cfg.MetricsToken, "metrics-token-1"},
		{"PlatformToken", cfg.PlatformToken, "platform-token-1"},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %v，期望 %v", c.name, c.got, c.want)
		}
	}

	if len(cfg.LDAPExcludeAccounts) != 2 || cfg.LDAPExcludeAccounts[1] != "svc_backup" {
		t.Errorf("LDAPExcludeAccounts 解析错误: %v", cfg.LDAPExcludeAccounts)
	}

	// 逗号列表要正确切分
	if len(cfg.OfficeAllowedHosts) != 2 || cfg.OfficeAllowedHosts[1] != "docs.internal" {
		t.Errorf("OfficeAllowedHosts 解析错误: %v", cfg.OfficeAllowedHosts)
	}
}

// 未配置时的默认值：预览与媒体默认开启，目录/通知默认关闭。
func TestLoadDefaultsForNewOptions(t *testing.T) {
	cfg, err := Load(func(string) string { return "" })
	if err != nil {
		t.Fatalf("空配置应能加载: %v", err)
	}
	if !cfg.PreviewEnabled || !cfg.MediaEnabled {
		t.Error("预览与媒体应默认开启（缺依赖时运行时降级）")
	}
	if cfg.PreviewDir == "" || cfg.MediaDir == "" {
		t.Error("预览/媒体目录应有默认值")
	}
	if cfg.LDAPURL != "" || cfg.SMTPHost != "" || cfg.OfficeURL != "" {
		t.Error("目录/邮件/编辑器默认应为空（未配置即关闭）")
	}
	if cfg.SMTPTLS != "starttls" || cfg.SMTPPort != 587 {
		t.Errorf("SMTP 默认值不符: tls=%s port=%d", cfg.SMTPTLS, cfg.SMTPPort)
	}
}
