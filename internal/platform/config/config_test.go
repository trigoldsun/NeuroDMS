package config

import (
	"errors"
	"strings"
	"testing"
)

func mapGetenv(m map[string]string) Getenv {
	return func(k string) string { return m[k] }
}

func TestLoadDevelopmentDefaults(t *testing.T) {
	c, err := Load(mapGetenv(nil))
	if err != nil {
		t.Fatalf("开发形态应可直接启动: %v", err)
	}
	if c.Mode != ModeDevelopment || c.HTTPAddr != ":8080" {
		t.Fatalf("默认值不符: %+v", c)
	}
}

func TestLoadProductionRejectsWeakSecret(t *testing.T) {
	_, err := Load(mapGetenv(map[string]string{
		"DOCVAULT_MODE":       ModeSaaS,
		"DOCVAULT_JWT_SECRET": "changeme",
		"DOCVAULT_DB_DSN":     "postgres://x",
	}))
	if err == nil {
		t.Fatal("SaaS 形态下弱密钥必须拒绝启动")
	}
	var ce *Error
	if !errors.As(err, &ce) {
		t.Fatalf("期望 *Error，实际 %T", err)
	}
	if len(ce.Problems) != 1 || !strings.Contains(ce.Problems[0], "JWT_SECRET") {
		t.Fatalf("问题项不符: %v", ce.Problems)
	}
}

func TestLoadListsAllProblems(t *testing.T) {
	_, err := Load(mapGetenv(map[string]string{
		"DOCVAULT_MODE":       "standalone",
		"DOCVAULT_JWT_SECRET": "short",
	}))
	if err == nil {
		t.Fatal("应报错")
	}
	var ce *Error
	if !errors.As(err, &ce) {
		t.Fatalf("期望 *Error，实际 %T", err)
	}
	// 密钥过短 + 缺 DSN，两项都要出现，不能只报第一个
	if len(ce.Problems) != 2 {
		t.Fatalf("应一次性列出 2 项问题，实际 %v", ce.Problems)
	}
}

func TestLoadRejectsUnknownMode(t *testing.T) {
	_, err := Load(mapGetenv(map[string]string{"DOCVAULT_MODE": "cluster"}))
	if err == nil {
		t.Fatal("未知形态应拒绝")
	}
}

func TestTrustProxyDefaultEmpty(t *testing.T) {
	c, err := Load(mapGetenv(nil))
	if err != nil {
		t.Fatal(err)
	}
	if len(c.TrustProxyCIDRs) != 0 {
		t.Fatal("默认不得信任任何代理：否则 XFF 可伪造来源 IP")
	}
}
