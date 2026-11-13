package directory

import (
	"context"
	"strings"
	"testing"
)

// 默认必须拒绝明文绑定：这台实验域控就是"没有 LDAP 证书"的典型情况，
// 若默认放行，客户现场会在毫不知情的情况下明文传域口令。
func TestPlaintextBindRefusedByDefault(t *testing.T) {
	_, err := NewLDAP(context.Background(), LDAPConfig{
		URL:    "ldap://192.0.2.10:389", // TEST-NET-1，不会真的连上
		BaseDN: "DC=example,DC=com",
	})
	if err == nil {
		t.Fatal("未加密且未显式允许时必须拒绝")
	}
	if !strings.Contains(err.Error(), "未加密") {
		t.Fatalf("错误信息应说明原因（便于现场排障），实际: %v", err)
	}
}

// 显式允许后不再因策略被拒（随后会因为连不上而失败，那是网络错误而非策略错误）。
func TestPlaintextBindAllowedWhenExplicit(t *testing.T) {
	_, err := NewLDAP(context.Background(), LDAPConfig{
		URL:                "ldap://192.0.2.10:389",
		BaseDN:             "DC=example,DC=com",
		AllowPlaintextBind: true,
		Timeout:            300_000_000, // 300ms，避免测试等待
	})
	if err == nil {
		t.Fatal("该地址本不可达，应返回连接错误")
	}
	if strings.Contains(err.Error(), "未加密") {
		t.Fatalf("显式允许后不应再报策略错误，实际: %v", err)
	}
}

// ldaps:// 与 StartTLS 都属于加密路径，不该被策略拦截。
// 这里只验证"不会报策略错误"，连接失败是预期（地址不可达）。
func TestEncryptedModesNotBlockedByPolicy(t *testing.T) {
	cases := []LDAPConfig{
		{URL: "ldaps://192.0.2.10:636", BaseDN: "DC=example,DC=com", InsecureSkipVerify: true, Timeout: 300_000_000},
		{URL: "ldap://192.0.2.10:389", BaseDN: "DC=example,DC=com", StartTLS: true, InsecureSkipVerify: true, Timeout: 300_000_000},
	}
	for _, cfg := range cases {
		_, err := NewLDAP(context.Background(), cfg)
		if err != nil && strings.Contains(err.Error(), "未加密") {
			t.Fatalf("%s 不应被明文策略拦截: %v", cfg.URL, err)
		}
	}
}
