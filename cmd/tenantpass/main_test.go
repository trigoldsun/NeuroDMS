package main

import (
	"strings"
	"testing"
	"time"
)

// pickTarget 决定"重置谁的口令"。判错的代价很具体：重置了一个停用账号，
// 运维以为修好了，客户仍然登不进去。

func active(username string) adminRow {
	return adminRow{ID: username, Username: username, DisplayName: username, Status: "active"}
}

func TestPickTargetSingleUsable(t *testing.T) {
	a := active("admin")
	got, err := pickTarget([]adminRow{a}, "")
	if err != nil || got.Username != "admin" {
		t.Fatalf("唯一可用管理员应被选中，得到 %v / %v", got.Username, err)
	}
}

func TestPickTargetSkipsDisabled(t *testing.T) {
	susp := active("old")
	susp.Status = "suspended"
	got, err := pickTarget([]adminRow{susp, active("admin")}, "")
	if err != nil || got.Username != "admin" {
		t.Fatalf("应跳过停用账号，得到 %v / %v", got.Username, err)
	}
}

func TestPickTargetSkipsExpired(t *testing.T) {
	past := active("expired")
	t0 := time.Now().Add(-24 * time.Hour)
	past.ExpiresAt = &t0
	got, err := pickTarget([]adminRow{past, active("admin")}, "")
	if err != nil || got.Username != "admin" {
		t.Fatalf("应跳过已过期账号，得到 %v / %v", got.Username, err)
	}
}

func TestPickTargetAmbiguous(t *testing.T) {
	_, err := pickTarget([]adminRow{active("a"), active("b")}, "")
	if err == nil || !strings.Contains(err.Error(), "多个") {
		t.Fatalf("多个可用管理员时应要求 -user，得到 %v", err)
	}
}

func TestPickTargetNoneUsable(t *testing.T) {
	s := active("only")
	s.Status = "suspended"
	if _, err := pickTarget([]adminRow{s}, ""); err == nil {
		t.Fatal("没有可用管理员时应报错，否则重置了也登不进去")
	}
}

func TestPickTargetExplicitUser(t *testing.T) {
	got, err := pickTarget([]adminRow{active("a"), active("b")}, "b")
	if err != nil || got.Username != "b" {
		t.Fatalf("-user 应精确命中，得到 %v / %v", got.Username, err)
	}
}

func TestPickTargetExplicitDisabled(t *testing.T) {
	s := active("a")
	s.Status = "suspended"
	if _, err := pickTarget([]adminRow{s}, "a"); err == nil {
		t.Fatal("显式指定的账号不可登录时也应拒绝：重置了也进不去")
	}
}

func TestPickTargetExplicitNotAdmin(t *testing.T) {
	if _, err := pickTarget([]adminRow{active("a")}, "nobody"); err == nil {
		t.Fatal("指定的账号不在管理员清单里应报错")
	}
}

// randomPassword：长度、字符集（去掉了易混字符）、以及"两次不一样"。
func TestRandomPassword(t *testing.T) {
	p1, err := randomPassword(20)
	if err != nil {
		t.Fatal(err)
	}
	if len(p1) != 20 {
		t.Fatalf("长度应为 20，得到 %d", len(p1))
	}
	for _, c := range p1 {
		if !strings.ContainsRune(pwAlphabet, c) {
			t.Fatalf("出现字符集外的字符 %q", c)
		}
		if strings.ContainsRune("0O1lI", c) {
			t.Fatalf("不应包含易混字符 %q（要靠人工抄写）", c)
		}
	}
	p2, _ := randomPassword(20)
	if p1 == p2 {
		t.Fatal("两次生成的口令不应相同")
	}
}
