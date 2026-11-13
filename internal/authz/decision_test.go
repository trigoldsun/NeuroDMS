package authz

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"
)

// fakeSource 是可控的规则来源，用于验证判定顺序与 fail-closed 行为。
type fakeSource struct {
	aces []ACE
	err  error
	got  *Object
}

func (f *fakeSource) Load(_ context.Context, _ Subject, obj Object) ([]ACE, error) {
	f.got = &obj
	if f.err != nil {
		return nil, f.err
	}
	return f.aces, nil
}

func baseSubject() Subject {
	return Subject{
		ID:         "u1",
		TenantID:   "t1",
		Active:     true,
		Epoch:      3,
		TokenEpoch: 3,
		Class:      1,
		Ceiling:    PresetEditor.Level(),
		DeptPaths:  []string{"d.sales"},
		RoleIDs:    []string{"r_staff"},
	}
}

func baseObject() Object {
	return Object{ID: "n1", TenantID: "t1", Type: "node", Class: 0}
}

func ace(t *testing.T, stype, sid string, allow, deny Bit, depth int, conds ...Condition) ACE {
	t.Helper()
	return ACE{SubjectType: stype, SubjectID: sid, Allow: allow, Deny: deny, Depth: depth, Conditions: conds, ID: "ace-" + sid + "-" + itoa(depth)}
}

func TestAuthorizeOrder(t *testing.T) {
	now := time.Now()

	t.Run("正常放行并归一化", func(t *testing.T) {
		src := &fakeSource{aces: []ACE{ace(t, "user", "u1", Download, 0, 0)}}
		d, err := Authorize(context.Background(), src, baseSubject(), baseObject(), Download, now)
		if err != nil || !d.Allowed {
			t.Fatalf("应放行: %v %s", err, d.Reason)
		}
		if !d.Bits.Has(Preview) || !d.Bits.Has(Display) {
			t.Fatalf("结果应补齐蕴含位，实际 %v", d.Bits.Names())
		}
	})

	t.Run("租户不匹配", func(t *testing.T) {
		obj := baseObject()
		obj.TenantID = "t2"
		src := &fakeSource{aces: []ACE{ace(t, "user", "u1", AllBits, 0, 0)}}
		d, _ := Authorize(context.Background(), src, baseSubject(), obj, Download, now)
		if d.Allowed || d.Reason != ReasonTenantMismatch {
			t.Fatalf("应因租户不匹配而拒，实际 %s", d.Reason)
		}
	})

	t.Run("会话已吊销", func(t *testing.T) {
		sub := baseSubject()
		sub.TokenEpoch = 2 // 与 Epoch 不一致
		src := &fakeSource{aces: []ACE{ace(t, "user", "u1", AllBits, 0, 0)}}
		d, _ := Authorize(context.Background(), src, sub, baseObject(), Download, now)
		if d.Allowed || d.Reason != ReasonSessionInvalid {
			t.Fatalf("应拒，实际 %s", d.Reason)
		}
	})

	t.Run("对象已删除按不存在处理", func(t *testing.T) {
		obj := baseObject()
		obj.Deleted = true
		src := &fakeSource{aces: []ACE{ace(t, "user", "u1", AllBits, 0, 0)}}
		d, _ := Authorize(context.Background(), src, baseSubject(), obj, Download, now)
		if d.Allowed || d.Reason != ReasonNotFound {
			t.Fatalf("应拒，实际 %s", d.Reason)
		}
	})
}

func TestClassificationGateBeatsOwner(t *testing.T) {
	obj := baseObject()
	obj.Class = 2 // 文件为"秘密"
	sub := baseSubject()
	sub.Class = 1 // 用户为"内部"
	src := &fakeSource{aces: []ACE{ace(t, "user", "u1", AllBits, 0, 0)}}

	d, _ := Authorize(context.Background(), src, sub, obj, Preview, time.Now())
	if d.Allowed || d.Reason != ReasonClassification {
		t.Fatalf("密级不足时即使 ACL 全开也必须拒，实际 %s", d.Reason)
	}
}

func TestDenyBeatsDeeperAllow(t *testing.T) {
	now := time.Now()
	src := &fakeSource{aces: []ACE{
		ace(t, "role", "r_staff", AllBits, 0, 0),
		ace(t, "user", "u1", Download, Download, 3),
	}}
	d, _ := Authorize(context.Background(), src, baseSubject(), baseObject(), Download, now)
	if d.Allowed || d.Reason != ReasonExplicitDeny {
		t.Fatalf("拒绝必须优先且不被更深层允许覆盖，实际 %s", d.Reason)
	}
}

func TestNearestExplicitAmongAllows(t *testing.T) {
	now := time.Now()
	sub := baseSubject()
	sub.GroupIDs = []string{"g_proj"}
	src := &fakeSource{aces: []ACE{
		ace(t, "role", "r_staff", Display, 0, 0),
		ace(t, "group", "g_proj", Preview, 0, 2),
	}}
	d, _ := Authorize(context.Background(), src, sub, baseObject(), Preview, now)
	if !d.Allowed {
		t.Fatalf("深层组授权应生效，实际 %s", d.Reason)
	}
}

func TestDeepAceNotMentioningBitDoesNotBlock(t *testing.T) {
	now := time.Now()
	sub := baseSubject()
	sub.GroupIDs = []string{"g_proj"}
	src := &fakeSource{aces: []ACE{
		ace(t, "role", "r_staff", Download, 0, 0),
		ace(t, "group", "g_proj", Edit, 0, 2), // 深层 ACE 只提 edit，未提及 download
	}}
	d, _ := Authorize(context.Background(), src, sub, baseObject(), Download, now)
	if !d.Allowed {
		t.Fatalf("未提及该位的深层 ACE 不应阻断，实际 %s", d.Reason)
	}
}

func TestNoAllow(t *testing.T) {
	src := &fakeSource{aces: []ACE{ace(t, "role", "r_other", AllBits, 0, 0)}}
	d, _ := Authorize(context.Background(), src, baseSubject(), baseObject(), Download, time.Now())
	if d.Allowed || d.Reason != ReasonNoAllow {
		t.Fatalf("无匹配 ACE 应拒，实际 %s", d.Reason)
	}
}

// ceiling 不参与动作判定：即使封顶为查看者，只要 ACL 给了 download 就可下载。
// 这条用例是对"封顶语义只作用于授权"的反向确认。
func TestCeilingDoesNotBlockOwnActions(t *testing.T) {
	sub := baseSubject()
	sub.Ceiling = PresetViewer.Level()
	src := &fakeSource{aces: []ACE{ace(t, "user", "u1", AllBits, 0, 0)}}
	d, _ := Authorize(context.Background(), src, sub, baseObject(), Download, time.Now())
	if !d.Allowed {
		t.Fatalf("ACL 有授权就应允许，实际 %s", d.Reason)
	}
}

func TestConditions(t *testing.T) {
	now := time.Now()
	sub := baseSubject()
	sub.IP = netip.MustParseAddr("10.1.2.3")
	sub.TrustedDevice = false
	sub.DownloadsToday = 5

	cases := []struct {
		name string
		cond Condition
		want bool
	}{
		{"IP 命中", Condition{Key: "ip_cidr", Op: "in", Value: []any{"10.0.0.0/8"}}, true},
		{"IP 未命中", Condition{Key: "ip_cidr", Op: "in", Value: []any{"203.0.113.0/24"}}, false},
		{"可信设备为假", Condition{Key: "device_trust", Op: "eq", Value: true}, false},
		{"配额未超", Condition{Key: "download_quota", Op: "lte", Value: 10}, true},
		{"配额已超", Condition{Key: "download_quota", Op: "lte", Value: 5}, false},
		{"未知条件键必须拒绝", Condition{Key: "geo_fence", Op: "eq", Value: "CN"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			src := &fakeSource{aces: []ACE{ace(t, "user", "u1", Download, 0, 0, c.cond)}}
			d, _ := Authorize(context.Background(), src, sub, baseObject(), Download, now)
			if d.Allowed != c.want {
				t.Fatalf("期望 allowed=%v，实际 %v（%s）", c.want, d.Allowed, d.Reason)
			}
		})
	}
}

func TestLoadErrorIsFailClosed(t *testing.T) {
	src := &fakeSource{err: errors.New("db timeout")}
	d, err := Authorize(context.Background(), src, baseSubject(), baseObject(), Download, time.Now())
	if err == nil {
		t.Fatal("应把底层错误向上返回，不可吞掉")
	}
	if d.Allowed {
		t.Fatal("规则加载失败必须判拒（0201-C3 的同构缺陷）")
	}
	if d.Reason != ReasonACLLoadError {
		t.Fatalf("原因应为 %s，实际 %s", ReasonACLLoadError, d.Reason)
	}
}

func TestExpiredACESkipped(t *testing.T) {
	past := time.Now().Add(-time.Hour)
	a := ace(t, "user", "u1", Download, 0, 0)
	a.ExpiresAt = &past
	src := &fakeSource{aces: []ACE{a}}
	d, _ := Authorize(context.Background(), src, baseSubject(), baseObject(), Download, time.Now())
	if d.Allowed {
		t.Fatal("到期授权不应生效")
	}
}

func TestInvalidActionRejected(t *testing.T) {
	src := &fakeSource{aces: []ACE{ace(t, "user", "u1", AllBits, 0, 0)}}
	d, err := Authorize(context.Background(), src, baseSubject(), baseObject(), Download|Preview, time.Now())
	if err == nil {
		t.Fatal("多位动作应报错")
	}
	if d.Allowed {
		t.Fatal("非法动作必须判拒")
	}
}
func TestACLOverridesCeilingForOwnActions(t *testing.T) {
	sub := baseSubject() // ceiling = editor（仅影响授出，不影响动作）
	src := &fakeSource{aces: []ACE{ace(t, "user", "u1", AllBits, 0, 0)}}

	if d, _ := Authorize(context.Background(), src, sub, baseObject(), Delete, time.Now()); !d.Allowed {
		t.Fatalf("ACL 给了 delete 就应允许，实际 %s", d.Reason)
	}
	if d, _ := Authorize(context.Background(), src, sub, baseObject(), ManageACL, time.Now()); !d.Allowed {
		t.Fatalf("ACL 给了 manage_acl 就应允许，实际 %s", d.Reason)
	}
}

func TestDeptPathInheritance(t *testing.T) {
	// 授权在 d.sales 上，成员 dept 路径为 d.sales.team-a，应命中（路径前缀匹配由存储层展开）
	sub := baseSubject()
	sub.DeptPaths = []string{"d.sales", "d.sales.team-a"}
	sub.RoleIDs = nil
	src := &fakeSource{aces: []ACE{ace(t, "dept", "d.sales", Preview, 0, 0)}}
	d, _ := Authorize(context.Background(), src, sub, baseObject(), Preview, time.Now())
	if !d.Allowed {
		t.Fatalf("部门授权应命中，实际 %s", d.Reason)
	}
}
