package edition

// 档位判定的单元测试。
//
// 这里覆盖的都是"错了会静默放行"的分支：脏档位、刚到期、到期宽限、
// 以及"租户把策略调得比档位还大"的情况。

import (
	"testing"
	"time"
)

func at(y int, m time.Month, d int) time.Time {
	return time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
}

func TestResolveEditions(t *testing.T) {
	now := at(2026, 11, 11)
	cases := []struct {
		in    string
		want  Edition
		class bool
	}{
		{"basic", Basic, false},
		{"professional", Professional, true},
		{"business", Business, true},
		{"  BUSINESS ", Business, true},
		{"enterprise", Basic, false}, // 未知档位收敛到 basic，不报错
		{"", Basic, false},
	}
	for _, c := range cases {
		st := Resolve(c.in, nil, now)
		if st.Edition != c.want {
			t.Fatalf("%q 应解析为 %s，实际 %s", c.in, c.want, st.Edition)
		}
		if st.Spec.Classification != c.class {
			t.Fatalf("%s 的密级能力应为 %v", st.Edition, c.class)
		}
	}
}

func TestResolveExpiry(t *testing.T) {
	now := at(2026, 11, 11)

	// 未到期
	future := now.Add(24 * time.Hour)
	if st := Resolve("professional", &future, now); st.InGrace || st.Expired || st.Edition != Professional {
		t.Fatalf("未到期应保持专业版，实际 grace=%v expired=%v ed=%s", st.InGrace, st.Expired, st.Edition)
	}

	// 刚到期：30 天宽限内仍按原档位
	justExpired := now.Add(-time.Hour)
	st := Resolve("professional", &justExpired, now)
	if !st.InGrace || st.Expired || st.Edition != Professional {
		t.Fatalf("宽限期内应按原档位运行，实际 grace=%v expired=%v ed=%s", st.InGrace, st.Expired, st.Edition)
	}

	// 宽限期结束：降为基础版，但保留声明的档位用于解释原因
	before := now.AddDate(0, 0, -(GraceDays + 1))
	st = Resolve("professional", &before, now)
	if !st.Expired || st.Edition != Basic || st.Declared != Professional {
		t.Fatalf("过宽限应降为基础版并保留声明值，实际 expired=%v ed=%s declared=%s",
			st.Expired, st.Edition, st.Declared)
	}
	if st.Spec.Classification {
		t.Fatal("降级后不应保留密级能力")
	}
}

func TestCanWriteClass(t *testing.T) {
	now := at(2026, 11, 11)

	basic := Resolve("basic", nil, now)
	if !basic.CanWriteClass(0) {
		t.Fatal("基础版必须允许写 0：上传不带密级时就是 0，否则连文件都传不上去")
	}
	for lv := 1; lv <= 6; lv++ {
		if basic.CanWriteClass(lv) {
			t.Fatalf("基础版不应允许密级 %d", lv)
		}
	}

	pro := Resolve("professional", nil, now)
	for _, lv := range []int{0, 3, 4} {
		if !pro.CanWriteClass(lv) {
			t.Fatalf("专业版应允许 %d", lv)
		}
	}
	for _, lv := range []int{1, 2, 5, 6} {
		if pro.CanWriteClass(lv) {
			t.Fatalf("专业版不应允许 %d", lv)
		}
	}

	biz := Resolve("business", nil, now)
	for lv := 0; lv <= 6; lv++ {
		if !biz.CanWriteClass(lv) {
			t.Fatalf("商业版应允许 %d", lv)
		}
	}
	if biz.CanWriteClass(7) || biz.CanWriteClass(-1) {
		t.Fatal("越界密级必须拒绝")
	}
}

func TestEffectiveLimitsNeverExceedEdition(t *testing.T) {
	now := at(2026, 11, 11)

	basic := Resolve("basic", nil, now)
	// 策略写得比档位大，也只能拿到档位的上限——
	// 否则改一个租户配置就等于免费升级。
	if got := basic.EffectiveVersionKeep(50); got != 3 {
		t.Fatalf("基础版版本保留上限应为 3，实际 %d", got)
	}
	if got := basic.EffectiveMaxUploadMB(10000); got != 1024 {
		t.Fatalf("基础版单文件上限应为 1024MB，实际 %d", got)
	}
	// 策略更严时以策略为准
	if got := basic.EffectiveVersionKeep(1); got != 1 {
		t.Fatalf("策略更严时应取 1，实际 %d", got)
	}

	biz := Resolve("business", nil, now)
	if got := biz.EffectiveVersionKeep(0); got != 50 {
		t.Fatalf("商业版默认保留 50，实际 %d", got)
	}
	if got := biz.EffectiveMaxUploadMB(0); got != 10240 {
		t.Fatalf("商业版单文件上限 10240MB，实际 %d", got)
	}
}
