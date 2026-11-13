package feature

import (
	"testing"
)

// 求值顺序是本包唯一的业务规则，必须逐条钉住。
func TestEvalOrder(t *testing.T) {
	code := "share.external"
	tenant := "11111111-2222-3333-4444-555555555555"

	cases := []struct {
		name string
		def  Def
		want bool
	}{
		// 总开关关闭：无论放量多少都不开
		{"总开关关闭-放量100", Def{Code: code, Default: false, Rollout: 100}, false},
		{"总开关关闭-放量50", Def{Code: code, Default: false, Rollout: 50}, false},
		// 总开关打开但放量为 0：仍然关闭（这是"已发布但未放量"的形态）
		{"总开关打开-放量0", Def{Code: code, Default: true, Rollout: 0}, false},
		{"总开关打开-放量100", Def{Code: code, Default: true, Rollout: 100}, true},
	}
	for _, c := range cases {
		if got := eval(c.def, tenant); got != c.want {
			t.Fatalf("%s: 期望 %v，实际 %v", c.name, c.want, got)
		}
	}
}

// 同一租户必须永远落在同一桶：否则用户会看到功能忽有忽无。
func TestBucketIsStable(t *testing.T) {
	tenant := "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	first := bucket(tenant, "share.external")
	for i := 0; i < 100; i++ {
		if got := bucket(tenant, "share.external"); got != first {
			t.Fatalf("桶值不稳定：%d != %d", got, first)
		}
	}
	if first < 0 || first >= 100 {
		t.Fatalf("桶值越界：%d", first)
	}
	// 不同开关给不同桶，避免"一个租户同时中所有灰度"
	if bucket(tenant, "share.external") == bucket(tenant, "media.transcode") {
		t.Log("提示：两个开关命中同一桶（概率 1%，不视为失败）")
	}
}

// 放量比例应当近似真实：用来发现"分桶实现退化成恒定值"的问题。
func TestBucketDistribution(t *testing.T) {
	const n = 2000
	const rollout = 30
	var hit int
	for i := 0; i < n; i++ {
		tenant := "tenant-" + itoa(i)
		if eval(Def{Code: "share.external", Default: true, Rollout: rollout}, tenant) {
			hit++
		}
	}
	// 允许 ±5 个百分点
	low, high := n*rollout/100-n*5/100, n*rollout/100+n*5/100
	if hit < low || hit > high {
		t.Fatalf("30%% 放量下命中 %d/%d，超出预期区间 [%d,%d]", hit, n, low, high)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [12]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

// 来源标注必须能解释"为什么是关的"。
//
// 现场问题：总开关=开启、放量=0%，实际对所有租户关闭，而界面显示"已开启"，
// 平台运营打开控制台找不到任何关闭动作。根因是来源只在 0<rollout<100 时标 rollout，
// rollout=0 被标成 default，于是"平台已暂停"看起来像"平台没动过"。
func TestEvalFlagSourceExplainsPause(t *testing.T) {
	const tenant = "11111111-2222-3333-4444-555555555555"
	paused := Def{Code: "share.external", Description: "对外分享", Default: true, Rollout: 0}

	f := evalFlag(paused, tenant, nil)
	if f.Enabled {
		t.Fatal("放量 0% 必须求值为关闭")
	}
	if f.Source != "rollout" {
		t.Fatalf("放量 0%% 的来源应为 rollout（否则界面无法解释），实际 %s", f.Source)
	}
	if f.DefaultEnabled != true || f.RolloutPercent != 0 {
		t.Fatalf("必须原样返回总开关与放量，供界面解释：%+v", f)
	}

	// 租户覆盖优先于放量，且来源标 override
	on := true
	f2 := evalFlag(paused, tenant, &on)
	if !f2.Enabled || f2.Source != "override" {
		t.Fatalf("覆盖应生效且来源为 override，实际 %+v", f2)
	}
	off := false
	f3 := evalFlag(Def{Code: "share.external", Default: true, Rollout: 100}, tenant, &off)
	if f3.Enabled || f3.Source != "override" {
		t.Fatalf("覆盖关闭应生效，实际 %+v", f3)
	}

	// 满量放量 + 默认开启：来源是 default，界面应显示"跟随平台默认"
	f4 := evalFlag(Def{Code: "share.external", Default: true, Rollout: 100}, tenant, nil)
	if !f4.Enabled || f4.Source != "default" {
		t.Fatalf("满量应为 default/开启，实际 %+v", f4)
	}
}
