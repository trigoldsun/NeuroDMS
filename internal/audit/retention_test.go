package audit

import (
	"testing"
	"time"

	"docvault/internal/tenant"
)

// 截止时间算错一天 = 多删或少删一整天日志，所以直接对着日期断言。
func TestRetentionCutoff(t *testing.T) {
	now := time.Date(2026, 11, 9, 20, 15, 0, 0, time.UTC)

	cases := []struct {
		name string
		days int
		want string
	}{
		{"2 年", 730, "2024-11-09"},
		{"未配置按 2 年", 0, "2024-11-09"},
		{"下界 30 天", 30, "2026-10-10"},
		{"越界值夹到上界", 99999, "2016-11-11"},
	}
	for _, c := range cases {
		got := retentionCutoff(now, c.days).Format("2006-01-02")
		if got != c.want {
			t.Errorf("%s: cutoff = %s, want %s", c.name, got, c.want)
		}
	}

	// 默认值必须真的是"2 年"，否则界面上写的 730 与实际删的范围不一致
	if retentionCutoff(now, 0) != retentionCutoff(now, tenant.DefaultAuditRetentionDays) {
		t.Fatal("未配置时的截止时间应等于默认保留期")
	}
}
