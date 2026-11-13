package tenant

import (
	"encoding/json"
	"testing"
)

// 保留期是"删除"的参数：解析错一次就等于删错一批日志，因此边界必须钉死。
func TestNormalizeRetention(t *testing.T) {
	cases := []struct{ in, want int }{
		{0, DefaultAuditRetentionDays},  // 未配置 → 2 年
		{-1, DefaultAuditRetentionDays}, // 脏数据按默认处理
		{1, MinAuditRetentionDays},      // 过短夹到下界
		{29, MinAuditRetentionDays},     // 下界内侧仍越界
		{30, 30},                        // 下界本身合法
		{730, 730},                      // 2 年
		{3650, 3650},                    // 上界本身合法
		{3651, MaxAuditRetentionDays},   // 超界夹到上界
		{99999, MaxAuditRetentionDays},  // 明显错误值
	}
	for _, c := range cases {
		if got := NormalizeRetention(c.in); got != c.want {
			t.Errorf("NormalizeRetention(%d) = %d, want %d", c.in, got, c.want)
		}
	}
}

// 老配置（没有 auditRetentionDays 字段）必须能正常解析，且落到默认 2 年。
// 若这里报错，升级当天所有租户的策略读取都会失败。
func TestPolicyBackwardCompatible(t *testing.T) {
	var p Policy
	if err := json.Unmarshal([]byte(`{"shareDefaultExpireDays":7,"maxUploadMB":100}`), &p); err != nil {
		t.Fatalf("旧策略无法解析: %v", err)
	}
	if p.ShareDefaultExpireDays != 7 || p.MaxUploadMB != 100 {
		t.Fatalf("旧字段被破坏: %+v", p)
	}
	if NormalizeRetention(p.AuditRetentionDays) != DefaultAuditRetentionDays {
		t.Fatalf("缺省保留期应为 %d 天", DefaultAuditRetentionDays)
	}
}
