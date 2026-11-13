package auth

import (
	"errors"
	"testing"
)

// 登录方式解析必须严格：认不出的值不能被"当成默认值"放过去，
// 否则前端拼错一个词，用户就会被按错误的身份去校验口令。
func TestParseLoginMode(t *testing.T) {
	ok := map[string]LoginMode{
		"":        LoginAuto,
		"auto":    LoginAuto,
		"local":   LoginLocal,
		"LOCAL":   LoginLocal,
		" domain": LoginDomain,
	}
	for raw, want := range ok {
		got, err := ParseLoginMode(raw)
		if err != nil || got != want {
			t.Errorf("ParseLoginMode(%q) = %q,%v want %q", raw, got, err, want)
		}
	}
	if _, err := ParseLoginMode("ldap2"); !errors.Is(err, ErrUnknownLoginMode) {
		t.Fatalf("未知方式应报错，实际 %v", err)
	}
}

// 每一种"再试也没用"的失败都必须带下一步提示，
// 否则用户只能反复重试或来问客服。
func TestHintCoversActionableErrors(t *testing.T) {
	cases := map[error]string{
		ErrDomainNotSynced:        "同步",
		ErrDirectoryNotConfigured: "本地账号",
		ErrDomainUnavailable:      "稍后重试",
		ErrDomainLocked:           "解锁",
		ErrDomainPasswordExpired:  "Ctrl+Alt+Del",
		ErrDomainPasswordMustChg:  "更改密码",
		ErrDomainDisabledInDir:    "IT",
		ErrAccountLocked:          "锁定",
		ErrAccountDisabled:        "管理员",
	}
	for err, keyword := range cases {
		h := Hint(err)
		if h == "" {
			t.Errorf("%v 缺少提示", err)
			continue
		}
		if !containsAny(h, keyword) {
			t.Errorf("%v 的提示应提到 %q，实际 %q", err, keyword, h)
		}
	}
	// 口令错误没有固定提示：由前端按当前登录方式给出针对性建议
	if Hint(ErrInvalidCredentials) != "" {
		t.Error("凭据错误不应由服务端固定提示")
	}
}

func containsAny(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

// 只有"口令输错"才计入失败次数。
// 目录不可达/口令过期如果也计数，一次域控维护就会把全员锁在本系统里。
func TestCountsAsFailure(t *testing.T) {
	yes := []error{ErrInvalidCredentials, ErrPasswordMismatch}
	no := []error{ErrDomainUnavailable, ErrDomainPasswordExpired, ErrDomainLocked,
		ErrDomainNotSynced, ErrDirectoryNotConfigured, ErrDomainPasswordMustChg, ErrDomainDisabledInDir}
	for _, e := range yes {
		if !countsAsFailure(e) {
			t.Errorf("%v 应计入失败次数", e)
		}
	}
	for _, e := range no {
		if countsAsFailure(e) {
			t.Errorf("%v 不应计入失败次数（否则外部故障会放大成本系统的锁定）", e)
		}
	}
}
