package directory

import (
	"errors"
	"fmt"
	"testing"

	"github.com/go-ldap/ldap/v3"
)

// AD 把"口令错 / 已锁定 / 口令过期 / 必须改密"都放在 ResultCode 49 的
// diagnosticMessage 里（形如 "data 775"）。不解析它，用户就只会看到
// "口令错误"，然后一直重试到账号被锁死——这是现场最常见的无效工单。
func TestClassifyBindError(t *testing.T) {
	mk := func(code uint16, msg string) error {
		return &ldap.Error{ResultCode: code, Err: fmt.Errorf("%s", msg)}
	}
	const adPrefix = "80090308: LdapErr: DSID-0C09044E, comment: AcceptSecurityContext error, "

	cases := []struct {
		name string
		err  error
		want error
	}{
		{"锁定 775", mk(49, adPrefix+"data 775, v4563"), ErrAccountLocked},
		{"口令过期 532", mk(49, adPrefix+"data 532, v4563"), ErrPasswordExpired},
		{"必须改密 773", mk(49, adPrefix+"data 773, v4563"), ErrPasswordMustChange},
		{"账号禁用 533", mk(49, adPrefix+"data 533, v4563"), ErrAccountDisabled},
		{"账号过期 701", mk(49, adPrefix+"data 701, v4563"), ErrAccountDisabled},
		{"口令错误 52e", mk(49, adPrefix+"data 52e, v4563"), ErrInvalidCredentials},
		{"无子码", mk(49, "invalid credentials"), ErrInvalidCredentials},
		{"服务不可用", mk(81, "server down"), ErrDirectoryUnavailable},
		{"非 LDAP 错误", errors.New("dial tcp: i/o timeout"), ErrDirectoryUnavailable},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := classifyBindError(c.err)
			if !errors.Is(got, c.want) {
				t.Fatalf("classify = %v, want %v", got, c.want)
			}
		})
	}
}

// 链路问题不能被说成"口令错误"：否则运维会去查密码，方向完全错。
func TestClassifyBindErrorKeepsCauseForUnavailable(t *testing.T) {
	err := classifyBindError(&ldap.Error{ResultCode: 91, Err: fmt.Errorf("connect error")})
	if !errors.Is(err, ErrDirectoryUnavailable) {
		t.Fatalf("应为目录不可用，实际 %v", err)
	}
	if err.Error() == ErrDirectoryUnavailable.Error() {
		t.Fatal("应保留原始错误，便于排障")
	}
}
