package auth

import (
	"context"
	"testing"

	"docvault/internal/directory"
)

// fakeDirectory 模拟域控：只有 alice 口令正确。
type fakeDirectory struct {
	calls    int
	failWith error
	disabled bool
}

func (f *fakeDirectory) Authenticate(_ context.Context, _ string, username, password string) (string, bool, error) {
	f.calls++
	if f.failWith != nil {
		return "", false, f.failWith
	}
	if username == "alice" && password == "domain-pass" {
		return "ldap-uid-1", f.disabled, nil
	}
	// 必须返回目录包的标准错误：认证层按 errors.Is 分类，
	// 随便造一个 errors.New 会被归到"域控不可达"，测试就测错了分支。
	return "", false, directory.ErrInvalidCredentials
}

func TestLDAPUserLoginDelegatesToDirectory(t *testing.T) {
	pool := svcPool(t)
	svc := newService(pool)
	dir := &fakeDirectory{}
	svc.SetDirectory(dir)

	slug, username, _, userID := seedUser(t, pool)
	if _, err := pool.Exec(context.Background(), `
		UPDATE app_user SET source='ldap', external_id='ldap-uid-1', password_hash=NULL WHERE id=$1`,
		userID); err != nil {
		t.Fatal(err)
	}

	// 口令由目录校验，不走本地散列
	tk, err := svc.Login(context.Background(), slug, username, "domain-pass", LoginDomain, "", "")
	if err != nil {
		t.Fatalf("域账号登录应成功: %v", err)
	}
	if tk.Access == "" {
		t.Fatal("应签发令牌")
	}
	if dir.calls != 1 {
		t.Fatalf("应调用目录一次，实际 %d", dir.calls)
	}

	// 域口令错误 → 统一凭据错误
	if _, err := svc.Login(context.Background(), slug, username, "wrong", LoginDomain, "", ""); err != ErrInvalidCredentials {
		t.Fatalf("域口令错误应返回凭据错误，实际 %v", err)
	}
}

// 目录里被停用的账号，即使口令正确也不能登录。
func TestLDAPDisabledInDirectoryRejected(t *testing.T) {
	pool := svcPool(t)
	svc := newService(pool)
	svc.SetDirectory(&fakeDirectory{disabled: true})

	slug, username, _, userID := seedUser(t, pool)
	if _, err := pool.Exec(context.Background(), `
		UPDATE app_user SET source='ldap', external_id='ldap-uid-1', password_hash=NULL WHERE id=$1`,
		userID); err != nil {
		t.Fatal(err)
	}

	// 断言具体错误而不是笼统的 ErrAccountDisabled：
	// "目录里被停用" 与 "本地账号被停用" 的处置不同，合并成一个错误会让客服查错方向。
	if _, err := svc.Login(context.Background(), slug, username, "domain-pass", LoginDomain, "", ""); err != ErrDomainDisabledInDir {
		t.Fatalf("目录停用账号应返回 ErrDomainDisabledInDir，实际 %v", err)
	}
}

// 未接目录时，域账号必须拒登而不是退化成"任意口令通过"。
func TestLDAPUserWithoutDirectoryFailsClosed(t *testing.T) {
	pool := svcPool(t)
	svc := newService(pool) // 未 SetDirectory

	slug, username, _, userID := seedUser(t, pool)
	if _, err := pool.Exec(context.Background(), `
		UPDATE app_user SET source='ldap', external_id='x', password_hash=NULL WHERE id=$1`,
		userID); err != nil {
		t.Fatal(err)
	}

	if _, err := svc.Login(context.Background(), slug, username, "anything", LoginDomain, "", ""); err != ErrDirectoryNotConfigured {
		t.Fatalf("未接目录应返回 ErrDirectoryNotConfigured（拒登），实际 %v", err)
	}
}
