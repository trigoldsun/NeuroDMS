package directory

import (
	"context"
	"docvault/internal/dbtest"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"docvault/internal/db"
	"docvault/migrations"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func testPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("DOCVAULT_TEST_DSN")
	if dsn == "" {
		t.Skip("未设置 DOCVAULT_TEST_DSN，跳过目录同步测试")
	}
	pool, err := db.Connect(context.Background(), dsn)
	if err != nil {
		t.Fatalf("连接失败: %v", err)
	}
	t.Cleanup(pool.Close)
	if _, err := db.Migrate(context.Background(), pool, migrations.Files); err != nil {
		t.Fatalf("迁移失败: %v", err)
	}
	return pool
}

func seedTenant(t *testing.T, pool *pgxpool.Pool) string {
	t.Helper()
	ctx := context.Background()
	var id string
	if err := pool.QueryRow(ctx,
		`INSERT INTO tenant (id, slug, name) VALUES (gen_random_uuid(), $1,$2) RETURNING id::text`,
		"ldap-"+randomSuffix(t), "目录测试租户").Scan(&id); err != nil {
		t.Fatalf("建租户失败: %v", err)
	}
	t.Cleanup(func() { dbtest.CleanupTenant(t, pool, id) })
	return id
}

func randomSuffix(t *testing.T) string {
	t.Helper()
	return strings.ReplaceAll(time.Now().Format("150405.000000"), ".", "")
}

// fakeDir 是可编程的目录实现，用于覆盖同步逻辑的各个分支。
type fakeDir struct {
	snap     Snapshot
	err      error
	fetched  int
	lastSinc string
}

func (f *fakeDir) Authenticate(_ context.Context, username, password string) (User, error) {
	for _, u := range f.snap.Users {
		if u.Username == username && password == "ok" {
			return u, nil
		}
	}
	return User{}, ErrInvalidCredentials
}

func (f *fakeDir) Fetch(_ context.Context, since string) (Snapshot, error) {
	f.fetched++
	f.lastSinc = since
	if f.err != nil {
		return Snapshot{}, f.err
	}
	return f.snap, nil
}

func (f *fakeDir) Close() error { return nil }

func sampleSnapshot() Snapshot {
	return Snapshot{
		Watermark: "1000",
		Users: []User{
			{ExternalID: "g-1", Username: "alice", Email: "alice@example.com", DisplayName: "Alice",
				DN: "CN=alice,OU=研发,DC=example,DC=com", Dept: "研发"},
			{ExternalID: "g-2", Username: "bob", Email: "bob@example.com", DisplayName: "Bob",
				DN: "CN=bob,OU=研发,DC=example,DC=com", Dept: "研发"},
			{ExternalID: "g-3", Username: "carol", Email: "carol@example.com", DisplayName: "Carol",
				DN: "CN=carol,OU=财务,DC=example,DC=com", Dept: "财务", Disabled: true},
		},
		Groups: []Group{
			// 财务组里含研发组（嵌套），以及一个目录外成员
			{DN: "CN=finance,OU=Groups,DC=example,DC=com", Name: "finance",
				Members: []string{"CN=研发,OU=Groups,DC=example,DC=com", "CN=outsider,DC=example,DC=com"}},
			{DN: "CN=研发,OU=Groups,DC=example,DC=com", Name: "rd",
				Members: []string{"CN=alice,OU=研发,DC=example,DC=com", "CN=bob,OU=研发,DC=example,DC=com"}},
		},
	}
}

func TestSyncCreatesUsersGroupsAndNestedMembers(t *testing.T) {
	pool := testPool(t)
	tenantID := seedTenant(t, pool)
	ctx := context.Background()

	dir := &fakeDir{snap: sampleSnapshot()}
	res, err := Sync(ctx, pool, tenantID, dir, "", Options{DisableMissing: true})
	if err != nil {
		t.Fatalf("同步失败: %v", err)
	}

	if res.Seen != 3 || res.Created != 3 {
		t.Fatalf("应创建 3 个账号，实际 seen=%d created=%d", res.Seen, res.Created)
	}
	if res.GroupsSynced != 2 {
		t.Fatalf("应同步 2 个组，实际 %d", res.GroupsSynced)
	}
	// rd 组直接含 alice/bob（2 条），finance 组通过嵌套也含 alice/bob（2 条）= 4 条。
	// outsider 不在本地账号里，必须被跳过——否则会给不存在的用户建关系。
	if res.MembersLinked != 4 {
		t.Fatalf("应关联 4 条组关系（含嵌套展开与去重），实际 %d", res.MembersLinked)
	}

	var status string
	if err := pool.QueryRow(ctx,
		`SELECT status FROM app_user WHERE tenant_id=$1 AND username='carol'`, tenantID).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "suspended" {
		t.Fatalf("目录停用的账号本地应为 suspended，实际 %s", status)
	}

	var memberCount int
	if err := pool.QueryRow(ctx, `
		SELECT count(*) FROM group_member gm
		  JOIN user_group g ON g.id = gm.group_id
		 WHERE gm.tenant_id=$1 AND g.name='finance'`, tenantID).Scan(&memberCount); err != nil {
		t.Fatal(err)
	}
	if memberCount != 2 {
		t.Fatalf("finance 组应有 2 名成员（嵌套展开后），实际 %d", memberCount)
	}

	// 快照记录必须落库
	var syncs int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM directory_sync WHERE tenant_id=$1 AND status='ok'`, tenantID).Scan(&syncs); err != nil {
		t.Fatal(err)
	}
	if syncs != 1 {
		t.Fatalf("应记录 1 次成功同步，实际 %d", syncs)
	}
}

func TestSyncIsIdempotent(t *testing.T) {
	pool := testPool(t)
	tenantID := seedTenant(t, pool)
	ctx := context.Background()
	dir := &fakeDir{snap: sampleSnapshot()}

	if _, err := Sync(ctx, pool, tenantID, dir, "", Options{}); err != nil {
		t.Fatal(err)
	}
	res, err := Sync(ctx, pool, tenantID, dir, "", Options{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Created != 0 {
		t.Fatalf("第二次同步不应再创建账号，实际 %d", res.Created)
	}
	if res.Updated != 3 {
		t.Fatalf("第二次应全部走更新分支，实际 %d", res.Updated)
	}
	var count int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM app_user WHERE tenant_id=$1 AND source='ldap'`, tenantID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 3 {
		t.Fatalf("账号不应重复，实际 %d 条", count)
	}
}

func TestSyncDisablesMissingUsersAndRevokesSessions(t *testing.T) {
	pool := testPool(t)
	tenantID := seedTenant(t, pool)
	ctx := context.Background()

	dir := &fakeDir{snap: sampleSnapshot()}
	if _, err := Sync(ctx, pool, tenantID, dir, "", Options{DisableMissing: true}); err != nil {
		t.Fatal(err)
	}

	// 给 alice 建一个会话，验证离职回收时会一起吊销
	var aliceID string
	if err := pool.QueryRow(ctx,
		`SELECT id::text FROM app_user WHERE tenant_id=$1 AND username='alice'`, tenantID).Scan(&aliceID); err != nil {
		t.Fatal(err)
	}
	if err := db.WithTenant(ctx, pool, tenantID, func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `
			INSERT INTO session (id, tenant_id, user_id, refresh_hash, epoch, expires_at)
			VALUES (gen_random_uuid(), $1, $2, '\\x00'::bytea, 1, now() + interval '1 day')`,
			tenantID, aliceID)
		return e
	}); err != nil {
		t.Fatal(err)
	}

	// alice 从目录消失
	shrunk := sampleSnapshot()
	shrunk.Users = shrunk.Users[1:] // 只留 bob 与 carol
	dir.snap = shrunk

	res, err := Sync(ctx, pool, tenantID, dir, "", Options{DisableMissing: true})
	if err != nil {
		t.Fatal(err)
	}
	if res.Disabled < 1 {
		t.Fatalf("应停用至少 1 个离职账号，实际 %d", res.Disabled)
	}

	var status string
	if err := pool.QueryRow(ctx, `SELECT status FROM app_user WHERE id=$1`, aliceID).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "suspended" {
		t.Fatalf("离职账号应停用，实际 %s", status)
	}

	var revoked bool
	if err := pool.QueryRow(ctx, `
		SELECT count(*) > 0 FROM session WHERE tenant_id=$1 AND user_id=$2 AND revoked_at IS NOT NULL`,
		tenantID, aliceID).Scan(&revoked); err != nil {
		t.Fatal(err)
	}
	if !revoked {
		t.Fatal("离职账号的会话必须被吊销，否则停用后令牌仍可用")
	}
}

func TestSyncRestoresOnlyDirectoryDisabledUsers(t *testing.T) {
	pool := testPool(t)
	tenantID := seedTenant(t, pool)
	ctx := context.Background()

	// carol 在目录里恢复
	snap := sampleSnapshot()
	snap.Users[2].Disabled = false
	dir := &fakeDir{snap: snap}

	if _, err := Sync(ctx, pool, tenantID, dir, "", Options{}); err != nil {
		t.Fatal(err)
	}
	var status string
	if err := pool.QueryRow(ctx,
		`SELECT status FROM app_user WHERE tenant_id=$1 AND username='carol'`, tenantID).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "active" {
		t.Fatalf("目录恢复后本地应恢复 active，实际 %s", status)
	}

	// 管理员手工停用的账号不应被同步悄悄放开
	if _, err := pool.Exec(ctx, `
		UPDATE app_user SET status='suspended', directory_disabled=false
		 WHERE tenant_id=$1 AND username='bob'`, tenantID); err != nil {
		t.Fatal(err)
	}
	if _, err := Sync(ctx, pool, tenantID, dir, "", Options{}); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx,
		`SELECT status FROM app_user WHERE tenant_id=$1 AND username='bob'`, tenantID).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "suspended" {
		t.Fatalf("手工停用的账号不应被同步恢复，实际 %s", status)
	}
}

func TestSyncDryRunWritesNothing(t *testing.T) {
	pool := testPool(t)
	tenantID := seedTenant(t, pool)
	ctx := context.Background()
	dir := &fakeDir{snap: sampleSnapshot()}

	res, err := Sync(ctx, pool, tenantID, dir, "", Options{DryRun: true, DisableMissing: true})
	if err != nil {
		t.Fatal(err)
	}
	if res.Created != 3 {
		t.Fatalf("预演也应给出将要创建的数量，实际 %d", res.Created)
	}
	var count int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM app_user WHERE tenant_id=$1`, tenantID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("预演不应写库，实际 %d 条账号", count)
	}
}

func TestSyncFailureIsRecorded(t *testing.T) {
	pool := testPool(t)
	tenantID := seedTenant(t, pool)
	ctx := context.Background()
	dir := &fakeDir{err: errors.New("目录连接超时")}

	if _, err := Sync(ctx, pool, tenantID, dir, "", Options{}); err == nil {
		t.Fatal("应返回错误")
	}
	var failed int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM directory_sync WHERE tenant_id=$1 AND status='failed'`, tenantID).Scan(&failed); err != nil {
		t.Fatal(err)
	}
	if failed != 1 {
		t.Fatalf("失败必须被记录（否则不可排障），实际 %d 条", failed)
	}
}

// 域内服务账号（krbtgt 等）必须被排除，但 Administrator / Guest 要保留。
func TestCleanUsersExcludesServiceAccounts(t *testing.T) {
	in := []User{
		{ExternalID: "g1", Username: "krbtgt"},
		{ExternalID: "g2", Username: "KRBTGT"}, // 大小写不同也应排除
		{ExternalID: "g3", Username: "DefaultAccount"},
		{ExternalID: "g4", Username: "Administrator"}, // 保留：运维要用
		{ExternalID: "g5", Username: "Guest"},         // 保留：可能是真在用的外部账号
		{ExternalID: "g6", Username: "sunxin"},
	}
	out, skipped := cleanUsers(in, excludeSet(nil))
	if skipped != 3 {
		t.Fatalf("应跳过 3 个服务账号，实际 %d", skipped)
	}
	names := map[string]bool{}
	for _, u := range out {
		names[u.Username] = true
	}
	if len(out) != 3 || !names["Administrator"] || !names["Guest"] || !names["sunxin"] {
		t.Fatalf("保留结果不符: %v", names)
	}

	// 额外排除名单也要生效（客户可能有自己的服务账号）
	out2, _ := cleanUsers(in, excludeSet([]string{"sunxin"}))
	for _, u := range out2 {
		if u.Username == "sunxin" {
			t.Fatal("额外排除名单未生效")
		}
	}
}

func TestCleanUsersDedupesAndSkips(t *testing.T) {
	in := []User{
		{ExternalID: "a", Username: "u1"},
		{ExternalID: "A", Username: "u1-dup"}, // 大小写不同视为同一人
		{ExternalID: "", Username: "no-id"},
		{ExternalID: "b", Username: ""},
	}
	out, skipped := cleanUsers(in, excludeSet(nil))
	if len(out) != 1 || skipped != 3 {
		t.Fatalf("应保留 1 条、跳过 3 条，实际 keep=%d skip=%d", len(out), skipped)
	}
}

func TestExpandGroupsHandlesNestingAndCycles(t *testing.T) {
	groups := []Group{
		{DN: "cn=a", Name: "a", Members: []string{"cn=u1", "cn=b"}},
		{DN: "cn=b", Name: "b", Members: []string{"cn=u2", "cn=c"}},
		{DN: "cn=c", Name: "c", Members: []string{"cn=u3", "cn=a"}}, // 环：a→b→c→a
	}
	out := expandGroups(groups)

	a := out["cn=a"]
	// a 应包含 u1、b 的 u2、c 的 u3；环不得导致重复或死循环
	joined := strings.Join(a, ",")
	for _, want := range []string{"cn=u1", "cn=u2", "cn=u3"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("a 应展开包含 %s，实际 %v", want, a)
		}
	}
	if len(a) != 3 {
		t.Fatalf("去重后应为 3 个成员，实际 %d: %v", len(a), a)
	}
}

func TestHelpers(t *testing.T) {
	if got := hostOf("ldaps://dc1.example.com:636/"); got != "dc1.example.com" {
		t.Fatalf("hostOf 解析错误: %s", got)
	}
	if got := localPart("zhang.san@example.com"); got != "zhang.san" {
		t.Fatalf("localPart 解析错误: %s", got)
	}
	if got := localPart("no-at-sign"); got != "no-at-sign" {
		t.Fatalf("无 @ 时应原样返回: %s", got)
	}
}

// 空口令必须直接拒绝：LDAP 的匿名绑定在不少服务端会"成功"，
// 若不挡住就是完整的认证绕过。
func TestAuthenticateRejectsEmptyPassword(t *testing.T) {
	d := &LDAPDirectory{cfg: LDAPConfig{URL: "ldap://127.0.0.1:1", BaseDN: "dc=x"}}
	if _, err := d.Authenticate(context.Background(), "alice", ""); err != ErrInvalidCredentials {
		t.Fatalf("空口令应直接拒绝，实际 %v", err)
	}
	if _, err := d.Authenticate(context.Background(), "", "pwd"); err != ErrInvalidCredentials {
		t.Fatalf("空用户名应直接拒绝，实际 %v", err)
	}
}
