package content

// 历史回退（docs/21）的集成测试。
//
// 这一组用例覆盖的都是"看起来会过、实际会坏"的地方：
//   - 回退后读取路径是否真的取到旧内容（而不是只改了指针）；
//   - 源版本被并发清理后，node.current_version_id 会不会被写成 NULL；
//   - 重复点击回退会不会白占一个版本名额；
//   - 回退会不会顺手把密级降了；
//   - 空间用量是否按 delta 维护（旧实现只有加法）。

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

// restoreFixture 在临时目录里造一个真实的 Store，并给节点追加若干版本。
type restoreFixture struct {
	pool     *pgxpool.Pool
	store    *Store
	tenantID string
	userID   string
	nodeID   string
	spaceID  string
}

// putVersion 写入一个版本的物理内容与数据库记录，返回版本号。
//
// 刻意不走 UploadFile：那条路径会去重、会走分片逻辑，测试里需要精确控制
// "同一个 blob 被两个版本复用"的场景。
func putVersion(t *testing.T, f *restoreFixture, content []byte) int {
	t.Helper()
	ctx := context.Background()

	sum := sha256.Sum256(content)
	key := hex.EncodeToString(sum[:])
	dir := filepath.Join(f.store.root, f.tenantID, key[:2])
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, key), content, 0o640); err != nil {
		t.Fatal(err)
	}

	var blobID string
	// ref_count 初始 0、由 version 触发器 +1。这里若沿用旧的 "+1"，会与触发器
	// 叠加成 2，删版本时永远减不到 0——正是生产代码要移除应用层计数的原因。
	if err := f.pool.QueryRow(ctx, `
		WITH ins AS (
			INSERT INTO blob (id, tenant_id, size_bytes, sha256, storage_key, ref_count)
			VALUES (gen_random_uuid(), $1, $2, $3, $4, 0)
			ON CONFLICT (tenant_id, sha256, size_bytes) DO NOTHING
			RETURNING id::text
		)
		SELECT id::text FROM ins
		UNION ALL
		SELECT id::text FROM blob
		 WHERE tenant_id = $1 AND sha256 = $3 AND size_bytes = $2
		LIMIT 1`, f.tenantID, len(content), sum[:], key).Scan(&blobID); err != nil {
		t.Fatal(err)
	}

	var no int
	if err := f.pool.QueryRow(ctx, `
		INSERT INTO version (id, tenant_id, node_id, version_no, blob_id, size_bytes, sha256, created_by)
		VALUES (gen_random_uuid(), $1, $2,
		        (SELECT COALESCE(max(version_no),0)+1 FROM version WHERE node_id = $2),
		        $3, $4, $5, $6)
		RETURNING version_no`,
		f.tenantID, f.nodeID, blobID, len(content), sum[:], f.userID).Scan(&no); err != nil {
		t.Fatal(err)
	}
	if _, err := f.pool.Exec(ctx, `
		UPDATE node SET current_version_id = (SELECT id FROM version WHERE node_id=$1 AND version_no=$2),
		                size_bytes = $3
		 WHERE id = $1`, f.nodeID, no, len(content)); err != nil {
		t.Fatal(err)
	}
	return no
}

func newRestoreFixture(t *testing.T) *restoreFixture {
	t.Helper()
	pool, tenantID, userID, nodeID := seedNode(t)
	ctx := context.Background()

	root := t.TempDir()
	store, err := New(pool, root)
	if err != nil {
		t.Fatal(err)
	}
	var spaceID string
	if err := pool.QueryRow(ctx, `SELECT space_id::text FROM node WHERE id = $1`, nodeID).Scan(&spaceID); err != nil {
		t.Fatal(err)
	}
	return &restoreFixture{
		pool: pool, store: store,
		tenantID: tenantID, userID: userID, nodeID: nodeID, spaceID: spaceID,
	}
}

func (f *restoreFixture) currentSize(t *testing.T) int64 {
	t.Helper()
	var n int64
	if err := f.pool.QueryRow(context.Background(),
		`SELECT size_bytes FROM node WHERE id = $1`, f.nodeID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func (f *restoreFixture) readCurrent(t *testing.T) string {
	t.Helper()
	rc, _, err := f.store.OpenContent(context.Background(), f.tenantID, f.nodeID)
	if err != nil {
		t.Fatalf("打开内容失败: %v", err)
	}
	defer rc.Close()
	b, err := io.ReadAll(rc)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// 回退的核心断言：内容真的变了、新版本被追加、来源被记录、密级没动。
func TestRestoreCreatesNewVersionAndSwitchesContent(t *testing.T) {
	f := newRestoreFixture(t)
	ctx := context.Background()

	v1 := putVersion(t, f, []byte("AAA"))
	v2 := putVersion(t, f, []byte("BBBBB"))
	if v2 != v1+1 {
		t.Fatalf("版本号应连续，得到 v%d 与 v%d", v1, v2)
	}
	if got := f.readCurrent(t); got != "BBBBB" {
		t.Fatalf("回退前内容应为 BBBBB，实际 %q", got)
	}

	// 顺手把密级抬到 4（机密），用来验证回退不会把它带回去
	if _, err := f.pool.Exec(ctx, `UPDATE node SET classification = 4 WHERE id = $1`, f.nodeID); err != nil {
		t.Fatal(err)
	}

	res, err := f.store.RestoreVersion(ctx, f.tenantID, f.nodeID, v1, f.userID)
	if err != nil {
		t.Fatalf("回退失败: %v", err)
	}
	if res.VersionNo != v2+1 {
		t.Fatalf("应追加 v%d，实际 v%d", v2+1, res.VersionNo)
	}
	if res.FromVersionNo != v1 {
		t.Fatalf("来源版本号应为 %d，实际 %d", v1, res.FromVersionNo)
	}

	// 读取路径必须真的取到旧内容——这是整个功能的意义
	if got := f.readCurrent(t); got != "AAA" {
		t.Fatalf("回退后内容应为 AAA，实际 %q", got)
	}
	if got := f.currentSize(t); got != 3 {
		t.Fatalf("node.size_bytes 应变为 3，实际 %d", got)
	}

	var origin string
	var fromNo *int
	var state string
	if err := f.pool.QueryRow(ctx,
		`SELECT origin, restored_from_no, state FROM version WHERE node_id=$1 AND version_no=$2`,
		f.nodeID, res.VersionNo).Scan(&origin, &fromNo, &state); err != nil {
		t.Fatal(err)
	}
	if origin != "restore" || fromNo == nil || *fromNo != v1 || state != "effective" {
		t.Fatalf("新版本元数据不对: origin=%s fromNo=%v state=%s", origin, fromNo, state)
	}

	// 密级不随内容回退
	var cls int
	if err := f.pool.QueryRow(ctx, `SELECT classification FROM node WHERE id=$1`, f.nodeID).Scan(&cls); err != nil {
		t.Fatal(err)
	}
	if cls != 4 {
		t.Fatalf("回退不应改变密级，期望 4，实际 %d", cls)
	}

	// state 必须唯一
	var effective int
	if err := f.pool.QueryRow(ctx,
		`SELECT count(*) FROM version WHERE node_id=$1 AND state='effective'`, f.nodeID).Scan(&effective); err != nil {
		t.Fatal(err)
	}
	if effective != 1 {
		t.Fatalf("effective 版本应唯一，实际 %d 个", effective)
	}
}

// 重复点击回退不应产生第二个版本。
func TestRestoreRejectsSameContent(t *testing.T) {
	f := newRestoreFixture(t)
	ctx := context.Background()

	v1 := putVersion(t, f, []byte("AAA"))
	putVersion(t, f, []byte("BBBBB"))

	if _, err := f.store.RestoreVersion(ctx, f.tenantID, f.nodeID, v1, f.userID); err != nil {
		t.Fatalf("首次回退失败: %v", err)
	}
	// 新版本的 sha 必须与源版本逐字节一致（bytea 误写成文本会让这里露出来）
	var sameSHA bool
	if err := f.pool.QueryRow(ctx, `
		SELECT (SELECT sha256 FROM version WHERE node_id=$1 AND version_no=$2)
		     = (SELECT sha256 FROM version WHERE node_id=$1 AND version_no=$3)`,
		f.nodeID, v1, v1+2).Scan(&sameSHA); err != nil {
		t.Fatal(err)
	}
	if !sameSHA {
		t.Fatal("回退生成的新版本 sha256 应与源版本相同")
	}
	// 内容已与 v1 相同，再点一次必须被拒，而不是再追加一个重复版本
	_, err := f.store.RestoreVersion(ctx, f.tenantID, f.nodeID, v1, f.userID)
	if !errors.Is(err, ErrVersionContentSame) {
		t.Fatalf("重复回退应返回 ErrVersionContentSame，实际 %v", err)
	}
}

// 回退到当前版本本身，应当直接拒绝。
func TestRestoreRejectsCurrent(t *testing.T) {
	f := newRestoreFixture(t)
	v1 := putVersion(t, f, []byte("AAA"))
	putVersion(t, f, []byte("BBBBB"))

	_, err := f.store.RestoreVersion(context.Background(), f.tenantID, f.nodeID, v1+1, f.userID)
	if !errors.Is(err, ErrVersionAlreadyCurrent) {
		t.Fatalf("回退到当前版本应返回 ErrVersionAlreadyCurrent，实际 %v", err)
	}
}

// 源版本被删掉后回退：必须报"版本不存在"，且**不能**把 current_version_id 写成 NULL。
// 这是 INSERT ... SELECT 0 行时最容易出的静默数据损坏。
func TestRestoreMissingSourceKeepsPointer(t *testing.T) {
	f := newRestoreFixture(t)
	ctx := context.Background()

	v1 := putVersion(t, f, []byte("AAA"))
	putVersion(t, f, []byte("BBBBB"))

	if _, err := f.pool.Exec(ctx,
		`DELETE FROM version WHERE node_id=$1 AND version_no=$2`, f.nodeID, v1); err != nil {
		t.Fatal(err)
	}

	_, err := f.store.RestoreVersion(ctx, f.tenantID, f.nodeID, v1, f.userID)
	if !errors.Is(err, ErrVersionNotFound) {
		t.Fatalf("应返回 ErrVersionNotFound，实际 %v", err)
	}

	var cur *string
	if err := f.pool.QueryRow(ctx,
		`SELECT current_version_id::text FROM node WHERE id=$1`, f.nodeID).Scan(&cur); err != nil {
		t.Fatal(err)
	}
	if cur == nil || *cur == "" {
		t.Fatal("回退失败后 node.current_version_id 不能为空（文件会变成打不开的空壳）")
	}
}

// 作废版本不能被复活。
func TestRestoreRejectsVoid(t *testing.T) {
	f := newRestoreFixture(t)
	ctx := context.Background()

	v1 := putVersion(t, f, []byte("AAA"))
	putVersion(t, f, []byte("BBBBB"))
	if _, err := f.pool.Exec(ctx,
		`UPDATE version SET state='void' WHERE node_id=$1 AND version_no=$2`, f.nodeID, v1); err != nil {
		t.Fatal(err)
	}

	_, err := f.store.RestoreVersion(ctx, f.tenantID, f.nodeID, v1, f.userID)
	if !errors.Is(err, ErrVersionVoid) {
		t.Fatalf("应返回 ErrVersionVoid，实际 %v", err)
	}
}

// 有人正在编辑时必须拒绝，否则对方保存后会把回退覆盖掉。
func TestRestoreRejectsActiveEditSession(t *testing.T) {
	f := newRestoreFixture(t)
	ctx := context.Background()

	v1 := putVersion(t, f, []byte("AAA"))
	putVersion(t, f, []byte("BBBBB"))

	if err := f.store.TouchDocSession(ctx, f.tenantID, f.nodeID, f.userID, f.userID); err != nil {
		t.Fatal(err)
	}

	_, err := f.store.RestoreVersion(ctx, f.tenantID, f.nodeID, v1, f.userID)
	if !errors.Is(err, ErrNodeEditing) {
		t.Fatalf("有活跃编辑会话时应返回 ErrNodeEditing，实际 %v", err)
	}

	// 回退被拒后会话不能被误伤（否则编辑者下次保存会失败）
	active, aerr := f.store.HasActiveDocSession(ctx, f.tenantID, f.nodeID)
	if aerr != nil || !active {
		t.Fatalf("被拒绝的回退不应使会话失效: active=%v err=%v", active, aerr)
	}
}

// 回退成功后，该文件的编辑会话必须失效。
func TestRestoreInvalidatesSessions(t *testing.T) {
	f := newRestoreFixture(t)
	ctx := context.Background()

	v1 := putVersion(t, f, []byte("AAA"))
	putVersion(t, f, []byte("BBBBB"))

	// 手工插一个"刚结束编辑"的会话：回退应在成功的路径上把它作废
	if _, err := f.pool.Exec(ctx, `
		INSERT INTO doc_session (tenant_id, node_id, session_key, user_id, last_seen_at)
		VALUES ($1,$2,'stale',$3, now() - interval '30 minutes')`,
		f.tenantID, f.nodeID, f.userID); err != nil {
		t.Fatal(err)
	}

	if _, err := f.store.RestoreVersion(ctx, f.tenantID, f.nodeID, v1, f.userID); err != nil {
		t.Fatalf("回退应成功（会话已过期）: %v", err)
	}

	var alive int
	if err := f.pool.QueryRow(ctx, `
		SELECT count(*) FROM doc_session
		 WHERE node_id=$1 AND invalidated_at IS NULL`, f.nodeID).Scan(&alive); err != nil {
		t.Fatal(err)
	}
	if alive != 0 {
		t.Fatalf("回退后不应有活跃会话，实际 %d", alive)
	}
}

// 按版本下载：取到的是指定版本的内容，而不是当前版本。
func TestOpenVersionContentReturnsRequestedVersion(t *testing.T) {
	f := newRestoreFixture(t)
	ctx := context.Background()

	v1 := putVersion(t, f, []byte("OLD-CONTENT"))
	putVersion(t, f, []byte("NEW-CONTENT-LONGER"))

	rc, _, size, err := f.store.OpenVersionContent(ctx, f.tenantID, f.nodeID, v1)
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	b, err := io.ReadAll(rc)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(b, []byte("OLD-CONTENT")) {
		t.Fatalf("应取到 v1 的内容，实际 %q", string(b))
	}
	// Content-Length 用的必须是该版本的大小，不是当前版本
	if size != int64(len("OLD-CONTENT")) {
		t.Fatalf("size 应为该版本大小 %d，实际 %d", len("OLD-CONTENT"), size)
	}
}

// 版本保留清理：只删超出数量的旧版本，永不删当前版本。
func TestPruneVersionsKeepsLatestAndCurrent(t *testing.T) {
	f := newRestoreFixture(t)
	ctx := context.Background()

	// 5 个版本，内容各不相同（否则会共用 blob，看不出引用计数变化）
	for i := 0; i < 5; i++ {
		putVersion(t, f, []byte(strings.Repeat("v", 10+i)))
	}

	removed, err := f.store.PruneVersions(ctx, f.tenantID, f.nodeID, 3)
	if err != nil {
		t.Fatalf("清理失败: %v", err)
	}
	if removed != 2 {
		t.Fatalf("应删除 2 个旧版本，实际 %d", removed)
	}

	var nos []int
	rows, err := f.pool.Query(ctx,
		`SELECT version_no FROM version WHERE node_id=$1 ORDER BY version_no`, f.nodeID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var n int
		if err := rows.Scan(&n); err != nil {
			t.Fatal(err)
		}
		nos = append(nos, n)
	}
	if len(nos) != 3 || nos[0] != 3 || nos[2] != 5 {
		t.Fatalf("应只剩 v3/v4/v5，实际 %v", nos)
	}

	// 当前版本必须仍然可读，指针不能动
	if got := f.readCurrent(t); got != strings.Repeat("v", 14) {
		t.Fatalf("清理后当前内容应为 v5，实际 %q", got)
	}
	var effective int
	if err := f.pool.QueryRow(ctx,
		`SELECT count(*) FROM version WHERE node_id=$1 AND state='effective'`, f.nodeID).Scan(&effective); err != nil {
		t.Fatal(err)
	}
	if effective != 1 {
		t.Fatalf("清理后仍须恰好一个 effective，实际 %d", effective)
	}

	// 被删版本的 blob 引用计数应归零（触发器生效），但 blob 行仍在
	var orphans int
	if err := f.pool.QueryRow(ctx,
		`SELECT count(*) FROM blob WHERE tenant_id=$1 AND ref_count = 0`, f.tenantID).Scan(&orphans); err != nil {
		t.Fatal(err)
	}
	if orphans != 2 {
		t.Fatalf("应有 2 个 blob 引用归零，实际 %d", orphans)
	}
}

// 保留数为 1 时也不能把当前版本删掉。
func TestPruneVersionsNeverDeletesEffective(t *testing.T) {
	f := newRestoreFixture(t)
	ctx := context.Background()

	putVersion(t, f, []byte("AAA"))
	putVersion(t, f, []byte("BBBBB"))

	if _, err := f.store.PruneVersions(ctx, f.tenantID, f.nodeID, 1); err != nil {
		t.Fatalf("清理失败: %v", err)
	}
	if got := f.readCurrent(t); got != "BBBBB" {
		t.Fatalf("当前内容不应被清理，实际 %q", got)
	}
	count := 0
	if err := f.pool.QueryRow(ctx,
		`SELECT count(*) FROM version WHERE node_id=$1`, f.nodeID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("保留 1 个版本时应只剩当前版本，实际 %d", count)
	}
}

// 覆盖上传后 space.used_bytes 必须等于新内容大小，而不是累加。
func TestOverwriteKeepsSpaceUsageAccurate(t *testing.T) {
	f := newRestoreFixture(t)
	ctx := context.Background()

	putVersion(t, f, []byte("AAA"))
	putVersion(t, f, []byte("BBBBB"))

	// putVersion 直接写库、不走 UploadFile，所以先手工把空间用量摆到当前大小，
	// 这样能单独验证回退是否按 delta 维护（而不是又加一次）。
	if _, err := f.pool.Exec(ctx,
		`UPDATE space SET used_bytes = 5 WHERE id = $1`, f.spaceID); err != nil {
		t.Fatal(err)
	}

	v1 := 1
	if _, err := f.store.RestoreVersion(ctx, f.tenantID, f.nodeID, v1, f.userID); err != nil {
		t.Fatal(err)
	}
	var used int64
	if err := f.pool.QueryRow(ctx,
		`SELECT used_bytes FROM space WHERE id=$1`, f.spaceID).Scan(&used); err != nil {
		t.Fatal(err)
	}
	// 回退到 3 字节内容：从 5 变成 3（delta = −2）
	if used != 3 {
		t.Fatalf("回退后空间用量应为 3，实际 %d", used)
	}
}
