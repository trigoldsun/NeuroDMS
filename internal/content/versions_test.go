package content

// 版本并发的正确性验证（AC-77）。
//
// 这是"读后写"最容易翻车的地方：max(version_no)+1 在并发下会算出同一个号，
// 数据库的唯一约束会挡住重复，但如果不重试，用户看到的就是 500。
// 这条用例要求：20 个并发全部成功，且版本号连续无空洞。

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"

	"docvault/internal/db"
	"docvault/internal/dbtest"

	"github.com/jackc/pgx/v5/pgxpool"
)

func vUUID(t *testing.T) string {
	t.Helper()
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		t.Fatal(err)
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	s := hex.EncodeToString(b[:])
	return fmt.Sprintf("%s-%s-%s-%s-%s", s[0:8], s[8:12], s[12:16], s[16:20], s[20:32])
}

// seedNode 建租户、用户、空间与一个文件节点。
func seedNode(t *testing.T) (pool *pgxpool.Pool, tenantID, userID, nodeID string) {
	t.Helper()
	dsn := os.Getenv("DOCVAULT_TEST_DSN")
	if dsn == "" {
		t.Skip("未设置 DOCVAULT_TEST_DSN，跳过内容集成测试")
	}
	p, err := db.Connect(context.Background(), dsn)
	if err != nil {
		t.Fatalf("连接失败: %v", err)
	}
	t.Cleanup(p.Close)

	ctx := context.Background()
	tenantID, userID = vUUID(t), vUUID(t)
	spaceID, nodeID := vUUID(t), vUUID(t)
	slug := "content-" + tenantID[:8]

	if _, err := p.Exec(ctx, `INSERT INTO tenant (id, slug, name) VALUES ($1,$2,$3)`,
		tenantID, slug, "内容测试租户"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { dbtest.CleanupTenant(t, p, tenantID) })

	if _, err := p.Exec(ctx, `
		INSERT INTO app_user (id, tenant_id, username, display_name, status)
		VALUES ($1,$2,'u1','U1','active')`, userID, tenantID); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Exec(ctx, `
		INSERT INTO space (id, tenant_id, kind, name, owner_id)
		VALUES ($1,$2,'project','测试空间',$3)`, spaceID, tenantID, userID); err != nil {
		t.Fatal(err)
	}
	if _, err := p.Exec(ctx, `
		INSERT INTO node (id, tenant_id, space_id, kind, name, owner_id)
		VALUES ($1,$2,$3,'file','shared.txt',$4)`, nodeID, tenantID, spaceID, userID); err != nil {
		t.Fatal(err)
	}
	return p, tenantID, userID, nodeID
}

func TestAC77ConcurrentAppendVersionsStayContinuous(t *testing.T) {
	pool, tenantID, userID, nodeID := seedNode(t)
	store, err := New(pool, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	const n = 20
	var wg sync.WaitGroup
	errs := make([]error, n)
	start := make(chan struct{})

	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start // 同一时刻起跑，才是真并发
			_, _, e := store.AppendVersion(context.Background(), tenantID, nodeID, userID,
				strings.NewReader(fmt.Sprintf("版本内容-%02d-%s", i, strings.Repeat("x", 32))), 1<<20)
			errs[i] = e
		}(i)
	}
	close(start)
	wg.Wait()

	for i, e := range errs {
		if e != nil {
			t.Fatalf("AC-77 第 %d 个并发版本失败: %v", i, e)
		}
	}

	rows, err := pool.Query(context.Background(),
		`SELECT version_no FROM version WHERE node_id = $1 ORDER BY version_no`, nodeID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()

	var nos []int
	for rows.Next() {
		var v int
		if err := rows.Scan(&v); err != nil {
			t.Fatal(err)
		}
		nos = append(nos, v)
	}
	if len(nos) != n {
		t.Fatalf("AC-77 应有 %d 个版本，实际 %d", n, len(nos))
	}
	for i, v := range nos {
		if v != i+1 {
			t.Fatalf("AC-77 版本号必须连续无空洞，第 %d 个是 %d（完整序列 %v）", i+1, v, nos)
		}
	}
}

// 节点指针必须指向最后一个版本，且 20 次追加后空间用量等于各版本之和。
func TestAC77VersionPointerAndUsageConsistent(t *testing.T) {
	pool, tenantID, userID, nodeID := seedNode(t)
	store, err := New(pool, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	lastVersion := ""
	var total int64
	for i := 0; i < 3; i++ {
		vid, size, err := store.AppendVersion(context.Background(), tenantID, nodeID, userID,
			strings.NewReader(strings.Repeat("a", 100+i)), 1<<20)
		if err != nil {
			t.Fatal(err)
		}
		lastVersion = vid
		total += size
	}

	var current string
	var nodeSize int64
	var used int64
	ctx := context.Background()
	if err := pool.QueryRow(ctx,
		`SELECT current_version_id::text, size_bytes FROM node WHERE id = $1`, nodeID).
		Scan(&current, &nodeSize); err != nil {
		t.Fatal(err)
	}
	if err := pool.QueryRow(ctx,
		`SELECT used_bytes FROM space WHERE id = (SELECT space_id FROM node WHERE id = $1)`, nodeID).
		Scan(&used); err != nil {
		t.Fatal(err)
	}

	if current != lastVersion {
		t.Fatalf("current_version_id 应指向最后追加的版本，实际 %s vs %s", current, lastVersion)
	}
	if nodeSize != 102 {
		t.Fatalf("节点大小应为最后一次内容大小 102，实际 %d", nodeSize)
	}
	// 空间用量是"当前文件大小"，不是所有版本之和。
	// 旧实现只有 used_bytes + size，覆盖上传会越加越多（100+101+102=303）；
	// 现在按 delta 维护，恒等于最后一次内容大小。
	if used != 102 {
		t.Fatalf("空间用量应等于当前文件大小 102，实际 %d", used)
	}
	_ = total // 保留累加，便于失败时人工核对
}
