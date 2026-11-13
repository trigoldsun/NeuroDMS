// Package db 负责数据库连接、迁移与租户上下文。
//
// 三条纪律（对应 SAD §9）：
//  1. 迁移单一所有者：只有 server 执行；worker 只做断言。
//  2. 迁移内容校验和绑定：已应用的脚本被改动即报错，防止"改了历史脚本导致各环境结构漂移"。
//  3. 租户上下文缺失即无数据：RLS 策略用 nullif(...,”)::uuid，未设置上下文时比较为 NULL，
//     不匹配任何行——忘记设置等于看不到数据，而不是看到全部数据。
package db

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// AppRole 是运行时使用的数据库角色：非超级用户、无 BYPASSRLS。
const AppRole = "docvault_app"

// Connect 建立连接池。
func Connect(ctx context.Context, dsn string) (*pgxpool.Pool, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("解析 DSN 失败: %w", err)
	}
	// 显式设置上限，避免默认值在并发下载场景把数据库连接打满
	cfg.MaxConns = 20
	cfg.MinConns = 2
	cfg.MaxConnLifetime = time.Hour
	cfg.MaxConnIdleTime = 15 * time.Minute

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("创建连接池失败: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("数据库不可达: %w", err)
	}
	return pool, nil
}

// Migrate 按文件名顺序执行未应用的迁移，返回本次实际应用的版本号。
//
// 已应用但校验和变化的脚本会直接报错而不是跳过——历史脚本不可变是迁移纪律的底线。
// migrationLockKey 是迁移用的 advisory lock 键（任意固定常量，全局唯一即可）。
const migrationLockKey int64 = 0x646f63766d6967 // "docvmig"

func Migrate(ctx context.Context, pool *pgxpool.Pool, fsys fs.FS) ([]string, error) {
	// 迁移必须串行。
	//
	// 多实例启动、或多个测试包并行跑时，两个连接会同时读到"0014 未应用"，
	// 然后一个成功、另一个撞 schema_migrations 主键冲突而启动失败。
	// 用会话级 advisory lock 把整段迁移串起来；锁随连接归还自动释放。
	conn, err := pool.Acquire(ctx)
	if err != nil {
		return nil, fmt.Errorf("获取迁移连接失败: %w", err)
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock($1)`, migrationLockKey); err != nil {
		return nil, fmt.Errorf("获取迁移锁失败: %w", err)
	}
	defer func() {
		// 用独立上下文释放：调用方的 ctx 可能已超时
		bg, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _ = conn.Exec(bg, `SELECT pg_advisory_unlock($1)`, migrationLockKey)
	}()

	if _, err := conn.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version    text PRIMARY KEY,
			checksum   text NOT NULL,
			applied_at timestamptz NOT NULL DEFAULT now()
		)`); err != nil {
		return nil, fmt.Errorf("创建 schema_migrations 失败: %w", err)
	}

	names, err := sqlFiles(fsys)
	if err != nil {
		return nil, err
	}

	applied := map[string]string{}
	rows, err := conn.Query(ctx, `SELECT version, checksum FROM schema_migrations`)
	if err != nil {
		return nil, fmt.Errorf("读取迁移记录失败: %w", err)
	}
	for rows.Next() {
		var v, c string
		if err := rows.Scan(&v, &c); err != nil {
			rows.Close()
			return nil, err
		}
		applied[v] = c
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}

	var done []string
	for _, name := range names {
		body, err := fs.ReadFile(fsys, name)
		if err != nil {
			return nil, fmt.Errorf("读取迁移 %s 失败: %w", name, err)
		}
		sum := sha256.Sum256(body)
		checksum := hex.EncodeToString(sum[:])

		if prev, ok := applied[name]; ok {
			if prev != checksum {
				return nil, fmt.Errorf("迁移 %s 已被修改（校验和不一致）：历史脚本不可变，请新增一个迁移文件", name)
			}
			continue
		}

		tx, err := conn.Begin(ctx)
		if err != nil {
			return nil, err
		}
		if _, err := tx.Exec(ctx, string(body)); err != nil {
			_ = tx.Rollback(ctx)
			return nil, fmt.Errorf("执行迁移 %s 失败: %w", name, err)
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO schema_migrations (version, checksum) VALUES ($1, $2)`, name, checksum); err != nil {
			_ = tx.Rollback(ctx)
			return nil, fmt.Errorf("记录迁移 %s 失败: %w", name, err)
		}
		if err := tx.Commit(ctx); err != nil {
			return nil, fmt.Errorf("提交迁移 %s 失败: %w", name, err)
		}
		done = append(done, name)
	}
	return done, nil
}

func sqlFiles(fsys fs.FS) ([]string, error) {
	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		return nil, fmt.Errorf("读取迁移目录失败: %w", err)
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if strings.HasSuffix(e.Name(), ".sql") {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	if len(names) == 0 {
		return nil, fmt.Errorf("未找到任何迁移脚本")
	}
	return names, nil
}

// TenantTableMissingPolicy 是自检结果项：表名与原因。
type TenantTableMissingPolicy struct {
	Table  string
	Reason string
}

// AssertRLSCoverage 校验"所有带 tenant_id 的表都启用了 RLS 且至少有一条策略"。
//
// 这条检查存在的唯一目的：把"某人新建表时忘了加隔离"从运行期隐患变成启动期失败。
func AssertRLSCoverage(ctx context.Context, pool *pgxpool.Pool) ([]TenantTableMissingPolicy, error) {
	const q = `
		SELECT c.relname,
		       CASE
		         WHEN c.relrowsecurity = false THEN 'RLS 未启用'
		         ELSE '缺少策略'
		       END AS reason
		FROM pg_class c
		JOIN pg_namespace n ON n.oid = c.relnamespace
		WHERE n.nspname = 'public'
		  AND c.relkind = 'r'
		  AND EXISTS (
		      SELECT 1 FROM information_schema.columns col
		      WHERE col.table_schema = 'public'
		        AND col.table_name = c.relname
		        AND col.column_name = 'tenant_id')
		  AND (
		      c.relrowsecurity = false
		      OR NOT EXISTS (SELECT 1 FROM pg_policy p WHERE p.polrelid = c.oid)
		  )
		ORDER BY c.relname`

	rows, err := pool.Query(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("RLS 自检查询失败: %w", err)
	}
	defer rows.Close()

	var out []TenantTableMissingPolicy
	for rows.Next() {
		var item TenantTableMissingPolicy
		if err := rows.Scan(&item.Table, &item.Reason); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

// WithTenant 在受控事务内执行 fn：切换应用角色并设置租户上下文。
//
// 使用 SET LOCAL，事务结束自动失效，不会污染连接池里的其他请求。
func WithTenant(ctx context.Context, pool *pgxpool.Pool, tenantID string, fn func(pgx.Tx) error) error {
	if tenantID == "" {
		return fmt.Errorf("租户上下文为空：拒绝在无租户上下文的情况下访问数据")
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, "SET LOCAL ROLE "+AppRole); err != nil {
		return fmt.Errorf("切换应用角色失败: %w", err)
	}
	if _, err := tx.Exec(ctx, "SELECT set_config('app.tenant_id', $1, true)", tenantID); err != nil {
		return fmt.Errorf("设置租户上下文失败: %w", err)
	}
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// PlatformQuery 以超级用户身份执行平台级查询（迁移、自检）。
// 仅允许在启动与运维路径使用，不得用于处理用户请求。
func PlatformQuery(ctx context.Context, pool *pgxpool.Pool, sql string, args ...any) (pgx.Rows, error) {
	return pool.Query(ctx, sql, args...)
}
