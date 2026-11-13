// Command dirsync 执行一次 LDAP/AD 同步。
//
// 为什么做成独立命令而不是 HTTP 接口：
//   - 同步通常是运维动作（可配 cron / 计划任务），不需要用户会话；
//   - 同步可能跑几分钟，放在 HTTP 请求里会超时；
//   - 出问题时能直接在服务器上跑 --dry-run 定位。
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"docvault/internal/bootstrap"
	"docvault/internal/db"
	"docvault/internal/directory"
	"docvault/internal/platform/config"
	"docvault/migrations"
)

func main() {
	var (
		tenantSlug = flag.String("tenant", "", "租户 slug（必填）")
		since      = flag.String("since", "", "增量起点水位；为空表示全量")
		dryRun     = flag.Bool("dry-run", false, "只计算不写库（首次同步前建议先跑一次）")
		keepMiss   = flag.Bool("keep-missing", false, "不回收目录中已消失的账号（默认回收）")
	)
	flag.Parse()

	if *tenantSlug == "" {
		fmt.Fprintln(os.Stderr, "必须指定 -tenant")
		os.Exit(2)
	}

	cfg, err := config.Load(os.Getenv)
	if err != nil {
		fmt.Fprintf(os.Stderr, "配置错误: %v\n", err)
		os.Exit(2)
	}
	if cfg.DBDSN == "" {
		fmt.Fprintln(os.Stderr, "必须设置 DOCVAULT_DB_DSN")
		os.Exit(2)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	pool, err := db.Connect(ctx, cfg.DBDSN)
	if err != nil {
		fmt.Fprintf(os.Stderr, "连接数据库失败: %v\n", err)
		os.Exit(1)
	}
	defer pool.Close()

	if _, err := db.Migrate(ctx, pool, migrations.Files); err != nil {
		fmt.Fprintf(os.Stderr, "迁移失败: %v\n", err)
		os.Exit(1)
	}

	dir, err := bootstrap.BuildDirectory(ctx, &cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
	if dir == nil {
		fmt.Fprintln(os.Stderr, "未配置目录（DOCVAULT_LDAP_URL / DOCVAULT_LDAP_BASE_DN）")
		os.Exit(2)
	}

	var tenantID string
	if err := pool.QueryRow(ctx,
		`SELECT id::text FROM tenant WHERE slug = $1 AND deleted_at IS NULL`, *tenantSlug).
		Scan(&tenantID); err != nil {
		fmt.Fprintf(os.Stderr, "租户 %s 不存在: %v\n", *tenantSlug, err)
		os.Exit(2)
	}

	res, err := directory.Sync(ctx, pool, tenantID, dir, *since, directory.Options{
		DisableMissing:  !*keepMiss,
		DryRun:          *dryRun,
		ExcludeAccounts: cfg.LDAPExcludeAccounts,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "同步失败: %v\n", err)
		os.Exit(1)
	}

	mode := "已写入"
	if *dryRun {
		mode = "预演（未写库）"
	}
	fmt.Printf("%s：可见 %d，新建 %d，更新 %d，停用 %d，恢复 %d，组 %d，成员关系 %d，水位 %s\n",
		mode, res.Seen, res.Created, res.Updated, res.Disabled, res.Restored,
		res.GroupsSynced, res.MembersLinked, res.Watermark)
}
