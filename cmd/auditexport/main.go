// Command auditexport 导出审计证据包。
//
// 做成独立命令而不是 HTTP 接口：导出通常用于监管检查、法务取证，
// 属于低频、强审计的运维动作，不该由普通会话触发；
// 也不该让一次超大导出把 Web 进程的内存打满。
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"docvault/internal/audit"
	"docvault/internal/db"
	"docvault/internal/platform/config"
	"docvault/migrations"
)

func main() {
	var (
		tenant = flag.String("tenant", "", "租户 slug（必填）")
		from   = flag.String("from", "", "起始时间 RFC3339（默认 30 天前）")
		to     = flag.String("to", "", "结束时间 RFC3339（默认现在）")
		out    = flag.String("out", "evidence.json", "输出文件")
	)
	flag.Parse()

	if *tenant == "" {
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

	fromT := time.Now().UTC().AddDate(0, 0, -30)
	toT := time.Now().UTC()
	if *from != "" {
		t, perr := time.Parse(time.RFC3339, *from)
		if perr != nil {
			fmt.Fprintf(os.Stderr, "-from 格式错误: %v\n", perr)
			os.Exit(2)
		}
		fromT = t
	}
	if *to != "" {
		t, perr := time.Parse(time.RFC3339, *to)
		if perr != nil {
			fmt.Fprintf(os.Stderr, "-to 格式错误: %v\n", perr)
			os.Exit(2)
		}
		toT = t
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

	var tenantID string
	if err := pool.QueryRow(ctx,
		`SELECT id::text FROM tenant WHERE slug = $1 AND deleted_at IS NULL`, *tenant).Scan(&tenantID); err != nil {
		fmt.Fprintf(os.Stderr, "租户 %s 不存在: %v\n", *tenant, err)
		os.Exit(2)
	}

	raw, err := audit.Export(ctx, pool, tenantID, fromT, toT)
	if err != nil {
		fmt.Fprintf(os.Stderr, "导出失败: %v\n", err)
		os.Exit(1)
	}
	if err := os.WriteFile(*out, raw, 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "写入失败: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("已导出 %d 字节到 %s（%s ~ %s）\n", len(raw), *out,
		fromT.Format(time.RFC3339), toT.Format(time.RFC3339))
	fmt.Println("校验：auditverify -bundle", *out, "-secret <锚点密钥>")
}
