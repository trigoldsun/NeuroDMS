// Command auditgap 把一次"审计缺口"作为**元事件**写入审计链。
//
// 为什么需要它：审计是哈希链（prev_hash → hash），断流期间的事件从未产生，
// 既不在库里也无法从其他业务表还原。用现在的数据"补造"那些事件等于伪造审计
// （时间戳与哈希都是新造的），一旦被核验发现，整条链的证明力归零。
//
// 正确做法是**承认缺口**：在链上追加一条 audit.gap，detail 记录缺口区间与原因。
// 这样链保持连续可验证，合规材料可以指向一条真实存在、可复算的记录，
// 而不是要求对方相信一句口头说明。
//
// 用法：
//
//	# 1) 先看会写入什么（默认 dry-run）
//	auditgap -tenant trigold786 -from 2026-11-15T10:50:31+08:00 -to 2026-11-16T20:06:00+08:00 \
//	         -reason "审计写入链路故障" -by "运维：sunxi"
//
//	# 2) 确认后写入
//	auditgap ... -apply
//
// 环境变量：DOCVAULT_DB_DSN（必填）。
//
// 安全约定：
//   - 只允许写入 audit.gap，不接受任意 action（否则等于给运维开一条伪造审计的口子）；
//   - 同一区间幂等：已存在相同 from/to 的 gap 记录时拒绝重复写入；
//   - 不改 created_at：记录时间就是"声明时间"，缺口区间放在 detail 里。
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

	"github.com/jackc/pgx/v5"
)

func main() {
	tenant := flag.String("tenant", "", "租户 slug（必填）")
	from := flag.String("from", "", "缺口开始时间 RFC3339（必填）")
	to := flag.String("to", "", "缺口结束时间 RFC3339（必填）")
	reason := flag.String("reason", "", "缺口原因（必填，写入 detail）")
	by := flag.String("by", "", "确认人（写入 detail，建议写明岗位与姓名）")
	apply := flag.Bool("apply", false, "真正写入（默认 dry-run，只打印）")
	flag.Parse()

	if *tenant == "" || *from == "" || *to == "" || *reason == "" {
		fmt.Fprintln(os.Stderr, "必须提供 -tenant / -from / -to / -reason")
		flag.Usage()
		os.Exit(2)
	}
	fromT, err := time.Parse(time.RFC3339, *from)
	if err != nil {
		fmt.Fprintf(os.Stderr, "-from 格式错误（需 RFC3339）: %v\n", err)
		os.Exit(2)
	}
	toT, err := time.Parse(time.RFC3339, *to)
	if err != nil {
		fmt.Fprintf(os.Stderr, "-to 格式错误（需 RFC3339）: %v\n", err)
		os.Exit(2)
	}
	if !toT.After(fromT) {
		fmt.Fprintln(os.Stderr, "-to 必须晚于 -from")
		os.Exit(2)
	}

	cfg, err := config.Load(os.Getenv)
	if err != nil {
		fmt.Fprintf(os.Stderr, "读取配置失败: %v\n", err)
		os.Exit(1)
	}
	if cfg.DBDSN == "" {
		fmt.Fprintln(os.Stderr, "必须设置 DOCVAULT_DB_DSN")
		os.Exit(2)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
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
		fmt.Fprintf(os.Stderr, "租户不存在或已删除: %s\n", *tenant)
		os.Exit(1)
	}

	fromStr := fromT.UTC().Format(time.RFC3339)
	toStr := toT.UTC().Format(time.RFC3339)

	// 幂等：同一区间只声明一次。重复声明会让链上出现多条互相矛盾的缺口记录。
	var dup int
	if err := pool.QueryRow(ctx, `
		SELECT count(*) FROM audit_event
		 WHERE tenant_id = $1 AND action = 'audit.gap'
		   AND detail->>'from' = $2 AND detail->>'to' = $3`, tenantID, fromStr, toStr).Scan(&dup); err != nil {
		fmt.Fprintf(os.Stderr, "检查既有声明失败: %v\n", err)
		os.Exit(1)
	}
	if dup > 0 {
		fmt.Printf("该区间已有 %d 条 audit.gap 声明，无需重复写入。\n", dup)
		return
	}

	detail := map[string]any{
		"from":        fromStr,
		"to":          toStr,
		"github":      "auditgap",
		"reason":      *reason,
		"confirmedBy": *by,
		"note":        "断流期间的业务事件未产生，无法补造；本条为缺口声明，非业务事件",
	}

	if !*apply {
		fmt.Println("== dry-run（未写入）==")
		fmt.Printf("租户    : %s (%s)\n", *tenant, tenantID)
		fmt.Printf("缺口区间: %s → %s\n", fromStr, toStr)
		fmt.Printf("原因    : %s\n确认人  : %s\n", *reason, *by)
		fmt.Println("确认无误后加 -apply 写入。")
		return
	}

	var seq int64
	err = db.WithTenant(ctx, pool, tenantID, func(tx pgx.Tx) error {
		if e := audit.Append(ctx, tx, tenantID, audit.Event{
			ActorType:  "system",
			Action:     "audit.gap",
			ObjectType: "tenant",
			Result:     "ok",
			Detail:     detail,
		}); e != nil {
			return e
		}
		return tx.QueryRow(ctx,
			`SELECT seq FROM audit_event WHERE tenant_id = $1 ORDER BY seq DESC LIMIT 1`, tenantID).Scan(&seq)
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "写入失败: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("已写入 audit.gap：租户 %s，seq=%d，区间 %s → %s\n", *tenant, seq, fromStr, toStr)
	fmt.Println("下一步：用 auditexport 重新导出证据包，auditverify 复算链完整性。")
}
