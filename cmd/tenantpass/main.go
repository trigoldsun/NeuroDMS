// Command tenantpass 重置某个租户账号的口令（运维通道）。
//
// 为什么需要它：租户端"重置口令"要求操作者**自己已经是系统管理员**；
// 一旦这家租户唯一的系统管理员口令丢了（或开通时填的口令没人记下），
// 产品里就没有任何自助路径——如果该账号还没登记邮箱/手机，
// 连登录页的"忘记口令"也走不通。平台运营台刻意不提供重置客户口令的能力
// （那等于平台可以接管任何客户账号，见 docs/55 §6）。
//
// 所以这条通道只能留在服务器上：需要 shell 访问 + 数据库凭据，
// 并且在**同一个事务**里写审计（`admin.member.password`，detail 标明来源 tenantpass）。
//
// 用法：
//
//	# 1) 先看一眼这家租户有哪些管理员（默认 dry-run，不改任何东西）
//	tenantpass -slug trigold786
//
//	# 2) 重置（生成 20 位随机口令，只在标准输出显示这一次）
//	tenantpass -slug trigold786 -apply
//
//	# 3) 降档前的运维清理：把某个管理员的密级降到目标档位允许的范围
//	tenantpass -slug trigold786 -user admin -setclass 0 -apply -reason "降档到基础版"
//
//	# 4) 指定账号 / 指定口令（一般不推荐自定口令）
//	tenantpass -slug trigold786 -user admin -apply
//	tenantpass -slug trigold786 -user admin -apply -password 'Temp-Pass-2026'
//
// 环境变量：DOCVAULT_DB_DSN（必填，可用 -dsn 覆盖）。
//
// 安全约定：
//   - 口令只写到 stdout，不写文件、不进日志、不进审计；
//   - 重置会吊销该账号全部会话（session_epoch 自增 + session.revoked_at）；
//   - 无论成功失败都建议留存这段输出，作为"运维介入"的书面记录。
package main

import (
	"context"
	"crypto/rand"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"docvault/internal/audit"
	"docvault/internal/db"
	"docvault/internal/iam"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// 口令字符集刻意去掉 0/O/1/l/I：这类口令是要靠人工抄写给客户的，
// 抄错一个字符的代价是"重置了口令还是登不进去"。
const pwAlphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"

type adminRow struct {
	ID             string
	Username       string
	DisplayName    string
	Status         string
	Source         string
	Email          string
	Phone          string
	LastLogin      *time.Time
	ExpiresAt      *time.Time
	Classification int
	Ceiling        int
}

func main() {
	var (
		dsn      = flag.String("dsn", "", "数据库 DSN（默认读 DOCVAULT_DB_DSN）")
		slug     = flag.String("slug", "", "租户标识（必填）")
		user     = flag.String("user", "", "要重置的账号用户名（默认取唯一可登录的系统管理员）")
		apply    = flag.Bool("apply", false, "真正执行重置（不加则只列出管理员）")
		password = flag.String("password", "", "指定新口令（默认生成 20 位随机口令）")
		reason   = flag.String("reason", "", "写进审计的原因（例如工单号）")
		setClass = flag.Int("setclass", -1, "把目标账号的密级改为 N（0-6），用于降档前的运维清理")
	)
	flag.Parse()

	if *slug == "" {
		fmt.Fprintln(os.Stderr, "必须指定 -slug（租户标识）")
		flag.Usage()
		os.Exit(2)
	}
	if *dsn == "" {
		*dsn = strings.TrimSpace(os.Getenv("DOCVAULT_DB_DSN"))
	}
	if *dsn == "" {
		fmt.Fprintln(os.Stderr, "必须设置 DOCVAULT_DB_DSN，或用 -dsn 指定")
		os.Exit(2)
	}

	// 30 秒足够：这是几条单行 UPDATE，超时说明数据库不可用。
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	pool, err := db.Connect(ctx, *dsn)
	if err != nil {
		fmt.Fprintf(os.Stderr, "连接数据库失败: %v\n", err)
		os.Exit(1)
	}
	defer pool.Close()

	var (
		tenantID, tenantName, tenantStatus string
	)
	err = pool.QueryRow(ctx,
		`SELECT id::text, name, status FROM tenant WHERE slug = $1 AND deleted_at IS NULL`,
		strings.ToLower(strings.TrimSpace(*slug))).Scan(&tenantID, &tenantName, &tenantStatus)
	if err != nil {
		if err == pgx.ErrNoRows {
			fmt.Fprintf(os.Stderr, "租户不存在或已删除: %s\n", *slug)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "读取租户失败: %v\n", err)
		os.Exit(1)
	}

	admins, err := listAdmins(ctx, pool, tenantID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "读取管理员失败: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("租户：%s（%s，状态 %s）\n", *slug, tenantName, tenantStatus)
	if len(admins) == 0 {
		// 一个系统管理员都没有：这本身就是要处理的事故。
		// 本工具不做"凭空造一个管理员"（那需要角色/部门/密级一整套上下文，
		// 而且默认值一旦选错就是在客户环境里留一个越权账号），
		// 这种情况请直接开单，由开发按现场数据补齐。
		fmt.Println("⚠ 该租户没有任何系统管理员。")
		fmt.Println("  本工具只重置已有账号的口令，不创建账号。请开单处理。")
		os.Exit(3)
	}

	fmt.Println("系统管理员：")
	for _, a := range admins {
		fmt.Printf("  - %s（%s）状态=%s 来源=%s 密级=%d 封顶=%d 邮箱=%s 手机=%s 最后登录=%s\n",
			a.Username, a.DisplayName, a.Status, a.Source, a.Classification, a.Ceiling,
			orDash(a.Email), orDash(a.Phone), fmtTime(a.LastLogin))
	}

	target, err := pickTarget(admins, *user)
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ %v\n", err)
		os.Exit(1)
	}

	// 改密级：降档到基础版前必须先清掉成员上的高密级（0058 的降档校验会拦），
	// 客户管理员自己可以往下调，但他失联/被停用时只剩这条通道。
	if *setClass >= 0 {
		if *setClass > 6 {
			fmt.Fprintln(os.Stderr, "❌ -setclass 取值范围 0-6")
			os.Exit(2)
		}
		if target.Classification == *setClass {
			fmt.Printf("\n%s 的密级已经是 %d，无需改动。\n", target.Username, *setClass)
			return
		}
		if !*apply {
			fmt.Printf("\n将把 %s（%s）的密级从 %d 改为 %d。\n",
				target.Username, target.DisplayName, target.Classification, *setClass)
			fmt.Println("当前是 dry-run，没有改动任何数据。确认无误后加 -apply 执行。")
			return
		}
		err = db.WithTenant(ctx, pool, tenantID, func(tx pgx.Tx) error {
			// ceiling 不低于 classification，避免造出"密级高于可授出上限"的怪状态。
			if _, e := tx.Exec(ctx, `
				UPDATE app_user
				   SET classification = $2,
				       ceiling = greatest(ceiling, $2),
				       updated_at = now()
				 WHERE id = $1`, target.ID, *setClass); e != nil {
				return e
			}
			detail := map[string]any{
				"username": target.Username,
				"before":   map[string]any{"classification": target.Classification},
				"after":    map[string]any{"classification": *setClass},
				"source":   "tenantpass",
			}
			if strings.TrimSpace(*reason) != "" {
				detail["reason"] = strings.TrimSpace(*reason)
			}
			return audit.Append(ctx, tx, tenantID, audit.Event{
				ActorType:  "system",
				Action:     "admin.member.classification",
				ObjectType: "app_user",
				ObjectID:   target.ID,
				Result:     audit.ResultOK,
				Detail:     detail,
			})
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "❌ 改密级失败（已回滚）: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("\n✅ 已把 %s 的密级从 %d 改为 %d。\n", target.Username, target.Classification, *setClass)
		fmt.Println("审计已写入 admin.member.classification（source=tenantpass），请保留本段输出作为书面记录。")
		return
	}

	if !*apply {
		fmt.Printf("\n将重置：%s（%s）\n", target.Username, target.DisplayName)
		fmt.Println("当前是 dry-run，没有改动任何数据。确认无误后加 -apply 执行。")
		if target.LastLogin == nil {
			fmt.Println("提示：该账号从未登录过。如果开通时设定的初始口令已无人知晓，直接用 -apply 重置即可。")
		}
		return
	}

	pw := *password
	generated := false
	if pw == "" {
		pw, err = randomPassword(20)
		if err != nil {
			fmt.Fprintf(os.Stderr, "生成口令失败: %v\n", err)
			os.Exit(1)
		}
		generated = true
	}

	// 改口令与写审计必须在同一事务：口令改了、审计没写，是最不能接受的不一致。
	err = db.WithTenant(ctx, pool, tenantID, func(tx pgx.Tx) error {
		if err := iam.SetPasswordTx(ctx, tx, target.ID, pw); err != nil {
			return err
		}
		detail := map[string]any{
			"username":        target.Username,
			"sessionsRevoked": true,
			"source":          "tenantpass",
			"generated":       generated,
		}
		if strings.TrimSpace(*reason) != "" {
			detail["reason"] = strings.TrimSpace(*reason)
		}
		return audit.Append(ctx, tx, tenantID, audit.Event{
			ActorType:  "system",
			Action:     "admin.member.password",
			ObjectType: "app_user",
			ObjectID:   target.ID,
			Result:     audit.ResultOK,
			Detail:     detail,
		})
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "❌ 重置失败（已回滚，口令未变更）: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("\n✅ 已重置 %s（%s）的口令，并吊销其全部会话。\n", target.Username, target.DisplayName)
	fmt.Printf("新口令：%s\n", pw)
	if generated {
		fmt.Println("（这是系统生成的口令，只显示这一次；请立即转交并让客户登录后修改。）")
	}
	fmt.Println("登录地址：<实例地址>/login → 组织标识填 " + *slug)
	fmt.Println("审计已写入 admin.member.password（source=tenantpass），请保留本段输出作为书面记录。")
}

func listAdmins(ctx context.Context, pool *pgxpool.Pool, tenantID string) ([]adminRow, error) {
	rows, err := pool.Query(ctx, `
		SELECT u.id::text, u.username, u.display_name, u.status, u.source,
		       coalesce(u.email, ''), coalesce(u.phone, ''),
		       u.last_login_at, u.expires_at, u.classification, u.ceiling
		  FROM app_user u
		  JOIN user_role ur ON ur.user_id = u.id AND ur.tenant_id = u.tenant_id
		  JOIN role r ON r.id = ur.role_id
		 WHERE u.tenant_id = $1 AND r.code = 'sysadmin'
		   AND u.deleted_at IS NULL AND r.deleted_at IS NULL
		 ORDER BY u.created_at`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []adminRow
	for rows.Next() {
		var a adminRow
		if err := rows.Scan(&a.ID, &a.Username, &a.DisplayName, &a.Status, &a.Source,
			&a.Email, &a.Phone, &a.LastLogin, &a.ExpiresAt,
			&a.Classification, &a.Ceiling); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// pickTarget 决定重置哪个账号。
//
// 只在"能登录"的管理员里挑：停用/过期的账号重置了口令也进不去，
// 那会让运维以为已经修好，实际上客户仍然登不了。
func pickTarget(admins []adminRow, want string) (adminRow, error) {
	usable := func(a adminRow) bool {
		if a.Status != "active" {
			return false
		}
		if a.ExpiresAt != nil && a.ExpiresAt.Before(time.Now()) {
			return false
		}
		return true
	}

	if want != "" {
		for _, a := range admins {
			if a.Username == want {
				if !usable(a) {
					return adminRow{}, fmt.Errorf("账号 %s 当前不可登录（状态=%s），先恢复账号再重置口令", a.Username, a.Status)
				}
				return a, nil
			}
		}
		return adminRow{}, fmt.Errorf("账号 %s 不是本租户的系统管理员（先用 -slug 不带 -user 查看清单）", want)
	}

	var cands []adminRow
	for _, a := range admins {
		if usable(a) {
			cands = append(cands, a)
		}
	}
	switch len(cands) {
	case 1:
		return cands[0], nil
	case 0:
		return adminRow{}, fmt.Errorf("没有可登录的系统管理员（全部停用或过期），请先恢复账号或用 -user 明确指定")
	default:
		names := make([]string, len(cands))
		for i, a := range cands {
			names[i] = a.Username
		}
		return adminRow{}, fmt.Errorf("存在多个可登录的系统管理员（%s），请用 -user 指定要重置哪一个",
			strings.Join(names, ", "))
	}
}

func randomPassword(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	out := make([]byte, n)
	for i, b := range buf {
		out[i] = pwAlphabet[int(b)%len(pwAlphabet)]
	}
	return string(out), nil
}

func orDash(s string) string {
	if strings.TrimSpace(s) == "" {
		return "—"
	}
	return s
}

func fmtTime(t *time.Time) string {
	if t == nil {
		return "从未登录"
	}
	return t.Local().Format("2006-01-02 15:04")
}
