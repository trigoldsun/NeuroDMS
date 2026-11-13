package directory

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"docvault/internal/db"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrEmptySnapshot 表示目录返回了 0 个账号，已跳过离职回收。
var ErrEmptySnapshot = errors.New("目录返回 0 个账号，已跳过离职回收（请检查过滤器与服务账号读权限）")

// Sync 执行一次目录同步。
//
// 七阶段（顺序不可随意调换，理由见每段注释）：
//  1. 拉快照           —— 先把外部世界读完整，避免"读到一半目录变了"的半截状态
//  2. 清洗与去重       —— 缺标识的条目必须丢弃，否则会产生大量重复账号
//  3. upsert 用户      —— 按 (tenant, source, external_id) 幂等
//  4. 落部门           —— 部门必须先存在，用户才能挂上去
//  5. upsert 组        —— 组按 DN 幂等
//  6. 展开嵌套组并关联 —— 只在组与用户都已入库后才能建立关系
//  7. 离职/恢复        —— 最后做，避免"先停用后被重新发现又恢复"的抖动
func Sync(ctx context.Context, pool *pgxpool.Pool, tenantID string, dir Directory, since string, opt Options) (Result, error) {
	if opt.Now == nil {
		opt.Now = time.Now
	}
	var res Result

	// 运行记录必须**先**用独立事务落库。
	//
	// 早先是把 INSERT 放在业务事务里：同步跑 3 分钟，这 3 分钟里界面上
	// 一条记录都没有（事务未提交，别的连接读不到），用户以为"点了没反应"。
	// 现在先写 running 行，结束时再更新状态与计数。
	runID, err := startRun(ctx, pool, tenantID)
	if err != nil {
		return res, fmt.Errorf("创建同步记录失败: %w", err)
	}
	fail := func(cause error) (Result, error) {
		failRun(ctx, pool, tenantID, runID, cause)
		return res, cause
	}

	snapshot, err := dir.Fetch(ctx, since)
	if err != nil {
		// 连快照都没拿到时也要留痕：这类失败最需要排障（证书过期、网段不通、服务账号口令失效）
		return fail(fmt.Errorf("拉取目录快照失败: %w", err))
	}
	res.Watermark = snapshot.Watermark

	users, _ := cleanUsers(snapshot.Users, excludeSet(opt.ExcludeAccounts))
	res.Seen = len(users)

	// 空快照保护：本次一个账号都没看到，而库里已有域账号——
	// 绝大多数情况是过滤器写错、服务账号权限不足、或连错了目录。
	// 此时若照常执行"离职回收"，会把全公司的域账号一次性停用。
	// 宁可让本次同步失败并报警，也不做这种不可逆的批量停用。
	if opt.DisableMissing && !opt.DryRun && res.Seen == 0 {
		var existing int
		if err := pool.QueryRow(ctx, `
			SELECT count(*) FROM app_user
			 WHERE tenant_id = $1 AND source = 'ldap' AND status = 'active'
			   AND deleted_at IS NULL`, tenantID).Scan(&existing); err != nil {
			return res, err
		}
		if existing > 0 {
			return fail(ErrEmptySnapshot)
		}
	}

	// 组 DN -> 展开后的成员 DN 集合（含嵌套）
	expanded := expandGroups(snapshot.Groups)

	err = db.WithTenant(ctx, pool, tenantID, func(tx pgx.Tx) error {
		// 3) 用户
		userIDByDN := make(map[string]string, len(users))
		userIDByExternal := make(map[string]string, len(users))
		seenExternal := make(map[string]struct{}, len(users))

		for _, u := range users {
			seenExternal[strings.ToLower(u.ExternalID)] = struct{}{}

			var deptID *string
			chain := u.DeptChain
			if len(chain) == 0 && u.Dept != "" {
				chain = []DeptNode{{Name: u.Dept}}
			}
			if len(chain) > 0 {
				id, derr := ensureDeptChain(ctx, tx, tenantID, chain)
				if derr != nil {
					return fmt.Errorf("写入部门 %v 失败: %w", chain, derr)
				}
				deptID = &id
			}

			outcome, id, uerr := upsertUser(ctx, tx, tenantID, u, deptID, opt)
			if uerr != nil {
				return fmt.Errorf("写入用户 %s 失败: %w", u.Username, uerr)
			}
			userIDByDN[strings.ToLower(u.DN)] = id
			userIDByExternal[strings.ToLower(u.ExternalID)] = id

			switch outcome {
			case "created":
				res.Created++
			case "updated":
				res.Updated++
			case "disabled":
				res.Disabled++
			case "restored":
				res.Restored++
			case "conflict":
				res.Conflicts++
				if len(res.ConflictUsers) < 10 {
					res.ConflictUsers = append(res.ConflictUsers, u.Username)
				}
			}
		}

		// 5) 组
		for _, g := range snapshot.Groups {
			if g.Name == "" || g.DN == "" {
				continue
			}
			gid, gerr := upsertGroup(ctx, tx, tenantID, g)
			if gerr != nil {
				return gerr
			}
			res.GroupsSynced++

			// 6) 关联（用展开后的成员）
			members := expanded[strings.ToLower(g.DN)]
			if opt.DryRun {
				continue // 预演不写库，也不做成员关联
			}
			for _, mdn := range members {
				uid, ok := userIDByDN[strings.ToLower(mdn)]
				if !ok {
					// 成员可能是组 DN（嵌套已在 expandGroups 里展开）或目录外账号，跳过
					continue
				}
				ct, lerr := tx.Exec(ctx, `
					INSERT INTO group_member (tenant_id, group_id, user_id, source)
					VALUES ($1,$2,$3,'ldap')
					ON CONFLICT (group_id, user_id) DO NOTHING`, tenantID, gid, uid)
				if lerr != nil {
					return lerr
				}
				if ct.RowsAffected() > 0 {
					res.MembersLinked++
				}
			}

			// 目录里已移除的成员要同步移除（只删 ldap 来源的，手工授权不动）。
			// 这里必须用"解析出的用户 ID"比较，不能用 DN：
			// external_id 存的是 objectGUID/entryUUID，拿 DN 去比会一次删光整个组。
			memberIDs := make([]string, 0, len(members))
			for _, mdn := range members {
				if uid, ok := userIDByDN[strings.ToLower(mdn)]; ok {
					memberIDs = append(memberIDs, uid)
				}
			}
			if _, derr := tx.Exec(ctx, `
				DELETE FROM group_member gm
				 WHERE gm.tenant_id = $1 AND gm.group_id = $2 AND gm.source = 'ldap'
				   AND NOT (gm.user_id = ANY($3::uuid[]))`, tenantID, gid, memberIDs); derr != nil {
				return derr
			}
		}

		// 7) 离职回收：目录里看不到的 ldap 账号一律停用
		if opt.DisableMissing && !opt.DryRun {
			ids := make([]string, 0, len(seenExternal))
			for k := range seenExternal {
				ids = append(ids, k)
			}
			ct, derr := tx.Exec(ctx, `
				UPDATE app_user
				   SET status = 'suspended', directory_disabled = true,
				       session_epoch = session_epoch + 1, updated_at = now()
				 WHERE tenant_id = $1 AND source = 'ldap' AND status = 'active'
				   AND deleted_at IS NULL
				   AND lower(external_id) <> ALL($2::text[])`, tenantID, ids)
			if derr != nil {
				return derr
			}
			res.Disabled += int(ct.RowsAffected())
			if ct.RowsAffected() > 0 {
				// 会话必须一并吊销：否则停用后 15 分钟内旧令牌仍可用
				if _, serr := tx.Exec(ctx, `
					UPDATE session SET revoked_at = now()
					 WHERE tenant_id = $1 AND revoked_at IS NULL
					   AND user_id IN (SELECT id FROM app_user
					                    WHERE tenant_id = $1 AND source = 'ldap' AND directory_disabled)`,
					tenantID); serr != nil {
					return serr
				}
			}
		}

		return nil
	})
	if err != nil {
		return fail(err)
	}
	// 计数在所有业务数据**提交之后**再写：否则会记下"已提交但实际回滚"的假数字
	if err := finishRun(ctx, pool, tenantID, runID, res); err != nil {
		// 数据已经提交，但记录没写成功。必须把这条 run 标成 failed，
		// 否则它会永远停在 running，界面看起来像"同步卡住了"。
		failRun(ctx, pool, tenantID, runID, err)
		return res, fmt.Errorf("同步已完成，但更新运行记录失败: %w", err)
	}
	return res, nil
}

// recordFailure 用独立事务记录一次失败，best-effort（记录失败本身不该再抛错）。
func recordFailure(ctx context.Context, pool *pgxpool.Pool, tenantID string, cause error) {
	_ = db.WithTenant(ctx, pool, tenantID, func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `
			INSERT INTO directory_sync (id, tenant_id, status, finished_at, error)
			VALUES (gen_random_uuid(), $1, 'failed', now(), $2)`, tenantID, cause.Error())
		return e
	})
}

// cleanUsers 丢弃缺稳定标识或用户名的条目，并按 external_id 去重。
//
// 为什么必须去重：目录常有同名/重复条目（尤其是从多个 OU 合并时），
// 不去重会在同一次同步里对同一行反复 upsert，把 updated 计数刷成假数据。
// defaultExcluded 是常见的域内服务账号。刻意不含 Administrator / Guest：
// 前者通常是运维要用的管理员，后者在部分客户那里是真在用的外部账号。
var defaultExcluded = []string{"krbtgt", "defaultaccount", "wdagutilityaccount"}

func excludeSet(extra []string) map[string]struct{} {
	set := make(map[string]struct{}, len(defaultExcluded)+len(extra))
	for _, a := range defaultExcluded {
		set[strings.ToLower(strings.TrimSpace(a))] = struct{}{}
	}
	for _, a := range extra {
		if a = strings.ToLower(strings.TrimSpace(a)); a != "" {
			set[a] = struct{}{}
		}
	}
	return set
}

func cleanUsers(in []User, exclude map[string]struct{}) ([]User, int) {
	seen := make(map[string]struct{}, len(in))
	out := make([]User, 0, len(in))
	skipped := 0
	for _, u := range in {
		key := strings.ToLower(strings.TrimSpace(u.ExternalID))
		if key == "" || strings.TrimSpace(u.Username) == "" {
			skipped++
			continue
		}
		if _, bad := exclude[strings.ToLower(strings.TrimSpace(u.Username))]; bad {
			skipped++
			continue
		}
		if _, dup := seen[key]; dup {
			skipped++
			continue
		}
		seen[key] = struct{}{}
		out = append(out, u)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Username < out[j].Username })
	return out, skipped
}

// expandGroups 计算每个组包含的全部用户 DN（含嵌套组）。
//
// 递归 + visited 防环：AD 里存在互相嵌套的组（配置错误但真实存在），
// 不做防环会直接栈溢出。
func expandGroups(groups []Group) map[string][]string {
	members := make(map[string][]string, len(groups))
	groupSet := make(map[string]struct{}, len(groups))
	for _, g := range groups {
		key := strings.ToLower(g.DN)
		groupSet[key] = struct{}{}
		members[key] = g.Members
	}

	out := make(map[string][]string, len(groups))
	for _, g := range groups {
		key := strings.ToLower(g.DN)
		visited := map[string]struct{}{key: {}}
		collect(key, members, groupSet, visited, out)
	}
	return out
}

func collect(dn string, members map[string][]string, groupSet map[string]struct{},
	visited map[string]struct{}, out map[string][]string) []string {

	if cached, ok := out[dn]; ok {
		return cached
	}
	var result []string
	seen := make(map[string]struct{})
	for _, m := range members[dn] {
		mdn := strings.ToLower(m)
		if _, isGroup := groupSet[mdn]; isGroup {
			if _, loop := visited[mdn]; loop {
				continue // 防环
			}
			visited[mdn] = struct{}{}
			for _, nested := range collect(mdn, members, groupSet, visited, out) {
				if _, dup := seen[nested]; !dup {
					seen[nested] = struct{}{}
					result = append(result, nested)
				}
			}
			continue
		}
		if _, dup := seen[mdn]; dup {
			continue
		}
		seen[mdn] = struct{}{}
		result = append(result, m)
	}
	out[dn] = result
	return result
}

// ensureDeptChain 按 OU 链建出部门树，返回最内层部门 ID。
//
// 为什么要建树而不是摊平：权限判定按部门祖先链继承（ace.LoadSubject 用 ltree `path @>`），
// 摊平成一层会导致"在上级部门授权、下级部门的人看不到"。
//
// 幂等：优先按 LDAP DN 定位（改名会新建而不是错挂），
// 其次按"同父同名"定位（目录里没有 DN 的场景，如本地建的组织）。
func ensureDeptChain(ctx context.Context, tx pgx.Tx, tenantID string, chain []DeptNode) (string, error) {
	var parentID any
	var parentPath string
	var lastID string

	for _, node := range chain {
		name := strings.TrimSpace(node.Name)
		if name == "" {
			continue
		}

		var id, path string
		var err error

		if node.DN != "" {
			err = tx.QueryRow(ctx, `
				SELECT id::text, path::text FROM dept
				 WHERE tenant_id = $1 AND ldap_dn = $2 AND deleted_at IS NULL
				 LIMIT 1`, tenantID, node.DN).Scan(&id, &path)
			if err == nil {
				lastID, parentID, parentPath = id, id, path
				continue
			}
			if !errors.Is(err, pgx.ErrNoRows) {
				return "", err
			}
		}

		err = tx.QueryRow(ctx, `
			SELECT id::text, path::text FROM dept
			 WHERE tenant_id = $1 AND parent_id IS NOT DISTINCT FROM $2
			   AND lower(name) = lower($3) AND deleted_at IS NULL
			 LIMIT 1`, tenantID, parentID, name).Scan(&id, &path)
		if err == nil {
			lastID, parentID, parentPath = id, id, path
			continue
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return "", err
		}

		label := ltreeLabel(name)
		fullPath := label
		if parentPath != "" {
			fullPath = parentPath + "." + label
		}
		var dnVal any
		if node.DN != "" {
			dnVal = node.DN
		}
		if err := tx.QueryRow(ctx, `
			INSERT INTO dept (id, tenant_id, parent_id, path, name, ldap_dn)
			VALUES (gen_random_uuid(), $1, $2, text2ltree($3), $4, $5)
			RETURNING id::text, path::text`,
			tenantID, parentID, fullPath, name, dnVal).Scan(&id, &path); err != nil {
			return "", err
		}
		lastID, parentID, parentPath = id, id, path
	}
	if lastID == "" {
		return "", errors.New("部门链为空")
	}
	return lastID, nil
}

// ltreeLabel 把部门名转成合法的 ltree 标签。
//
// ltree 只接受字母数字下划线，中文与 & 号都得替换；替换后可能撞名，
// 因此追加名称哈希的后 8 位十六进制保证同父下唯一。
func ltreeLabel(name string) string {
	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	label := b.String()
	if len(label) > 40 {
		label = label[:40]
	}
	sum := sha256.Sum256([]byte(name))
	return fmt.Sprintf("%s_%x", label, sum[:4])
}

// upsertUser 按外部标识插入或更新。
//
// 停用/恢复的处理要点：
//   - 目录停用 → 本地 suspended，并自增 session_epoch（踢下线）
//   - 目录恢复 → 本地恢复 active（只针对由目录停用的账号，
//     管理员手工停用的账号不应被同步"悄悄放开"）
func upsertUser(ctx context.Context, tx pgx.Tx, tenantID string, u User, deptID *string, opt Options) (string, string, error) {
	var existingID, status, source string
	var directoryDisabled bool
	err := tx.QueryRow(ctx, `
		SELECT id::text, status, source, directory_disabled
		  FROM app_user
		 WHERE tenant_id = $1 AND source = 'ldap' AND lower(external_id) = lower($2)
		   AND deleted_at IS NULL`, tenantID, u.ExternalID).
		Scan(&existingID, &status, &source, &directoryDisabled)

	if errors.Is(err, pgx.ErrNoRows) {
		if opt.DryRun {
			return "created", "", nil
		}
		// 先查同名冲突再插入：能避免绝大多数报错，也让日志干净。
		//
		// 只按 source='ldap' 判重（0032 起唯一键是 tenant+source+username）：
		// 本地与域允许同名，本地账号**不再**阻止域账号导入——
		// 这正是"管理员先用本地号、后来接域"这种最常见场景卡住的地方。
		// 这里剩下的冲突只可能是"域里两个不同对象用了同一个 sAMAccountName"。
		//
		// 但这不是最终防线——真正的保证是下面的 SAVEPOINT（并发下仍可能撞上）。
		var taken bool
		if cerr := tx.QueryRow(ctx, `
			SELECT EXISTS (SELECT 1 FROM app_user
			                WHERE tenant_id = $1 AND source = 'ldap'
			                  AND lower(username) = lower($2)
			                  AND deleted_at IS NULL)`, tenantID, u.Username).Scan(&taken); cerr != nil {
			return "", "", cerr
		}
		if taken {
			return "conflict", "", nil
		}

		wantStatus := "active"
		if u.Disabled {
			wantStatus = "suspended"
		}
		var id string
		// SAVEPOINT 是必需的，不是保险：
		// PostgreSQL 里一条语句失败就把**整个事务**标记为 aborted，
		// 客户端即使捕获了错误并继续，后续任何语句都只会返回
		// "current transaction is aborted"。要"跳过这一条继续同步"，
		// 唯一正确的做法是把它关在自己的保存点里。
		if _, serr := tx.Exec(ctx, "SAVEPOINT ins_user"); serr != nil {
			return "", "", serr
		}
		ierr := tx.QueryRow(ctx, `
			INSERT INTO app_user (id, tenant_id, principal_type, source, username, email,
			                      display_name, dept_id, external_id, status, directory_disabled, synced_at)
			VALUES (gen_random_uuid(), $1, 'internal', 'ldap', $2, nullif($3,''),
			        $4, $5, $6, $7, $8, now())
			RETURNING id::text`,
			tenantID, u.Username, u.Email, displayName(u), deptID, u.ExternalID,
			wantStatus, u.Disabled).Scan(&id)
		if ierr != nil {
			// 同名账号冲突：租户里已经有同名账号（本地账号，或另一个外部标识的旧记录）。
			//
			// 这里**必须跳过而不是失败**：早先直接返回错误，导致整个同步事务回滚——
			// 目录里只要有一个与本地同名的账号（管理员自己往往就是），
			// 全公司域账号就一个都同步不进来，而且每次重试都一样。
			_, _ = tx.Exec(ctx, "ROLLBACK TO SAVEPOINT ins_user")
			var pgErr *pgconn.PgError
			if errors.As(ierr, &pgErr) && pgErr.Code == "23505" {
				return "conflict", "", nil
			}
			return "", "", ierr
		}
		if _, rerr := tx.Exec(ctx, "RELEASE SAVEPOINT ins_user"); rerr != nil {
			return "", "", rerr
		}
		return "created", id, nil
	}
	if err != nil {
		return "", "", err
	}

	outcome := "updated"
	newStatus := status
	newDisabled := directoryDisabled

	switch {
	case u.Disabled && status == "active":
		newStatus, newDisabled, outcome = "suspended", true, "disabled"
	case !u.Disabled && directoryDisabled && status != "active":
		// 只有"因目录停用"的账号才自动恢复
		newStatus, newDisabled, outcome = "active", false, "restored"
	}

	if opt.DryRun {
		return outcome, existingID, nil
	}

	_, err = tx.Exec(ctx, `
		UPDATE app_user
		   SET username = $2, email = nullif($3,''), display_name = $4, dept_id = $5,
		       status = $6, directory_disabled = $7, synced_at = now(), updated_at = now(),
		       session_epoch = CASE WHEN $6 <> 'active' AND $8 = 'active' THEN session_epoch + 1
		                            ELSE session_epoch END
		 WHERE id = $1`,
		existingID, u.Username, u.Email, displayName(u), deptID, newStatus, newDisabled, status)
	if err != nil {
		return "", "", err
	}
	return outcome, existingID, nil
}

func displayName(u User) string {
	if strings.TrimSpace(u.DisplayName) != "" {
		return u.DisplayName
	}
	return u.Username
}

func upsertGroup(ctx context.Context, tx pgx.Tx, tenantID string, g Group) (string, error) {
	var id string
	err := tx.QueryRow(ctx, `
		INSERT INTO user_group (id, tenant_id, name, kind, ldap_dn)
		VALUES (gen_random_uuid(), $1, $2, 'ldap', $3)
		ON CONFLICT (tenant_id, lower(name)) WHERE deleted_at IS NULL
		DO UPDATE SET ldap_dn = EXCLUDED.ldap_dn
		RETURNING id::text`, tenantID, g.Name, g.DN).Scan(&id)
	return id, err
}

// startRun 在独立事务里创建"运行中"记录（见 Sync 顶部说明）。
func startRun(ctx context.Context, pool *pgxpool.Pool, tenantID string) (string, error) {
	var id string
	err := db.WithTenant(ctx, pool, tenantID, func(tx pgx.Tx) error {
		// 回收"僵尸运行记录"：进程在同步中途重启/被杀时，那条 running
		// 会永远留着，界面上看起来像"同步卡住了"，而且会让人误以为
		// 现在的配置有问题。同步本身有 30 分钟超时，1 小时前的必然已中断。
		if _, e := tx.Exec(ctx, `
			UPDATE directory_sync
			   SET status='failed', finished_at=now(),
			       error='运行中断（服务重启或异常退出），本次结果未知'
			 WHERE tenant_id=$1 AND status='running'
			   AND started_at < now() - interval '1 hour'`, tenantID); e != nil {
			return e
		}
		return tx.QueryRow(ctx,
			`INSERT INTO directory_sync (id, tenant_id) VALUES (gen_random_uuid(), $1) RETURNING id::text`,
			tenantID).Scan(&id)
	})
	return id, err
}

// finishRun 把结果写回运行记录（独立事务，在业务数据提交之后）。
func finishRun(ctx context.Context, pool *pgxpool.Pool, tenantID, runID string, res Result) error {
	// 空的切片与 nil 在 pgx 里编码结果不同：nil 会变成 SQL NULL，
	// 撞上 conflict_users 的 NOT NULL 约束（本轮的第二次踩坑）。
	conflictUsers := res.ConflictUsers
	if conflictUsers == nil {
		conflictUsers = []string{}
	}
	return db.WithTenant(ctx, pool, tenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `
			UPDATE directory_sync
			   SET status='ok', finished_at=now(), watermark=$2,
			       users_seen=$3, users_created=$4, users_updated=$5,
			       users_disabled=$6, users_restored=$7,
			       groups_synced=$8, members_linked=$9, conflicts=$10,
			       conflict_users=COALESCE($11::text[], '{}')
			 WHERE id=$1`,
			runID, res.Watermark, res.Seen, res.Created, res.Updated,
			res.Disabled, res.Restored, res.GroupsSynced, res.MembersLinked,
			res.Conflicts, conflictUsers)
		return err
	})
}

// failRun 标记失败（best-effort：连失败原因都写不进去时，也只能记日志）。
func failRun(ctx context.Context, pool *pgxpool.Pool, tenantID, runID string, cause error) {
	_ = db.WithTenant(ctx, pool, tenantID, func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `
			UPDATE directory_sync SET status='failed', finished_at=now(), error=$2
			 WHERE id=$1 AND status='running'`, runID, cause.Error())
		return e
	})
}
