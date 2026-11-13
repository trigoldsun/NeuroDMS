package audit

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// 面向人的两类日志。
//
// 底层审计表（audit_event）是为"合规取证"设计的：追加写、哈希链、只给
// auditor 看。它不适合直接当产品日志用——普通员工看不到自己的操作，
// 系统管理员也看不到"谁改了谁的权限"。这里做一层读模型：
//
//	用户日志（user）      ：我自己的行为，只按 actor_id = 自己查
//	管理日志（management）：管理/安全治理动作，按角色收敛可见范围
//
// 分类用 LIKE 前缀而不是穷举动作名：新增埋点（例如将来 office.force_save）
// 会自动落进对应分类，而穷举清单会静默漏掉。

const (
	CategoryUser       = "user"
	CategoryManagement = "management"
)

// userPatterns 覆盖"用户对自己或自己的文件做的动作"。
var userPatterns = []string{
	"auth.%", "node.%", "folder.%", "space.%", "share.%", "upload.%",
	"office.%", "profile.%", "account.%", "batch.%", "preview.%", "version.%",
}

// managementPatterns 覆盖"管理员对他人/对系统做的动作"。
//
// share.% 与用户分类重叠的只有 approve/revoke 两条：
// 它们由审批人发起，属于治理动作，而不是"我分享了一个文件"。
var managementPatterns = []string{
	"admin.%", "acl.%", "classification.%", "tenant.%", "platform.%",
	"share.approve", "share.revoke",
}

// securityPatterns 是安全管理员可见的子集。
//
// 三权分立下 secadmin 不应看到"谁给谁改了密码"这类人事动作，
// 但必须能看到密级、授权、外发审批——这些正是它签字负责的部分。
var securityPatterns = []string{
	"classification.%", "acl.%", "share.approve", "share.revoke",
}

// CategoryPatterns 返回某分类的匹配模式。
func CategoryPatterns(category string) []string {
	switch category {
	case CategoryUser:
		return userPatterns
	case CategoryManagement:
		return managementPatterns
	default:
		return nil
	}
}

// ManagementPatternsFor 按角色收敛管理日志的可见范围。
//
// 返回 nil 表示该用户完全无权查看管理日志（调用方应回 403）。
// 判定与 requireRole 同源：三权分立违规（同时持有 auditor 与其他管理角色）
// 在这里也一并拒绝，避免"换个入口就绕过了互斥检查"。
func ManagementPatternsFor(held []string, separationViolation string) []string {
	if separationViolation != "" {
		return nil
	}
	has := func(code string) bool {
		for _, h := range held {
			if h == code {
				return true
			}
		}
		return false
	}
	// 系统管理员与审计管理员看全量；secadmin 只看安全相关
	switch {
	case has("sysadmin"), has("auditor"):
		return managementPatterns
	case has("secadmin"):
		return securityPatterns
	default:
		return nil
	}
}

// sensitiveFragments 命中即脱敏。
//
// 用"包含"而不是精确键名：埋点里出现过 passwordHash、newPassword、
// refreshToken、clientSecret 等不同写法，精确匹配一定会漏。
var sensitiveFragments = []string{"password", "passwd", "secret", "token", "credential", "privatekey", "apikey"}

// RedactDetail 把 detail 解析成 map 并抹掉敏感值。
//
// 日志页面是给几十个人看的，而 detail 里常常顺手带上了请求参数。
// 只要有一处埋点把口令写进 detail，日志页就成了口令泄露渠道——
// 所以在**读取侧**统一兜底，而不是指望每个埋点作者都记得。
func RedactDetail(raw []byte) (map[string]any, bool) {
	if len(raw) == 0 {
		return nil, false
	}
	var m map[string]any
	if json.Unmarshal(raw, &m) != nil {
		return nil, false
	}
	return redactMap(m), true
}

func redactMap(m map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		lk := strings.ToLower(strings.ReplaceAll(k, "_", ""))
		if isSensitiveKey(lk) {
			out[k] = "[已脱敏]"
			continue
		}
		switch tv := v.(type) {
		case map[string]any:
			out[k] = redactMap(tv)
		case []any:
			out[k] = redactSlice(tv)
		default:
			out[k] = v
		}
	}
	return out
}

func redactSlice(in []any) []any {
	out := make([]any, 0, len(in))
	for _, v := range in {
		if m, ok := v.(map[string]any); ok {
			out = append(out, redactMap(m))
			continue
		}
		out = append(out, v)
	}
	return out
}

func isSensitiveKey(k string) bool {
	for _, f := range sensitiveFragments {
		if strings.Contains(k, f) {
			return true
		}
	}
	return false
}

// ActivityQuery 是日志页的查询参数。
type ActivityQuery struct {
	Category string
	ActorID  string
	Action   string
	Result   string
	From     *time.Time
	To       *time.Time
	Page     int
	Size     int
}

// ActivityPage 是日志页的响应。
type ActivityPage struct {
	Items []EventRow
	Total int64
	Page  int
	Size  int
}

// maxActivitySize 限制单页条数。
//
// 前端默认 20 条。放大到几百条并不会让"查日志"更好用，
// 只会让审计表被反复大范围扫描。
const maxActivitySize = 200

// QueryActivity 读取一页日志，并给出总数。
func QueryActivity(ctx context.Context, pool *pgxpool.Pool, tenantID string, q ActivityQuery, patterns []string) (ActivityPage, error) {
	if q.Page < 1 {
		q.Page = 1
	}
	if q.Size <= 0 || q.Size > maxActivitySize {
		q.Size = 20
	}
	f := QueryFilter{
		Action:  q.Action,
		Actions: patterns,
		ActorID: q.ActorID,
		Result:  q.Result,
		From:    q.From,
		To:      q.To,
		Limit:   q.Size,
		Offset:  (q.Page - 1) * q.Size,
	}
	total, err := Count(ctx, pool, tenantID, f)
	if err != nil {
		return ActivityPage{}, err
	}
	items, err := Query(ctx, pool, tenantID, f)
	if err != nil {
		return ActivityPage{}, err
	}
	if items == nil {
		items = []EventRow{}
	}
	return ActivityPage{Items: items, Total: total, Page: q.Page, Size: q.Size}, nil
}

// activityGroups 是界面上"动作分类"下拉的取值。
//
// 之所以由服务端定义而不是让前端传 LIKE 模式：模式直接进 SQL，
// 一旦允许客户端传参，就等于把审计表的模糊匹配交给外部控制
// （`%` 能扫全表，`_` 能试探字段内容）。
var activityGroups = map[string][]string{
	"auth":    {"auth.%"},
	"file":    {"node.%", "folder.%", "space.%", "batch.%", "version.%"},
	"share":   {"share.%"},
	"office":  {"office.%", "preview.%"},
	"account": {"profile.%", "account.%"},
	"member":  {"admin.member.%", "admin.role.%", "admin.user.%"},
	"acl":     {"acl.%", "classification.%"},
	"system":  {"tenant.%", "platform.%"},
}

// GroupPatterns 取某个分组的模式；未知分组返回空。
func GroupPatterns(key string) []string {
	return activityGroups[key]
}

// IntersectPatterns 取两个模式集合的交集（各取更窄的一侧）。
//
// 用途：界面选了"分享"分组，但调用者只有权看 share.approve / share.revoke，
// 直接返回 share.% 会越权；直接返回角色集合又会让分组筛选失效。
func IntersectPatterns(base, group []string) []string {
	if len(group) == 0 {
		return base
	}
	var out []string
	for _, g := range group {
		gp := strings.TrimSuffix(g, "%")
		for _, b := range base {
			bp := strings.TrimSuffix(b, "%")
			switch {
			case strings.HasPrefix(gp, bp):
				out = append(out, g)
			case strings.HasPrefix(bp, gp):
				out = append(out, b)
			}
		}
	}
	return out
}

// MaxExportRows 是单次导出的硬上限。
//
// 导出没有上限时，一个"导出去年全部日志"的点击就足以把库拖进长事务，
// 而导出的人往往只是想贴进一份周报。
const MaxExportRows = 5000

// WriteCSV 把日志写成 CSV。
//
// 三件事必须做对：
//  1. BOM：否则 Excel 打开中文是乱码，用户会以为导出坏了；
//  2. 公式注入：单元格以 = + - @ 开头时 Excel 会当公式执行，
//     日志里的文件名/备注完全可能是攻击者可控的；
//  3. 换行/引号转义：详情里带 JSON，必然出现引号与换行。
func WriteCSV(rows []EventRow) []byte {
	var b strings.Builder
	b.WriteString("\uFEFF")
	b.WriteString("序号,时间(UTC),操作人,操作类型,动作,对象,结果,来源IP,请求ID,详情\r\n")
	for _, r := range rows {
		detail := ""
		if m, ok := RedactDetail(r.Detail); ok {
			if enc, err := json.Marshal(m); err == nil {
				detail = string(enc)
			}
		}
		actor := r.ActorName
		if actor == "" {
			actor = r.ActorID
		}
		cells := []string{
			strconv.FormatInt(r.Seq, 10),
			r.CreatedAt.UTC().Format(time.RFC3339),
			actor,
			r.ActorType,
			r.Action,
			r.ObjectID,
			r.Result,
			r.IP,
			r.RequestID,
			detail,
		}
		for i, c := range cells {
			if i > 0 {
				b.WriteString(",")
			}
			b.WriteString(csvCell(c))
		}
		b.WriteString("\r\n")
	}
	return []byte(b.String())
}

func csvCell(s string) string {
	// 公式注入：前置单引号让 Excel 按文本处理
	if s != "" && strings.ContainsRune("=+-@\t\r", rune(s[0])) {
		s = "'" + s
	}
	if strings.ContainsAny(s, ",\"\r\n") {
		return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
	}
	return s
}
