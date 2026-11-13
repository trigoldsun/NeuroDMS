package authz

import (
	"context"
	"net/netip"
	"time"
)

// Subject 是权限判定的主体快照。
// 之所以做成快照而非在判定过程中反复查库，是为了让判定成为纯函数、可测试、可缓存。
type Subject struct {
	ID          string
	TenantID    string
	IsExternal  bool
	IsAnonymous bool
	Active      bool

	// Epoch 来自令牌，TokenEpoch 来自会话记录；不相等说明会话已被吊销。
	Epoch      int
	TokenEpoch int

	// Class 是用户密级；判定时与对象密级比较（MAC，先于 ACL）。
	Class int
	// Ceiling 是封顶等级（1..6），决定能授出的最高档位。
	Ceiling int

	DeptPaths []string
	RoleIDs   []string
	GroupIDs  []string

	// 以下字段供条件表达式求值。
	IP             netip.Addr
	TrustedDevice  bool
	MFASatisfied   bool
	ApprovalState  string
	DownloadsToday int
}

// Object 是判定对象的最小投影。
type Object struct {
	ID       string
	TenantID string
	Type     string // space | node
	Class    int
	Deleted  bool
}

// Condition 是条件表达式的一项；多项之间为 AND。
type Condition struct {
	Key   string
	Op    string
	Value any
}

// ACE 是一条访问控制条目。位图落库，条件为 JSONB。
type ACE struct {
	SubjectType string // user|dept|role|group|external|anonymous
	SubjectID   string
	Allow       Bit
	Deny        Bit
	Conditions  []Condition
	// Depth 是对象在树中的深度：空间根为 0，越深越大。用于"就近显式优先"。
	Depth     int
	ExpiresAt *time.Time
	ID        string
}

// 判定原因，稳定字符串，可直接进审计与解释接口。
const (
	ReasonOK             = "OK"
	ReasonTenantMismatch = "TENANT_MISMATCH"
	ReasonSessionInvalid = "SESSION_INVALID"
	ReasonNotFound       = "NOT_FOUND"
	ReasonClassification = "CLASSIFICATION_DENIED"
	ReasonExplicitDeny   = "EXPLICIT_DENY"
	ReasonNoAllow        = "NO_ALLOW"
	ReasonCondition      = "CONDITION_NOT_MET"
	ReasonCeiling        = "CEILING"
	ReasonACLLoadError   = "ACL_LOAD_ERROR"
	ReasonInvalidAction  = "INVALID_ACTION"
)

// Decision 是判定结果。Chain 记录依据，供解释接口与越权排障使用。
type Decision struct {
	Allowed bool
	Reason  string
	Bits    Bit
	Chain   []string
}

// Step 是判定过程中的一步，供权限解释接口展示。
//
// 为什么要暴露分步而不是只给结论：越权工单里 80% 的时间花在
// "到底卡在哪一步"。只回 403 的话，运维只能靠猜——猜错就会去改 ACL，
// 而真正的原因是密级或会话过期。
type Step struct {
	Name   string `json:"step"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail,omitempty"`
}

// Explanation 是带分步轨迹的判定结果。
type Explanation struct {
	Decision
	Steps []Step
}

// deny 构造一个拒绝结果。
func deny(reason string, chain ...string) Decision {
	return Decision{Allowed: false, Reason: reason, Chain: chain}
}

// RuleSource 提供某主体在某对象上可见的 ACE 集合（含从祖先继承而来的部分）。
//
// 关键纪律：Load 返回 error 时，调用方必须判拒。
// 历史事故（0201-C3）就是"查询失败 → 当作空结果 → 按角色基线放行"。
type RuleSource interface {
	Load(ctx context.Context, sub Subject, obj Object) ([]ACE, error)
}

// Authorize 按固定顺序判定。
//
// 顺序不可调换的理由：密级是"不允许给"，ACL 是"可以给"；
// 若先算 ACL，则管理员给自己授权即可绕过密级。
//
// 关于 ceiling：本函数只判"这个人对这份文件能做什么"，不看 ceiling；
// ceiling 在授权路径（ace.Grant → authz.Grantable）里生效。
func Authorize(ctx context.Context, src RuleSource, sub Subject, obj Object, act Bit, now time.Time) (Decision, error) {
	ex, err := Explain(ctx, src, sub, obj, act, now)
	return ex.Decision, err
}

// Explain 与 Authorize 是**同一份实现**，只是额外返回分步轨迹。
//
// 独立再写一份"解释版判定"是绝对不允许的：两份逻辑一旦漂移，
// 解释接口会告诉你"应该能下载"，实际却 403——比没有解释更糟。
func Explain(ctx context.Context, src RuleSource, sub Subject, obj Object, act Bit, now time.Time) (Explanation, error) {
	steps := make([]Step, 0, 8)
	fail := func(reason string, chain ...string) (Explanation, error) {
		return Explanation{Decision: deny(reason, chain...), Steps: steps}, nil
	}

	if !act.IsSingle() {
		steps = append(steps, Step{Name: "action", OK: false, Detail: "动作必须是单个权限位"})
		return Explanation{Decision: deny(ReasonInvalidAction), Steps: steps}, &InvalidActionError{Action: act}
	}
	steps = append(steps, Step{Name: "action", OK: true, Detail: act.Name()})

	// 1 租户
	if sub.TenantID == "" || sub.TenantID != obj.TenantID {
		steps = append(steps, Step{Name: "tenant", OK: false, Detail: "主体与对象不同租户"})
		return fail(ReasonTenantMismatch)
	}
	steps = append(steps, Step{Name: "tenant", OK: true})

	// 2 主体有效性（含会话吊销）
	if !sub.Active || sub.Epoch != sub.TokenEpoch {
		steps = append(steps, Step{Name: "session", OK: false,
			Detail: "active=" + boolStr(sub.Active) + " epoch=" + itoa(sub.Epoch) + " token_epoch=" + itoa(sub.TokenEpoch)})
		return fail(ReasonSessionInvalid)
	}
	steps = append(steps, Step{Name: "session", OK: true})

	// 3 对象存在性：已删除与不存在同样处理，避免泄漏"曾经存在"
	if obj.ID == "" || obj.Deleted {
		steps = append(steps, Step{Name: "object", OK: false, Detail: "对象不存在或已删除"})
		return fail(ReasonNotFound)
	}
	steps = append(steps, Step{Name: "object", OK: true})

	// 4 密级强制门（MAC）：ACL 全开也不能突破
	if sub.Class < obj.Class {
		steps = append(steps, Step{Name: "classification", OK: false,
			Detail: "user_class=" + itoa(sub.Class) + " object_class=" + itoa(obj.Class)})
		return fail(ReasonClassification, "user_class="+itoa(sub.Class), "object_class="+itoa(obj.Class))
	}
	steps = append(steps, Step{Name: "classification", OK: true,
		Detail: "user_class=" + itoa(sub.Class) + " object_class=" + itoa(obj.Class)})

	// 5 取 ACE：失败即拒（fail-closed），不得降级为空集合后继续
	aces, err := src.Load(ctx, sub, obj)
	if err != nil {
		steps = append(steps, Step{Name: "acl_load", OK: false, Detail: "权限条目读取失败"})
		return Explanation{Decision: deny(ReasonACLLoadError), Steps: steps}, err
	}
	steps = append(steps, Step{Name: "acl_load", OK: true, Detail: "条目数=" + itoa(len(aces))})

	keys := subjectKeys(sub)
	matched := make([]ACE, 0, len(aces))
	for _, aceRow := range aces {
		if aceRow.ExpiresAt != nil && !aceRow.ExpiresAt.After(now) {
			continue // 临时授权已到期
		}
		if !keys[aceRow.SubjectType+":"+aceRow.SubjectID] {
			continue
		}
		matched = append(matched, aceRow)
	}
	steps = append(steps, Step{Name: "subject_match", OK: len(matched) > 0, Detail: "命中条目=" + itoa(len(matched))})

	// 6 显式拒绝：任何一条命中即拒，且不被更深层的允许覆盖
	for _, aceRow := range matched {
		if aceRow.Deny.Has(act) {
			steps = append(steps, Step{Name: "explicit_deny", OK: false,
				Detail: "ace=" + aceRow.ID + " deny=" + act.Name()})
			return fail(ReasonExplicitDeny, "ace="+aceRow.ID, "deny="+act.Name())
		}
	}
	steps = append(steps, Step{Name: "explicit_deny", OK: true, Detail: "无命中拒绝"})

	// 7 允许集合：就近显式优先
	// 只在"显式设置了该位"的 ACE 之间比较深度，未提及该位的深层 ACE 不构成阻断。
	//
	// 用 found 标志而不是把 maxDepth 初始化成 -1：depth 由数据源给出，
	// 一旦出现负值（历史数据、其他 RuleSource 实现），-1 哨兵会把所有条目都判成
	// "没有一条授予"，表现是"明明有权限却 403"，且极难排查。
	maxDepth, found := 0, false
	for _, aceRow := range matched {
		if !aceRow.Allow.Has(act) {
			continue
		}
		if !found || aceRow.Depth > maxDepth {
			maxDepth, found = aceRow.Depth, true
		}
	}
	if !found {
		steps = append(steps, Step{Name: "allow_set", OK: false, Detail: "没有任何条目授予 " + act.Name()})
		return fail(ReasonNoAllow)
	}
	steps = append(steps, Step{Name: "allow_set", OK: true, Detail: "最大深度=" + itoa(maxDepth)})

	var winning *ACE
	for i := range matched {
		aceRow := &matched[i]
		if aceRow.Depth == maxDepth && aceRow.Allow.Has(act) {
			winning = aceRow
			break
		}
	}

	// 8 条件求值：未知条件键视为不满足（fail-closed）
	if winning != nil {
		for _, c := range winning.Conditions {
			ok, known := evalCondition(c, sub, obj, now)
			if !known {
				steps = append(steps, Step{Name: "condition", OK: false, Detail: "未知条件键=" + c.Key})
				return fail(ReasonCondition, "unknown_condition="+c.Key)
			}
			if !ok {
				steps = append(steps, Step{Name: "condition", OK: false, Detail: "条件不满足=" + c.Key})
				return fail(ReasonCondition, "condition="+c.Key)
			}
		}
		steps = append(steps, Step{Name: "condition", OK: true, Detail: "条件全部满足"})
	}

	// 9 归一化：补齐蕴含位，保证结果自洽
	//
	// 注意：这里**不做** ceiling 校验。ceiling 的语义是"最多能授出多高的档位"，
	// 用于防止授权链上的权限膨胀；它不限制本人依据 ACL 能做什么。
	// 早期版本把两者混在一起，结果是"空间所有者因其用户 ceiling=editor 而无法授权"，
	// 由集成测试暴露后修正（见 FSD §3.4）。
	granted := Normalize(act)
	chain := []string{}
	if winning != nil {
		chain = append(chain, "ace="+winning.ID, "depth="+itoa(winning.Depth))
		steps = append(steps, Step{Name: "winning_ace", OK: true,
			Detail: "ace=" + winning.ID + " depth=" + itoa(winning.Depth)})
	}
	steps = append(steps, Step{Name: "result", OK: true, Detail: "允许 " + act.Name()})
	return Explanation{
		Decision: Decision{Allowed: true, Reason: ReasonOK, Bits: granted, Chain: chain},
		Steps:    steps,
	}, nil
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// subjectKeys 把主体展开成可匹配的键集合。
// 部门用路径匹配，因此授权在父部门时，子部门成员自动命中。
func subjectKeys(sub Subject) map[string]bool {
	keys := make(map[string]bool, len(sub.DeptPaths)+len(sub.RoleIDs)+len(sub.GroupIDs)+2)
	if sub.IsAnonymous {
		keys["anonymous:"] = true
		return keys
	}
	if sub.IsExternal {
		keys["external:"+sub.ID] = true
	} else {
		keys["user:"+sub.ID] = true
	}
	for _, d := range sub.DeptPaths {
		keys["dept:"+d] = true
	}
	for _, r := range sub.RoleIDs {
		keys["role:"+r] = true
	}
	for _, g := range sub.GroupIDs {
		keys["group:"+g] = true
	}
	return keys
}

// evalCondition 返回 (是否满足, 是否为已知键)。
// 第二个返回值为 false 时调用方必须判拒——未知条件键绝不能当作"无此条件"放行。
func evalCondition(c Condition, sub Subject, obj Object, now time.Time) (bool, bool) {
	switch c.Key {
	case "mfa_satisfied":
		want, ok := c.Value.(bool)
		return ok && sub.MFASatisfied == want, true

	case "device_trust":
		want, ok := c.Value.(bool)
		return ok && sub.TrustedDevice == want, true

	case "watermark_required":
		// 水印是出站渲染的属性，不构成准入条件；这里显式声明为"恒满足"，避免被误用为拒绝理由。
		return true, true

	case "approval_state":
		want, ok := c.Value.(string)
		return ok && sub.ApprovalState == want, true

	case "download_quota":
		limit, ok := toInt(c.Value)
		return ok && sub.DownloadsToday < limit, true

	case "ip_cidr":
		return matchCIDR(c.Value, sub.IP), true

	default:
		return false, false
	}
}

// matchCIDR 判断主体 IP 是否落在任一网段内。
func matchCIDR(v any, ip netip.Addr) bool {
	if !ip.IsValid() {
		return false
	}
	list, ok := v.([]any)
	if !ok {
		if s, isStr := v.(string); isStr {
			list = []any{s}
		} else {
			return false
		}
	}
	for _, item := range list {
		s, ok := item.(string)
		if !ok {
			continue
		}
		prefix, err := netip.ParsePrefix(s)
		if err != nil {
			continue
		}
		if prefix.Contains(ip) {
			return true
		}
	}
	return false
}

func toInt(v any) (int, bool) {
	switch n := v.(type) {
	case int:
		return n, true
	case int64:
		return int(n), true
	case float64:
		return int(n), true
	default:
		return 0, false
	}
}

// InvalidActionError 表示传入的动作不是单个合法位。
type InvalidActionError struct{ Action Bit }

func (e *InvalidActionError) Error() string {
	return "invalid action: must be exactly one permission bit"
}
