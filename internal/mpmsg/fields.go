package mpmsg

// 模板字段映射。
//
// 为什么要可配置：订阅消息的 `data` 必须与**公众平台上那个模板的字段**逐字对应，
// 多一个、少一个、类型不对都会被微信拒绝（47003 / 47004）。
// 模板是客户在后台选的，字段名（`thing1` / `character_string2` / `phrase3`…）
// 事先不可能知道，所以只能由部署方声明"字段 → 语义"的映射。
//
// 语义键固定四个（本系统的提醒内容就这四样）：
//   name       文件名称
//   requester  申请人
//   time       申请时间
//   status     状态（当前固定"待审批"）
//
// 配置写法（DOCVAULT_WX_TODO_FIELDS）：
//   thing1=name,thing2=requester,time3=time,phrase4=status
// 留空则使用下面这套默认值（与 docs/31 §14 的默认模板一致）。

import (
	"errors"
	"fmt"
	"strings"
)

// 语义键。
const (
	SemName      = "name"
	SemRequester = "requester"
	SemTime      = "time"
	SemStatus    = "status"
)

var semanticKeys = map[string]bool{SemName: true, SemRequester: true, SemTime: true, SemStatus: true}

// DefaultFields 是"未声明映射"时的默认字段（按文档约定）。
var DefaultFields = map[string]string{
	"thing1":  SemName,
	"thing2":  SemRequester,
	"time3":   SemTime,
	"phrase4": SemStatus,
}

// ParseFields 解析 "字段名=语义键[,字段名=语义键…]"。
//
// 三条校验，缺一条都会在真机上变成"授权成功但收不到消息"：
//  1. 字段名非空且不含空白（微信字段名是固定标识，不是标题）；
//  2. 语义键必须是已知四个之一（写错等于把"申请人"塞进"文件名称"）；
//  3. 同一个语义键不能出现两次（模板里两个字段显示同一内容，用户会以为是 bug）。
//
// 不强制四个语义齐全：模板可能只有三个字段（例如没有"状态"），
// 少发一个字段是允许的，多发一个不允许。
func ParseFields(spec string) (map[string]string, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return nil, nil // nil 表示用 DefaultFields
	}
	out := map[string]string{}
	seen := map[string]string{}
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		k, v, ok := strings.Cut(part, "=")
		k = strings.TrimSpace(k)
		v = strings.TrimSpace(v)
		if !ok || k == "" || v == "" {
			return nil, fmt.Errorf("字段映射 %q 不是「字段名=语义键」", part)
		}
		if strings.ContainsAny(k, " \t") {
			return nil, fmt.Errorf("字段名 %q 不能包含空白", k)
		}
		if !semanticKeys[v] {
			return nil, fmt.Errorf("语义键 %q 不合法，只能是 name / requester / time / status", v)
		}
		if prev, dup := seen[v]; dup {
			return nil, fmt.Errorf("语义键 %q 被 %s 与 %s 重复使用", v, prev, k)
		}
		seen[v] = k
		out[k] = v
	}
	if len(out) == 0 {
		return nil, errors.New("字段映射为空")
	}
	return out, nil
}

// MPState 是点击通知后跳转的小程序版本。
const (
	StateDeveloper = "developer"
	StateTrial     = "trial"
	StateFormal    = "formal"
)

// ParseMPState 解析 DOCVAULT_WX_MP_STATE。
//
// 为什么要配：开发版/体验版测试时，`formal` 会跳到线上正式版——
// 要么打不开（还没发布），要么打开的是旧代码，测试结论完全失真。
// 非法值直接报错而不是回落 formal：静默回落会让"配了 developer 却跳正式版"
// 这种问题以"偶发"的面目出现。
func ParseMPState(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return StateFormal, nil
	}
	switch s {
	case StateDeveloper, StateTrial, StateFormal:
		return s, nil
	default:
		return "", fmt.Errorf("DOCVAULT_WX_MP_STATE=%q 不合法，只能是 developer / trial / formal", s)
	}
}

// valueOf 返回某个语义键对应的展示值。
func valueOf(semantic string, t Todo) string {
	switch semantic {
	case SemName:
		return t.FileName
	case SemRequester:
		return t.Requester
	case SemTime:
		if t.CreatedAt.IsZero() {
			return ""
		}
		return t.CreatedAt.Format("2006-01-02 15:04")
	case SemStatus:
		return "待审批"
	default:
		return ""
	}
}

// clipByField 按微信的**字段类型**截断。
//
// 微信的限制是分类型的：thing 20 个字符、phrase 5 个汉字、name 10 个汉字、
// character_string 32 个字符。统一按 20 字截断会让 phrase 超长（47003），
// 也会让 character_string 被无谓地截短。
func clipByField(field, val string) string {
	r := []rune(strings.TrimSpace(val))
	limit := 20
	switch {
	case strings.HasPrefix(field, "phrase"):
		limit = 5
	case strings.HasPrefix(field, "name"):
		limit = 10
	case strings.HasPrefix(field, "character_string"):
		limit = 32
	case strings.HasPrefix(field, "thing"):
		limit = 20
	case strings.HasPrefix(field, "time"), strings.HasPrefix(field, "date"):
		limit = 32 // 时间/日期不截断，格式由 valueOf 保证
	}
	if len(r) <= limit {
		return string(r)
	}
	return string(r[:limit])
}
