package httpapi

// 审计里的"改前 / 改后"。
//
// 起因是一条很具体的追问：审计日志里只有"谁在什么时候改了策略"，
// 却没有"从多少改成多少"。这样的记录事后回答不了三个最关键的问题：
//   1. 这次提交是真的改了，还是原样保存了一遍？
//   2. 某个参数是哪一天从 100 变成 200 的？
//   3. 出事那次变更，到底动了哪一项？
// 所以配置类的审计一律带 before / after，并且只放**发生了变化的字段**：
// 全量快照看起来很完整，实际会把"改了哪一项"埋在一堆未变字段里。

import (
	"encoding/json"
	"reflect"
	"sort"
)

// auditDiff 组装改动前后对照。
//
// 返回形如：
//
//	{"before": {"maxUploadMB": 100}, "after": {"maxUploadMB": 200}, "changed": ["maxUploadMB"]}
//
// 三条约定：
//   - 只包含发生变化的字段。没有变化时 before/after 都不出现，changed 为空数组，
//     前端据此显示"原样保存，未改动"——这本身就是有价值的事实。
//   - before 为 nil（读不到旧值）时，所有字段都算"新增"，前端显示"— → 新值"。
//     不编造旧值比编造一个看起来合理的旧值安全。
//   - 值只放标量或字符串数组。口令类字段一律不进来，另用 xxxChanged 布尔标记。
func auditDiff(before, after map[string]any) map[string]any {
	keys := make([]string, 0, len(before)+len(after))
	seen := make(map[string]bool, len(before)+len(after))
	for k := range before {
		if !seen[k] {
			seen[k] = true
			keys = append(keys, k)
		}
	}
	for k := range after {
		if !seen[k] {
			seen[k] = true
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)

	oldVals := map[string]any{}
	newVals := map[string]any{}
	changed := make([]string, 0, len(keys))
	for _, k := range keys {
		if reflect.DeepEqual(before[k], after[k]) {
			continue
		}
		changed = append(changed, k)
		oldVals[k] = before[k]
		newVals[k] = after[k]
	}

	out := map[string]any{"changed": changed}
	if len(changed) > 0 {
		// before 未知（读不到旧值）时整个省略：界面据此显示"—"，
		// 而不是把 nil 当成"该项原来是空"。
		if before != nil {
			out["before"] = oldVals
		}
		out["after"] = newVals
	}
	return out
}

// jsonMap 把结构体转成 JSON 友好的 map。
//
// 用它而不是手写字段清单：策略这类结构以后加字段时，审计不会因为
// 忘了补一行而漏记——漏记的审计比没有审计更容易误导人。
func jsonMap(v any) map[string]any {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	var m map[string]any
	if json.Unmarshal(raw, &m) != nil {
		return nil
	}
	return m
}
