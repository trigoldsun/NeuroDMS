package httpapi

import (
	"encoding/json"
	"testing"
	"time"
)

// 列表字段必须是 [] 而不是 null（docs/E2E 验收 F-01）。
// 这里直接测出口函数，不依赖数据库。
func TestNonNullListsAtResponseBoundary(t *testing.T) {
	type inner struct {
		Name  string   `json:"name"`
		Tags  []string `json:"tags"`
		Bytes []byte   `json:"bytes"`
		When  time.Time
	}
	type payload struct {
		Points   []int          `json:"points"`
		Items    []inner        `json:"items"`
		Mixed    map[string]any `json:"mixed"`
		Optional *int           `json:"optional"`
		At       *time.Time     `json:"at"`
	}

	raw, err := json.Marshal(nonNullLists(payload{
		Mixed: map[string]any{
			"list":  []string(nil),
			"objs":  []inner{{Name: "x"}},
			"nilP":  (*int)(nil),
			"empty": []int{},
		},
	}))
	if err != nil {
		t.Fatalf("编码失败: %v", err)
	}

	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("解码失败: %v", err)
	}

	// 1) 顶层 nil 切片 → []
	if v, ok := got["points"].([]any); !ok || v == nil || len(v) != 0 {
		t.Fatalf("points 应为 []，实际 %#v", got["points"])
	}
	// 2) 结构体切片 → []（不是 null）
	if v, ok := got["items"].([]any); !ok || len(v) != 0 {
		t.Fatalf("items 应为 []，实际 %#v", got["items"])
	}
	// 3) map 里的 nil 切片也要变成 []
	m := got["mixed"].(map[string]any)
	if v, ok := m["list"].([]any); !ok || len(v) != 0 {
		t.Fatalf("mixed.list 应为 []，实际 %#v", m["list"])
	}
	// 4) nil 指针字段保持 null（这是"未设置"的语义，不能改）
	if m["nilP"] != nil {
		t.Fatalf("nil 指针应保持 null，实际 %#v", m["nilP"])
	}
	if _, exists := got["optional"]; !exists || got["optional"] != nil {
		t.Fatalf("optional 应保留为 null，实际 %#v", got["optional"])
	}
	if got["at"] != nil {
		t.Fatalf("at 应保留为 null，实际 %#v", got["at"])
	}
	// 5) 已有的空切片不受影响
	if v, ok := m["empty"].([]any); !ok || len(v) != 0 {
		t.Fatalf("mixed.empty 应为 []，实际 %#v", m["empty"])
	}
}

// 结构体内部的 nil 切片同样要收敛，且 []byte 不能被改成空切片（会变成空字符串）。
func TestNonNullListsInsideStructs(t *testing.T) {
	type child struct {
		Tags  []string `json:"tags"`
		Bytes []byte   `json:"bytes"`
	}
	type wrapper struct {
		Children []child `json:"children"`
	}

	// 构造一个"有元素、元素内部列表为 nil"的载荷：
	// 这是最容易漏的形态——顶层看着不为空，但每个元素里还是 null。
	raw, err := json.Marshal(nonNullLists(wrapper{
		Children: []child{{}, {Tags: []string{"a"}}},
	}))
	if err != nil {
		t.Fatalf("编码失败: %v", err)
	}

	var got struct {
		Children []struct {
			Tags  []string `json:"tags"`
			Bytes []byte   `json:"bytes"`
		} `json:"children"`
	}
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("解码失败: %v", err)
	}
	if got.Children[0].Tags == nil {
		t.Fatal("子对象里的 nil 切片也应变成 []")
	}
	if got.Children[1].Tags == nil || len(got.Children[1].Tags) != 1 {
		t.Fatalf("已有列表被破坏：%#v", got.Children[1].Tags)
	}
	// []byte 为 nil 时保持 null（不能变成 ""）
	t.Logf("bytes(空)=%v", string(raw))
}

// nil / 非结构化载荷不能 panic（错误响应里 data 就是 nil）。
func TestNonNullListsHandlesNilAndScalars(t *testing.T) {
	for _, v := range []any{nil, 1, "x", 3.14, true} {
		_ = nonNullLists(v)
	}
	// 环状结构不应栈溢出（深度上限兜住）
	type node struct {
		Next *node `json:"next"`
		Kids []int `json:"kids"`
	}
	n := &node{}
	n.Next = n
	_ = nonNullLists(n)
}
