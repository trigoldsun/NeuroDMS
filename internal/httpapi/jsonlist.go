package httpapi

import (
	"encoding"
	"encoding/json"
	"reflect"
)

// 列表字段的 JSON 约定：**空列表是 []，不是 null**。
//
// 起因（docs/E2E 验收 F-01）：新租户还没有用量事件时，
// `GET /v1/platform/tenants/{slug}/usage` 的 `points` 是 null，
// 前端每处都要写 `?? []` 兜住，漏一处就是
// `Cannot read properties of null (reading 'map')`。
//
// 逐个接口手写 `make([]T, 0)` 靠不住——新增接口时没人记得，
// 再过两个版本又会冒出一处 null。所以放在**响应出口**统一收敛：
// 编码前把 nil 切片换成空切片。
//
// 三条边界（都是刻意的）：
//   - 只处理**切片**，不碰 nil map：`null` 与 `{}` 的语义差别比 `[]` 小得多，
//     而且有些字段用 null 表示"未设置"（如 `quota`），改成 `{}` 反而骗人；
//   - **[]byte 保持 nil**：它是二进制，转成空切片会让 base64 从 null 变成 ""；
//   - 实现了 `json.Marshaler` / `TextMarshaler` 的类型不往下走：
//     它们的字段布局由自己决定（`time.Time` 展开成结构体只会是噪音）。
func nonNullLists(v any) any {
	if v == nil {
		return nil
	}
	rv := reflect.ValueOf(v)
	// 需要一个可写副本：reflect.New(...).Elem() 是可寻址的，
	// 直接改原对象（比如调用方还在用的 map/slice）不合适。
	cp := reflect.New(rv.Type()).Elem()
	cp.Set(rv)
	fixNilLists(cp, 0)
	return cp.Interface()
}

// fixNilLists 递归把 nil 切片换成空切片；depth 用来兜住意外的环形结构。
func fixNilLists(v reflect.Value, depth int) {
	if depth > 12 || !v.IsValid() {
		return
	}
	switch v.Kind() {
	case reflect.Pointer:
		if v.IsNil() {
			return
		}
		fixNilLists(v.Elem(), depth+1)

	case reflect.Interface:
		if v.IsNil() {
			return
		}
		// 接口里的动态值不可寻址：复制出来修，再塞回去
		inner := v.Elem()
		if inner.Kind() == reflect.Slice || inner.Kind() == reflect.Map ||
			inner.Kind() == reflect.Struct || inner.Kind() == reflect.Array {
			cp := reflect.New(inner.Type()).Elem()
			cp.Set(inner)
			fixNilLists(cp, depth+1)
			if v.CanSet() {
				v.Set(cp)
			}
			return
		}
		fixNilLists(inner, depth+1)

	case reflect.Slice:
		// []byte / json.RawMessage 之类的字节切片不参与：它们不是"列表"
		if v.Type().Elem().Kind() == reflect.Uint8 {
			return
		}
		if v.IsNil() {
			if v.CanSet() {
				v.Set(reflect.MakeSlice(v.Type(), 0, 0))
			}
			return
		}
		for i := 0; i < v.Len(); i++ {
			// 元素不可寻址（如 []any 里的值），先复制再修
			if !v.Index(i).CanSet() {
				continue
			}
			fixNilLists(v.Index(i), depth+1)
		}

	case reflect.Array:
		for i := 0; i < v.Len(); i++ {
			if v.Index(i).CanSet() {
				fixNilLists(v.Index(i), depth+1)
			}
		}

	case reflect.Map:
		if v.IsNil() {
			return
		}
		iter := v.MapRange()
		for iter.Next() {
			val := iter.Value()
			if !val.IsValid() {
				continue
			}
			if val.Kind() == reflect.Slice && val.IsNil() &&
				val.Type().Elem().Kind() != reflect.Uint8 {
				v.SetMapIndex(iter.Key(), reflect.MakeSlice(val.Type(), 0, 0))
				continue
			}
			// map 的元素不可寻址：复制一份可写的，修完放回
			if isMarshaler(val) {
				continue
			}
			cpv := reflect.New(val.Type()).Elem()
			cpv.Set(val)
			fixNilLists(cpv, depth+1)
			v.SetMapIndex(iter.Key(), cpv)
		}

	case reflect.Struct:
		if isMarshaler(v) {
			return
		}
		for i := 0; i < v.NumField(); i++ {
			f := v.Field(i)
			// 未导出字段 CanSet=false，跳过（也不该动）
			if !f.CanSet() {
				continue
			}
			fixNilLists(f, depth+1)
		}
	}
}

// isMarshaler 判断该值是否自带 JSON 序列化逻辑（有就不该展开它的字段）。
func isMarshaler(v reflect.Value) bool {
	if !v.IsValid() {
		return false
	}
	if v.Kind() == reflect.Pointer && v.IsNil() {
		return false
	}
	if v.CanInterface() {
		if _, ok := v.Interface().(json.Marshaler); ok {
			return true
		}
		if _, ok := v.Interface().(encoding.TextMarshaler); ok {
			return true
		}
	}
	if v.CanAddr() && v.Addr().CanInterface() {
		p := v.Addr().Interface()
		if _, ok := p.(json.Marshaler); ok {
			return true
		}
		if _, ok := p.(encoding.TextMarshaler); ok {
			return true
		}
	}
	return false
}
