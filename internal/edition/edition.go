// Package edition 定义租户档位与能力矩阵。
//
// 设计原则（docs/17 §2）：
//   - 档位是**代码内置枚举**，运营只能改"某租户属于哪一档"，
//     不能改"这一档含哪些能力"。否则同一个档位在不同客户处含义不同，
//     报价单、客服话术、验收标准全部无法对齐。
//   - 档位的差异优先落在**写入口**（能写什么值、能写多大、能留几个版本），
//     而不是只藏 UI。藏 UI 只是体验，写入口才让越权数据根本不产生。
//
// 到期处理（docs/18 §5 的 SaaS 等价实现）：
//   - 到期后先给 30 天宽限，期间按原档位运行；
//   - 宽限结束按 basic 计算能力——**运行时判定，不落库、不依赖定时任务**。
//     定时任务停摆会让客户一直免费用下去，运行时判定每次都准。
package edition

import (
	"strings"
	"time"
)

// Edition 是档位枚举。
type Edition string

const (
	Basic        Edition = "basic"
	Professional Edition = "professional"
	Business     Edition = "business"
)

// GraceDays 是到期后的宽限天数。
const GraceDays = 30

// Spec 是一档的能力与配额。
type Spec struct {
	Name string

	// Classification 表示是否提供密级功能（false 时对象密级恒为 0）。
	Classification bool
	// ClassSelectable 是允许写入的密级值。空表示只能写 0。
	ClassSelectable []int

	AD           bool
	ShareMail    bool
	CustomDomain bool

	// VersionKeep 是每个文件保留的历史版本数上限。
	VersionKeep int
	// MaxUploadMB 是单文件上传上限（MB）。
	MaxUploadMB int
	// StorageGBPerSeat 是每席位容量（GB）。
	StorageGBPerSeat int
	// MaxSeats 是席位数上限，0 表示不设上限。
	MaxSeats int
}

var matrix = map[Edition]Spec{
	Basic: {
		Name:             "基础版",
		Classification:   false,
		ClassSelectable:  nil,
		AD:               false,
		ShareMail:        false,
		CustomDomain:     false,
		VersionKeep:      3,
		MaxUploadMB:      1024,
		StorageGBPerSeat: 10,
		MaxSeats:         20,
	},
	Professional: {
		Name:             "专业版",
		Classification:   true,
		ClassSelectable:  []int{0, 3, 4},
		AD:               true,
		ShareMail:        true,
		CustomDomain:     false,
		VersionKeep:      10,
		MaxUploadMB:      5120,
		StorageGBPerSeat: 20,
		MaxSeats:         0,
	},
	Business: {
		Name:             "商业版",
		Classification:   true,
		ClassSelectable:  []int{0, 1, 2, 3, 4, 5, 6},
		AD:               true,
		ShareMail:        true,
		CustomDomain:     true,
		VersionKeep:      50,
		MaxUploadMB:      10240,
		StorageGBPerSeat: 50,
		MaxSeats:         0,
	},
}

// State 是某租户在某一时刻的生效档位。
type State struct {
	// Edition 是**生效**档位（到期且过宽限后为 basic）。
	Edition Edition
	// Declared 是库里声明的档位，用于界面显示"已到期，原为专业版"。
	Declared  Edition
	Spec      Spec
	ExpiresAt *time.Time
	// InGrace 表示已到期但仍在宽限期内（仍按原档位运行）。
	InGrace bool
	// Expired 表示已过宽限期，能力按 basic 计算。
	Expired bool
}

// Normalize 把任意字符串收敛为合法档位，未知值按基础版处理。
//
// 为什么不报错：档位字段来自数据库，脏数据不应该让整个租户不可用。
// 收敛到 basic 是"最保守但不致命"的选择，同时会让能力立即受限，
// 运营很快就会发现并修正。
func Normalize(s string) Edition {
	switch Edition(strings.ToLower(strings.TrimSpace(s))) {
	case Professional:
		return Professional
	case Business:
		return Business
	default:
		return Basic
	}
}

// Resolve 计算某时刻的生效档位。
func Resolve(declared string, expires *time.Time, now time.Time) State {
	d := Normalize(declared)
	st := State{
		Edition:   d,
		Declared:  d,
		Spec:      matrix[d],
		ExpiresAt: expires,
	}
	if expires == nil {
		return st
	}
	if now.Before(*expires) {
		return st
	}
	graceEnd := expires.AddDate(0, 0, GraceDays)
	if now.Before(graceEnd) {
		st.InGrace = true
		return st
	}
	// 宽限期结束：能力降为基础版，但 Declared 保留，便于界面说明原因
	st.Edition = Basic
	st.Spec = matrix[Basic]
	st.Expired = true
	return st
}

// CanWriteClass 判断该档位能否把对象写成指定密级。
//
// 基础版并非"不能用密级功能"，而是"只能保持 0"：
// 上传不传密级时值为 0，必须放行，否则基础版连文件都传不上去。
func (s State) CanWriteClass(level int) bool {
	if level < 0 || level > 6 {
		return false
	}
	if !s.Spec.Classification {
		return level == 0
	}
	for _, v := range s.Spec.ClassSelectable {
		if v == level {
			return true
		}
	}
	return false
}

// SelectableClasses 返回可选的密级值（用于前端渲染）。
func (s State) SelectableClasses() []int {
	if !s.Spec.Classification {
		return nil
	}
	return append([]int(nil), s.Spec.ClassSelectable...)
}

// EffectiveVersionKeep 计算实际保留的版本数：取"档位上限"与"租户策略"的较小值。
//
// 租户只能把保留数调小，不能靠改策略突破档位——否则改一个配置就等于升级。
func (s State) EffectiveVersionKeep(policy int) int {
	limit := s.Spec.VersionKeep
	if policy <= 0 {
		return limit
	}
	if policy < limit {
		return policy
	}
	return limit
}

// EffectiveMaxUploadMB 计算单文件上限：同样取较小值。
func (s State) EffectiveMaxUploadMB(policy int) int {
	limit := s.Spec.MaxUploadMB
	if policy <= 0 {
		return limit
	}
	if policy < limit {
		return policy
	}
	return limit
}

// All 返回全部档位规格（运营台展示用），顺序固定。
func All() []struct {
	Edition Edition
	Spec    Spec
} {
	out := make([]struct {
		Edition Edition
		Spec    Spec
	}, 0, 3)
	for _, e := range []Edition{Basic, Professional, Business} {
		out = append(out, struct {
			Edition Edition
			Spec    Spec
		}{e, matrix[e]})
	}
	return out
}

// SelectableFor 返回某档位允许写入的密级集合（降档校验用）。
func SelectableFor(e Edition) []int {
	return matrix[Normalize(string(e))].ClassSelectable
}
