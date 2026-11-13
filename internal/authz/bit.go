// Package authz 实现 DocVault 的权限内核。
//
// 设计约束（见 SAD §5、FSD §3）：
//  1. 判定顺序固定，不可调换：租户 → 主体 → 对象 → 密级(MAC) → 显式拒绝 → 允许集合 → 条件 → 封顶 → 归一化。
//  2. fail-closed：任何一环取不到依据都拒绝，绝不"降级为空权限后放行"。
//  3. 位之间有蕴含关系，允许与拒绝两侧都要归一化，避免出现"能下载却不能预览"的矛盾配置。
package authz

import "strings"

// Bit 是一个原子权限位。15 位刚好放进 uint64，可整行读取、单次判定。
type Bit uint64

// 15 个原子权限位。位序一旦发布不得变更（ACE 以位图落库）。
const (
	Display       Bit = 1 << iota // 可见：看到对象与属性、列出目录
	Preview                       // 预览：打开并查看内容（含历史版本）
	Download                      // 下载：取走原文件与历史版本
	Print                         // 打印：网页打印、导出 PDF
	Copy                          // 复制：复制正文、另存、复制到其他目录
	Edit                          // 编辑：在线编辑、覆盖同名文件
	Rename                        // 重命名：改名（不改内容）
	Create                        // 新建：在该目录下新建/上传
	Move                          // 移动：需源 move + 目标 create
	Delete                        // 删除：移入回收站
	ShareInternal                 // 内部分享
	ShareExternal                 // 外部分享
	ManageVersion                 // 版本管理：设定生效版、回滚、清理
	ManageACL                     // 授权管理：受 ceiling 约束
	Owner                         // 所有者：全部能力 + 移交
)

// AllBits 是全部 15 位。
const AllBits = Display | Preview | Download | Print | Copy | Edit | Rename |
	Create | Move | Delete | ShareInternal | ShareExternal |
	ManageVersion | ManageACL | Owner

// bitName 用于日志、审计与权限解释接口。
var bitName = map[Bit]string{
	Display:       "display",
	Preview:       "preview",
	Download:      "download",
	Print:         "print",
	Copy:          "copy",
	Edit:          "edit",
	Rename:        "rename",
	Create:        "create",
	Move:          "move",
	Delete:        "delete",
	ShareInternal: "share_internal",
	ShareExternal: "share_external",
	ManageVersion: "manage_version",
	ManageACL:     "manage_acl",
	Owner:         "owner",
}

// orderedBits 固定遍历顺序，保证日志与解释链输出稳定。
var orderedBits = []Bit{
	Display, Preview, Download, Print, Copy, Edit, Rename, Create, Move,
	Delete, ShareInternal, ShareExternal, ManageVersion, ManageACL, Owner,
}

// 蕴含关系：给了 key，就必须同时具备 value 中的位。
//
// 刻意不把 Copy 挂在 Download 下：复制正文属"站内搬移内容"，
// 与"把文件取走"是不同风险，二者解耦（见 FSD §3.2）。
var implies = map[Bit]Bit{
	Preview:       Display,
	Download:      Preview | Print,
	Edit:          Preview,
	ManageVersion: Edit,
	ShareInternal: Display,
	ShareExternal: ShareInternal,
	ManageACL:     ShareInternal,
	Owner:         AllBits,
}

// Name 返回权限位名称；未知位返回 "unknown"。
func (b Bit) Name() string {
	if n, ok := bitName[b]; ok {
		return n
	}
	return "unknown"
}

// Has 判断是否包含某一位。
func (b Bit) Has(want Bit) bool { return b&want == want }

// Names 按固定顺序返回所包含位的名称，用于解释链与审计 detail。
func (b Bit) Names() []string {
	out := make([]string, 0, 15)
	for _, one := range orderedBits {
		if b.Has(one) {
			out = append(out, bitName[one])
		}
	}
	return out
}

// IsSingle 判断是否为单个合法位（判定入口只接受单个动作）。
func (b Bit) IsSingle() bool {
	if b == 0 || b&^AllBits != 0 {
		return false
	}
	return b&(b-1) == 0
}

// Normalize 反复补齐蕴含位，直到稳定。
// 之所以要循环，是因为存在链式蕴含：ManageACL → ShareInternal → Display。
func Normalize(b Bit) Bit {
	for {
		add := Bit(0)
		for from, to := range implies {
			if b.Has(from) {
				add |= to
			}
		}
		if b|add == b {
			return b
		}
		b |= add
	}
}

// Preset 是面向非 IT 用户的权限档位。
type Preset string

const (
	PresetViewer      Preset = "viewer"
	PresetCommenter   Preset = "commenter"
	PresetContributor Preset = "contributor"
	PresetEditor      Preset = "editor"
	PresetManager     Preset = "manager"
	PresetOwner       Preset = "owner"
)

// presetBits 是档位到原子位的映射，必须与 PRD/FSD 的表格逐字一致。
var presetBits = map[Preset]Bit{
	PresetViewer:      Display | Preview,
	PresetCommenter:   Display | Preview,
	PresetContributor: Display | Preview | Download | Print | Create,
	PresetEditor:      Display | Preview | Download | Print | Create | Copy | Edit | Rename,
	PresetManager:     Display | Preview | Download | Print | Create | Copy | Edit | Rename | Move | Delete | ShareInternal | ManageVersion,
	PresetOwner:       AllBits,
}

// presetLevel 是封顶等级；数值越大能力越强，用于 ceiling 比较。
var presetLevel = map[Preset]int{
	PresetViewer:      1,
	PresetCommenter:   2,
	PresetContributor: 3,
	PresetEditor:      4,
	PresetManager:     5,
	PresetOwner:       6,
}

// Bits 返回档位对应的原子位（已归一化）。
func (p Preset) Bits() Bit { return Normalize(presetBits[p]) }

// Level 返回封顶等级，未知档位为 0。
func (p Preset) Level() int { return presetLevel[p] }

// Valid 判断是否为已定义档位。
func (p Preset) Valid() bool {
	_, ok := presetBits[p]
	return ok
}

// Presets 按从弱到强返回全部档位，供界面渲染。
func Presets() []Preset {
	return []Preset{
		PresetViewer, PresetCommenter, PresetContributor,
		PresetEditor, PresetManager, PresetOwner,
	}
}

// LevelBits 返回封顶等级对应的能力位掩码。
func LevelBits(level int) Bit {
	if level <= 0 {
		return 0
	}
	if level > 6 {
		level = 6
	}
	for _, p := range Presets() {
		if p.Level() == level {
			return p.Bits()
		}
	}
	return 0
}

// ErrCeilingExceeded 表示授权方试图授出超过自身封顶的能力。
type CeilingError struct {
	GranterLevel  int
	Requested     Preset
	RequestedLvl  int
	MissingBits   Bit
	RequestedName string
}

func (e *CeilingError) Error() string {
	return "ceiling exceeded: granter level " + itoa(e.GranterLevel) +
		" cannot grant " + e.RequestedName + " (level " + itoa(e.RequestedLvl) + ")"
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

// Grantable 校验"授权方能否授出某档位"，同时返回被越权的位用于审计 detail。
func Grantable(granterLevel int, want Preset) error {
	if !want.Valid() {
		return &CeilingError{GranterLevel: granterLevel, Requested: want, RequestedName: string(want)}
	}
	if want.Level() > granterLevel {
		return &CeilingError{
			GranterLevel:  granterLevel,
			Requested:     want,
			RequestedLvl:  want.Level(),
			MissingBits:   want.Bits() &^ LevelBits(granterLevel),
			RequestedName: string(want),
		}
	}
	return nil
}

// ActionByName 把单个位名解析为动作位。
//
// 与 ParseBits 的区别：ParseBits 会补齐蕴含位（用于配置整体能力），
// 而判定入口要求"恰好一位"，所以这里严格一对一，不做归一化。
func ActionByName(name string) (Bit, bool) {
	for bit, n := range bitName {
		if n == name {
			return bit, true
		}
	}
	return 0, false
}

// ParseBits 解析逗号分隔的位名，用于配置与测试数据；未知名称返回错误而非静默忽略。
func ParseBits(s string) (Bit, error) {
	var out Bit
	for _, part := range strings.Split(s, ",") {
		name := strings.TrimSpace(part)
		if name == "" {
			continue
		}
		found := false
		for bit, n := range bitName {
			if n == name {
				out |= bit
				found = true
				break
			}
		}
		if !found {
			return 0, &UnknownBitError{Name: name}
		}
	}
	return Normalize(out), nil
}

// UnknownBitError 表示出现了未定义的权限位名称。
// 不允许静默忽略：忽略等于放宽权限（fail-closed 的反面）。
type UnknownBitError struct{ Name string }

func (e *UnknownBitError) Error() string { return "unknown permission bit: " + e.Name }
