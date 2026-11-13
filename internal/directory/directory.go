// Package directory 对接 LDAP / Active Directory。
//
// 边界：
//   - 只负责"认证"与"把人与组搬进来"，不负责权限判定；
//   - 目录里被停用的账号会被本地停用，但**不删**（审计要留人）；
//   - 同步是幂等的：同一份目录数据跑两次，结果一致（除时间戳）。
package directory

import (
	"context"
	"errors"
	"time"
)

// 认证失败原因。
//
// 除"账号或口令不正确"外，其余几种都来自 AD 的 bind 子码（data 775/532/773/533/701）。
// 之所以要区分：这几种情况下用户"再试一次"永远不可能成功，必须告诉他去改口令、
// 等锁定解除或找 IT——把所有人统一成"口令错误"是现场最常见的无效工单来源。
//
// 安全权衡：这些错误只可能来自目录的真实反馈，且需要发起一次 bind 才会得到；
// 代价是"该账号在 AD 中存在"这一位信息会泄漏。企业内网系统里，可操作性优先，
// 并已由登录限速与失败计数兜底（见 auth.Service.Login）。
var (
	ErrInvalidCredentials   = errors.New("账号或口令不正确")
	ErrDirectoryUnavailable = errors.New("目录服务不可用")
	// 以下为可操作的失败原因
	ErrAccountLocked      = errors.New("域账号已被锁定")
	ErrPasswordExpired    = errors.New("域账号口令已过期")
	ErrPasswordMustChange = errors.New("域账号需要先修改口令")
	ErrAccountDisabled    = errors.New("域账号已在目录中被禁用")
)

// DeptNode 是目录里的一个组织单位（OU）。
type DeptNode struct {
	Name string
	DN   string
}

// User 是目录中的一个账号。
type User struct {
	// ExternalID 是目录侧稳定标识（AD: objectGUID 十六进制，OpenLDAP: entryUUID）
	ExternalID  string
	Username    string
	Email       string
	DisplayName string
	// DistinguishedName 用于按组解析成员关系
	DN string
	// Dept 是单一层级部门（来自 department 属性），DeptChain 为空时使用
	Dept string
	// DeptChain 是从最外层到最内层的 OU 链。
	//
	// AD 里用户的 OU 不是属性，只存在于 DN 中（CN=x,OU=A,OU=B,DC=...）。
	// 只读 department 属性会漏掉绝大多数账号，因此必须解析 DN；
	// 保留整条链是为了在本地建出部门树——权限按祖先链继承，
	// 摊平成一层会让"上级部门授权、下级部门生效"失效。
	DeptChain []DeptNode
	Disabled  bool
	// Groups 是该账号直接所属的组 DN（不含嵌套展开结果）
	Groups []string
}

// Group 是目录中的一个组。
type Group struct {
	DN      string
	Name    string
	Members []string // 直接成员 DN
	// Nested 是被嵌套包含的组 DN（AD 的 memberOf 反向关系也可由调用方补齐）
	Nested []string
}

// Snapshot 是一次目录读取的结果。
type Snapshot struct {
	Users     []User
	Groups    []Group
	Watermark string
}

// Directory 是目录服务的抽象。
//
// 抽象出接口有两个实际理由：
//  1. 同步逻辑（增删改、离职回收、组展开）能在没有真实目录的环境下被完整测试；
//  2. 将来接其他目录（如通过 SCIM 的 HR 系统）时只需实现这个接口。
type Directory interface {
	// Authenticate 用目录凭据校验口令。返回 nil 表示通过。
	Authenticate(ctx context.Context, username, password string) (User, error)
	// Fetch 拉取全量或增量快照。since 为空表示全量。
	Fetch(ctx context.Context, since string) (Snapshot, error)
	Close() error
}

// Options 是同步策略。
type Options struct {
	// DisableMissing 为真时，目录里已不存在/已停用的账号在本地被停用。
	// 生产建议开启：离职账号不回收是安全审计里最常见的发现项。
	DisableMissing bool
	// DryRun 只计算不落库，用于上线前预演（第一次同步前强烈建议跑一次）。
	DryRun bool
	// ExcludeAccounts 是不参与同步的账号名（小写比较）。
	// 默认排除域内服务账号：krbtgt 是 KDC 密钥账号，把它当"用户"列进通讯录
	// 既不专业也容易让人误选。AD 里这类账号通常已禁用，但"能出现在列表里"本身就是问题。
	ExcludeAccounts []string
	Now             func() time.Time
}

// Result 是同步结果，逐项对应"七阶段"的实际产出。
type Result struct {
	Seen          int
	Created       int
	Updated       int
	Disabled      int
	Restored      int
	GroupsSynced  int
	MembersLinked int
	// Conflicts 是"与本地同名账号冲突被跳过"的数量。
	// 必须显式统计：否则管理员只会看到"目录里 52 个、系统里 51 个"，不知道差在哪。
	Conflicts     int
	ConflictUsers []string
	Watermark     string
}
