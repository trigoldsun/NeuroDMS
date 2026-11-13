package httpapi

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	"docvault/internal/db"
	"docvault/internal/edition"
	"docvault/internal/tenant"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// tenantGate 是"这个租户现在还能不能写"的唯一判定点。
//
// 为什么集中在 requireAuth 里而不是每个写接口各写一遍：
//
//	写接口会不断增加（M3 已经加了 10 个），任何一次遗漏都会让"已停用/超额"
//	的租户继续写数据。一处判定 + 一张白名单，是唯一能长期守住的做法。
//
// 只读的两个来源：
//  1. 租户状态为 readonly（试用到期、运营降级）；
//  2. 配额超限且 on_exceed=readonly（超量后先限制写，再谈扩容）。
//
// 缓存 15 秒：判定会随运营操作变化，但不是安全边界（真正的隔离在 RLS），
// 15 秒的收敛延迟可以接受，换来的是每个写请求不多打两次库。
type gateState struct {
	readonly bool
	reason   string
	at       time.Time
}

type gateCache struct {
	mu sync.RWMutex
	m  map[string]gateState
}

const gateTTL = 15 * time.Second

// tenantWriteBlocked 返回是否应拒绝写操作及原因。
func (a *API) tenantWriteBlocked(ctx context.Context, tenantID string) (bool, string) {
	// 读路径不加写锁：先取到 map 引用再判断。
	//
	// 这里曾经写成"先 if a.gate.m == nil { a.gate.m = make(...) } 再 RLock"——
	// 那次赋值发生在锁外，并发请求下就是一次对 map 字段的数据竞争
	// （race detector 只有在并发打同一租户时才会报，平时看不出来）。
	a.gate.mu.RLock()
	if a.gate.m != nil {
		if st, ok := a.gate.m[tenantID]; ok && time.Since(st.at) < gateTTL {
			a.gate.mu.RUnlock()
			return st.readonly, st.reason
		}
	}
	a.gate.mu.RUnlock()

	st := a.loadGate(ctx, tenantID)
	a.gate.mu.Lock()
	if a.gate.m == nil {
		a.gate.m = make(map[string]gateState)
	}
	// 简单容量护栏：租户数量级远小于此
	if len(a.gate.m) > 10000 {
		a.gate.m = make(map[string]gateState)
	}
	a.gate.m[tenantID] = st
	a.gate.mu.Unlock()
	return st.readonly, st.reason
}

func (a *API) loadGate(ctx context.Context, tenantID string) gateState {
	now := time.Now()

	// 判定失败一律**放行**：这是可用性取舍。
	// 租户状态与配额是运营约束，不是安全边界——因为一次查询抖动把所有客户
	// 变成只读，造成的损失远大于"停用晚生效 15 秒"。
	if a.Tenants == nil {
		return gateState{at: now}
	}

	var status string
	if err := db.WithTenant(ctx, a.Pool, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT status FROM tenant WHERE id = $1`, tenantID).Scan(&status)
	}); err != nil {
		return gateState{at: now}
	}
	if tenant.ReadOnly(status) {
		return gateState{readonly: true, reason: "tenant_readonly", at: now}
	}

	if a.Metering != nil {
		if st, err := a.Metering.LoadState(ctx, tenantID); err == nil {
			if blocked, why := st.WritesBlocked(); blocked {
				return gateState{readonly: true, reason: "quota:" + why, at: now}
			}
		}
	}
	return gateState{at: now}
}

// invalidateGate 在状态变更后清缓存（本实例立即生效）。
func (a *API) invalidateGate(tenantID string) {
	a.gate.mu.Lock()
	delete(a.gate.m, tenantID)
	a.gate.mu.Unlock()
}

// writableMethod 判断该方法是否属于"写"。
// GET/HEAD/OPTIONS 只读；其余一律按写处理——宁可多拦一个只读的 POST，
// 也不要漏掉一个真正改数据的 PUT/PATCH/DELETE。
func writableMethod(m string) bool {
	switch m {
	case "GET", "HEAD", "OPTIONS":
		return false
	}
	return true
}

// gateExempt 是只读状态下**仍然允许**的写路径（账号安全与退出）。
//
// 这些操作的共同点：不产生业务数据，且如果被禁止会让用户卡在
// "想改密码解不了、想退出退不掉"的状态。
func gateExempt(path string) bool {
	switch {
	case strings.HasPrefix(path, "/v1/auth/"):
		return true
	case strings.HasPrefix(path, "/v1/me/"):
		return true
	}
	return false
}

// tenantPolicy 读取租户策略。读不到时返回零值（调用方按系统默认处理）。
func (a *API) tenantPolicy(ctx context.Context, tenantID string) (tenant.Policy, error) {
	if a.Tenants == nil {
		return tenant.Policy{}, nil
	}
	return a.Tenants.GetPolicy(ctx, tenantID)
}

// editionState 读取租户当前生效档位（含到期与宽限判定）。
//
// 读失败一律返回错误，由调用方转 503。授权不可判定时放行，
// 等于开了一个"数据库抖动期间全功能可用"的后门——这是档位体系里最不能犯的错。
func (a *API) editionState(ctx context.Context, tenantID string) (edition.State, error) {
	var ed string
	var expires *time.Time
	err := db.WithTenant(ctx, a.Pool, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT edition, edition_expires_at FROM tenant WHERE id = $1`, tenantID).
			Scan(&ed, &expires)
	})
	if err != nil {
		return edition.State{}, err
	}
	return edition.Resolve(ed, expires, time.Now()), nil
}

// isQuotaErr 判断错误是否来自数据库的配额硬拦截（SQLSTATE DV403）。
//
// 触发器抛出的异常在应用层是普通 error，如果不翻译，客户看到的是 500
// "上传失败"——而真实原因是"配额满了，该扩容了"。这类错误必须可读。
func isQuotaErr(err error) (string, bool) {
	var pe *pgconn.PgError
	if !errors.As(err, &pe) || pe.Code != "DV403" {
		return "", false
	}
	// MESSAGE 形如 "quota:storage"
	if i := strings.Index(pe.Message, ":"); i >= 0 {
		return pe.Message[i+1:], true
	}
	return "storage", true
}
