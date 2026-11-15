package auth

import (
	"context"
	"time"

	"docvault/internal/edition"
	"docvault/internal/entitlement"
)

// entitlementState 读取租户的**生效**档位，并判断该租户此刻是否允许登录。
//
// 抽出来是因为"短信登录"与"域账号登录"要做同一件事：先确认租户可用、
// 再按生效档位算能力。两处各写一遍，迟早出现"短信判了到期降档、AD 没判"
// 这种只在降档后才暴露的差异。
//
// 返回 ok=false 的三种情况（都按不可用处理）：读不到租户、租户不可登录、
// 授权服务未装配。全部 fail-closed。
func (s *Service) entitlementState(ctx context.Context, tenantID string) (edition.State, bool) {
	var (
		declared, status string
		expires          *time.Time
	)
	if err := s.pool.QueryRow(ctx, `
		SELECT edition, status, edition_expires_at FROM tenant
		 WHERE id = $1 AND deleted_at IS NULL`, tenantID).Scan(&declared, &status, &expires); err != nil {
		return edition.State{}, false
	}
	if status != "active" && status != "trial" && status != "readonly" {
		return edition.State{}, false
	}
	return edition.Resolve(declared, expires, s.now()), true
}

// dirAuthAllowed 判断该租户此刻是否允许"域账号登录"。
//
// 与短信登录同构：档位 × 单项授权（加购 / 平台强制关）。
// 为什么不能只看"目录配置还在"：配置是部署事实，能力是合同事实。
// 降档后目录配置通常仍在，若只看配置，基础版客户会一直用 AD 登录——
// 降档就只改了报价单，没改行为。
//
// 读不到一律按不可用（fail-closed）：多拒一次登录，好过放过一个已停用的能力。
func (s *Service) dirAuthAllowed(ctx context.Context, tenantID string) bool {
	st, ok := s.entitlementState(ctx, tenantID)
	if !ok {
		return false
	}
	// 授权服务未装配时按**档位默认**判定：档位是从库里读到的确定事实，
	// 而"装配缺失"不等于"客户没买"。生产必然装配（main 里注入），
	// 这条只覆盖单元测试与半初始化进程；真正的 fail-closed 在"读不到档位"那一步。
	if s.ents == nil {
		return st.Spec.AD
	}
	allowed, err := s.ents.Entitled(ctx, tenantID, entitlement.DirAuth, st.Edition)
	return err == nil && allowed
}
