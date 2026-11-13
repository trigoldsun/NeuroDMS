package tenant

// 租户档位（docs/17 §2、§4）。
//
// 与 feature_flag 的区别必须记牢：flag 是"发布节奏"，档位是"买了什么"。
// 把两者混用，客服就无法回答"这个功能是没买，还是灰度没覆盖到"。

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

var (
	// ErrInvalidEdition 表示档位名不合法。
	ErrInvalidEdition = errors.New("未知档位")
	// ErrEditionDowngradeBlocked 表示目标档位无法表达现有密级数据。
	// 调用方应把清单展示给运营，先降密再降档。
	ErrEditionDowngradeBlocked = errors.New("存在目标档位无法表达的密级对象")
)

// EditionInfo 是租户档位与最近变更。
type EditionInfo struct {
	TenantID  string          `json:"tenantId"`
	Edition   string          `json:"edition"`
	ExpiresAt *time.Time      `json:"expiresAt"`
	Changes   json.RawMessage `json:"changes"`
}

// EditionChange 是一次改档的结果。
type EditionChange struct {
	TenantID       string     `json:"tenantId"`
	PrevEdition    string     `json:"prevEdition"`
	CurEdition     string     `json:"curEdition"`
	PrevExpires    *time.Time `json:"prevExpires"`
	CurExpires     *time.Time `json:"curExpires"`
	BlockedCount   int        `json:"blockedCount"`
	BlockedSamples []string   `json:"blockedSamples,omitempty"`
}

// GetEdition 读取租户档位与最近 20 次变更。
func (s *Service) GetEdition(ctx context.Context, slug string) (EditionInfo, error) {
	var out EditionInfo
	err := s.pool.QueryRow(ctx,
		`SELECT tid::text, edition, expires_at, changes FROM platform_tenant_edition($1)`,
		strings.ToLower(strings.TrimSpace(slug))).
		Scan(&out.TenantID, &out.Edition, &out.ExpiresAt, &out.Changes)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return EditionInfo{}, ErrNotFound
		}
		return EditionInfo{}, fmt.Errorf("读取档位失败: %w", err)
	}
	return out, nil
}

// SetEdition 改档。降档时先校验密级兼容性，不通过则整体不生效。
func (s *Service) SetEdition(ctx context.Context, slug, ed string, expires *time.Time, reason, operator string) (EditionChange, error) {
	var out EditionChange
	err := s.pool.QueryRow(ctx, `
		SELECT tid::text, prev_edition, cur_edition, prev_expires, cur_expires,
		       blocked_count, blocked_samples
		  FROM platform_tenant_set_edition($1, $2, $3, $4, $5)`,
		strings.ToLower(strings.TrimSpace(slug)), ed, expires, reason, operator).
		Scan(&out.TenantID, &out.PrevEdition, &out.CurEdition,
			&out.PrevExpires, &out.CurExpires, &out.BlockedCount, &out.BlockedSamples)
	if err != nil {
		switch {
		case isCode(err, "DV404") || errors.Is(err, pgx.ErrNoRows):
			return EditionChange{}, ErrNotFound
		case isCode(err, "DV002"):
			return EditionChange{}, ErrInvalidEdition
		default:
			return EditionChange{}, fmt.Errorf("变更档位失败: %w", err)
		}
	}
	if out.BlockedCount > 0 {
		return out, ErrEditionDowngradeBlocked
	}
	return out, nil
}
