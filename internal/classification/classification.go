// Package classification 实现密级体系：定密、降密审批、标签收紧。
//
// 三条不可让渡的规则（缺一条密级就是装饰）：
//  1. 对象密级必须真正进入判定（authz.Object.Class），否则引擎里的密级门永不触发；
//  2. 定密不得超过本人密级（否则自己造一份"只有自己能看"的密级，或反过来标低规避管控）；
//  3. 降密必须审批（降密 = 扩大知悉范围，是唯一需要第二人确认的密级动作）。
//
// 标签只用来**收紧**：effective = max(对象密级, 标签策略下限)。
// 任何"标签可以放宽权限"的设计都会成为绕过 ACE 的第二条授权通道。
package classification

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
)

// MaxLevel 是密级上限（0..6，与 schema 的 CHECK 一致）。
const MaxLevel = 6

// ErrBadLevel 表示密级超出 0..6。
var ErrBadLevel = errors.New("密级必须在 0..6 之间")

// ErrAboveSelf 表示试图给自己无权掌握的密级定密。
var ErrAboveSelf = errors.New("不能设置高于自身密级的密级")

// ErrNotFound 表示对象或申请不存在。
var ErrNotFound = errors.New("对象不存在")

// ErrPendingExists 表示该对象已有待审的密级变更申请。
var ErrPendingExists = errors.New("该对象已有待审批的密级变更申请")

// ErrNotPending 表示申请已处理过，不能重复审批。
var ErrNotPending = errors.New("该申请已处理")

// defaultLabels 是内置密级名称。租户可改显示名，但等级语义固定。
var defaultLabels = map[int]struct {
	Name string
	Desc string
}{
	0: {"公开", "可在组织外自由传播"},
	1: {"内部", "仅组织内成员可见"},
	2: {"敏感", "仅相关部门可见"},
	3: {"秘密", "仅限于项目成员，外发需审批"},
	4: {"机密", "仅限于授权人员，外发需审批并留痕"},
	5: {"绝密", "仅限指定人员，禁止外发"},
	6: {"核心", "最高保护级别，禁止任何形式外发"},
}

// Label 是一个密级的展示信息。
type Label struct {
	Level       int    `json:"level"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

// Levels 返回租户的密级定义（缺省行用内置名称补齐）。
//
// 用"读时补齐"而不是"建租户时插入"：存量租户与测试租户都不会缺行，
// 也不会因为一次迁移遗漏就出现"密级列表为空"的界面。
func Levels(ctx context.Context, tx pgx.Tx, tenantID string) ([]Label, error) {
	rows, err := tx.Query(ctx,
		`SELECT level, name, description FROM classification_label WHERE tenant_id = $1`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	custom := map[int]Label{}
	for rows.Next() {
		var l Label
		if err := rows.Scan(&l.Level, &l.Name, &l.Description); err != nil {
			return nil, err
		}
		custom[l.Level] = l
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	out := make([]Label, 0, MaxLevel+1)
	for lv := 0; lv <= MaxLevel; lv++ {
		if l, ok := custom[lv]; ok {
			out = append(out, l)
			continue
		}
		d := defaultLabels[lv]
		out = append(out, Label{Level: lv, Name: d.Name, Description: d.Desc})
	}
	return out, nil
}

// SetLabelName 修改密级的显示名与说明。
//
// 只允许改展示信息：等级与其排序是系统语义，一旦可改，
// 攻击者就能把"绝密"改名成"公开"来骗审批人，或把低等级的描述改成"禁止访问"来制造混乱。
func SetLabelName(ctx context.Context, tx pgx.Tx, tenantID string, level int, name, desc string) error {
	if level < 0 || level > MaxLevel {
		return ErrBadLevel
	}
	name = strings.TrimSpace(name)
	if name == "" || len([]rune(name)) > 32 {
		return errors.New("密级名称需 1..32 字")
	}
	if len([]rune(desc)) > 200 {
		return errors.New("密级说明不能超过 200 字")
	}
	_, err := tx.Exec(ctx, `
		INSERT INTO classification_label (tenant_id, level, name, description)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (tenant_id, level)
		DO UPDATE SET name = EXCLUDED.name, description = EXCLUDED.description, updated_at = now()`,
		tenantID, level, name, desc)
	return err
}

// EffectiveClass 计算对象的有效密级：对象密级与标签策略取最大。
//
// spaceID 用于判定对象本身是空间（此时 node 表查不到）。
func EffectiveClass(ctx context.Context, tx pgx.Tx, tenantID, nodeID, spaceID string) (int, error) {
	var class int
	err := tx.QueryRow(ctx, `
		SELECT GREATEST(
		  COALESCE((SELECT classification FROM node WHERE id = $1), 0),
		  COALESCE((SELECT classification FROM space WHERE id = $2), 0),
		  COALESCE((SELECT max(lp.min_level)
		              FROM node_label nl
		              JOIN label_policy lp ON lp.tenant_id = nl.tenant_id AND lp.label = nl.label
		             WHERE nl.node_id = $1), 0)
		)`, nodeID, spaceID).Scan(&class)
	if err != nil {
		return 0, err
	}
	return class, nil
}

// SetNode 定密。newLevel 不得超过操作人自身密级。
//
// 同时写一条审计由调用方负责（handler 层），这里只做数据与规则。
func SetNode(ctx context.Context, tx pgx.Tx, nodeID string, newLevel, actorClass int) error {
	if newLevel < 0 || newLevel > MaxLevel {
		return ErrBadLevel
	}
	if newLevel > actorClass {
		return ErrAboveSelf
	}
	tag, err := tx.Exec(ctx,
		`UPDATE node SET classification = $2, updated_at = now() WHERE id = $1 AND deleted_at IS NULL`,
		nodeID, newLevel)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// SetLabels 覆盖式设置对象标签（空切片表示清空）。
//
// 目标对象必须存在；标签本身不校验是否存在策略——
// 没有策略的标签按 0 级处理（即"打了标签但没人配策略"不会意外收紧或放宽）。
func SetLabels(ctx context.Context, tx pgx.Tx, tenantID, nodeID string, labels []string) error {
	var exists bool
	if err := tx.QueryRow(ctx,
		`SELECT true FROM node WHERE id = $1 AND deleted_at IS NULL`, nodeID).Scan(&exists); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM node_label WHERE node_id = $1`, nodeID); err != nil {
		return err
	}
	for _, l := range labels {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		if len([]rune(l)) > 64 {
			return errors.New("标签过长（上限 64 字）")
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO node_label (tenant_id, node_id, label) VALUES ($1,$2,$3)
			ON CONFLICT DO NOTHING`, tenantID, nodeID, l); err != nil {
			return err
		}
	}
	return nil
}

// LabelsOf 返回对象的标签列表。
func LabelsOf(ctx context.Context, tx pgx.Tx, nodeID string) ([]string, error) {
	rows, err := tx.Query(ctx, `SELECT label FROM node_label WHERE node_id = $1 ORDER BY label`, nodeID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var l string
		if err := rows.Scan(&l); err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

// SetPolicy 配置标签的最低密级。
func SetPolicy(ctx context.Context, tx pgx.Tx, tenantID, label string, minLevel int) error {
	label = strings.TrimSpace(label)
	if label == "" || len([]rune(label)) > 64 {
		return errors.New("标签需 1..64 字")
	}
	if minLevel < 0 || minLevel > MaxLevel {
		return ErrBadLevel
	}
	_, err := tx.Exec(ctx, `
		INSERT INTO label_policy (tenant_id, label, min_level) VALUES ($1,$2,$3)
		ON CONFLICT (tenant_id, label) DO UPDATE SET min_level = EXCLUDED.min_level`,
		tenantID, label, minLevel)
	return err
}

// Policies 返回租户的标签策略。
func Policies(ctx context.Context, tx pgx.Tx, tenantID string) (map[string]int, error) {
	rows, err := tx.Query(ctx,
		`SELECT label, min_level FROM label_policy WHERE tenant_id = $1 ORDER BY label`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var l string
		var lv int
		if err := rows.Scan(&l, &lv); err != nil {
			return nil, err
		}
		out[l] = lv
	}
	return out, rows.Err()
}

// ChangeRequest 是一条密级变更申请。
type ChangeRequest struct {
	ID           string
	NodeID       string
	FromLevel    int
	ToLevel      int
	Reason       string
	Status       string
	RequestedBy  string
	DecidedBy    string
	DecisionNote string
}

// RequestDown 提交降密申请。
//
// 只允许"降"：升密由对象管理者直接定密即可（收紧不需要第二人确认，
// 但会立即影响其他人，因此必须审计）。降密必须有人复核。
func RequestDown(ctx context.Context, tx pgx.Tx, tenantID, nodeID string, toLevel int,
	reason, requestedBy string) (string, error) {

	if toLevel < 0 || toLevel > MaxLevel {
		return "", ErrBadLevel
	}
	reason = strings.TrimSpace(reason)
	if len([]rune(reason)) < 4 {
		return "", errors.New("降密理由至少 4 个字（审批人需要知道为什么）")
	}

	var fromLevel int
	err := tx.QueryRow(ctx,
		`SELECT classification FROM node WHERE id = $1 AND deleted_at IS NULL`, nodeID).Scan(&fromLevel)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", ErrNotFound
		}
		return "", err
	}
	if toLevel >= fromLevel {
		return "", fmt.Errorf("这不是降密：当前 %d 级，申请 %d 级", fromLevel, toLevel)
	}

	var id string
	err = tx.QueryRow(ctx, `
		INSERT INTO classification_change
			(id, tenant_id, node_id, from_level, to_level, reason, requested_by)
		VALUES (gen_random_uuid(), $1, $2, $3, $4, $5, $6)
		RETURNING id::text`,
		tenantID, nodeID, fromLevel, toLevel, reason, requestedBy).Scan(&id)
	if err != nil {
		if isUniqueViolation(err) {
			return "", ErrPendingExists
		}
		return "", err
	}
	return id, nil
}

// Decide 审批降密申请。
//
// 两条纪律：
//  1. 申请人不得自批（否则审批流程只是多点一次鼠标）；
//  2. 审批用一条 UPDATE ... WHERE status='pending' 原子完成，
//     并发双击不会把同一申请处理两次。
func Decide(ctx context.Context, tx pgx.Tx, tenantID, requestID, approverID string,
	approve bool, note string) (nodeID string, newLevel int, err error) {

	var (
		fromLevel, toLevel int
		requestedBy        string
		status             string
	)
	err = tx.QueryRow(ctx, `
		SELECT node_id::text, from_level, to_level, requested_by::text, status
		  FROM classification_change WHERE id = $1 AND tenant_id = $2`,
		requestID, tenantID).Scan(&nodeID, &fromLevel, &toLevel, &requestedBy, &status)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", 0, ErrNotFound
		}
		return "", 0, err
	}
	if status != "pending" {
		return "", 0, ErrNotPending
	}
	if requestedBy == approverID {
		return "", 0, errors.New("不能审批自己提交的降密申请")
	}

	newStatus := "rejected"
	if approve {
		newStatus = "approved"
	}
	tag, err := tx.Exec(ctx, `
		UPDATE classification_change
		   SET status = $2, decided_by = $3, decided_at = now(), decision_note = $4
		 WHERE id = $1 AND status = 'pending'`, requestID, newStatus, approverID, note)
	if err != nil {
		return "", 0, err
	}
	if tag.RowsAffected() == 0 {
		return "", 0, ErrNotPending
	}

	if !approve {
		return nodeID, fromLevel, nil
	}
	if _, err := tx.Exec(ctx, `
		UPDATE node SET classification = $2, updated_at = now() WHERE id = $1`, nodeID, toLevel); err != nil {
		return "", 0, err
	}
	return nodeID, toLevel, nil
}

// PendingOf 返回对象上待审的降密申请（供界面提示"审批中"）。
func PendingOf(ctx context.Context, tx pgx.Tx, nodeID string) (*ChangeRequest, error) {
	var r ChangeRequest
	err := tx.QueryRow(ctx, `
		SELECT id::text, node_id::text, from_level, to_level, reason, status, requested_by::text
		  FROM classification_change WHERE node_id = $1 AND status = 'pending'
		 ORDER BY created_at DESC LIMIT 1`, nodeID).
		Scan(&r.ID, &r.NodeID, &r.FromLevel, &r.ToLevel, &r.Reason, &r.Status, &r.RequestedBy)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &r, nil
}

func isUniqueViolation(err error) bool {
	return strings.Contains(err.Error(), "23505") || strings.Contains(err.Error(), "23P01")
}
