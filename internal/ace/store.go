// Package ace 负责从数据库装载主体的权限快照与对象的 ACE 集合，
// 供内部 authz 包做纯函数判定。
//
// 分工：本包只做"取数据 + 组装"，不做判定；判定逻辑全部在 authz 里，
// 这样判定语义可以用表驱动测试钉死，不受 SQL 细节干扰。
package ace

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"docvault/internal/authz"

	"github.com/jackc/pgx/v5"
)

// LoadSubject 组装主体快照：部门祖先路径、角色、用户组、密级、封顶。
//
// 部门用"祖先链"而不是仅所属部门：授权在父部门时，子部门成员应自动命中。
func LoadSubject(ctx context.Context, tx pgx.Tx, tenantID, userID string) (authz.Subject, error) {
	var (
		s       authz.Subject
		class   int
		ceiling int
		status  string
		epoch   int
		pType   string
		deptID  *string
	)
	err := tx.QueryRow(ctx, `
		SELECT principal_type, status, session_epoch, classification, ceiling, dept_id::text
		  FROM app_user WHERE id = $1`, userID).
		Scan(&pType, &status, &epoch, &class, &ceiling, &deptID)
	if err != nil {
		return authz.Subject{}, err
	}

	s.ID = userID
	s.TenantID = tenantID
	s.IsExternal = pType == "external"
	s.Active = status == "active"
	s.Class = class
	s.Ceiling = ceiling
	s.Epoch = epoch
	s.TokenEpoch = epoch // 由调用方在拿到令牌声明后覆盖校验

	if deptID != nil {
		rows, err := tx.Query(ctx, `
			WITH me AS (SELECT path FROM dept WHERE id = $1)
			SELECT id::text FROM dept WHERE path @> (SELECT path FROM me)`, *deptID)
		if err != nil {
			return authz.Subject{}, err
		}
		for rows.Next() {
			var d string
			if err := rows.Scan(&d); err != nil {
				rows.Close()
				return authz.Subject{}, err
			}
			s.DeptPaths = append(s.DeptPaths, d)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return authz.Subject{}, err
		}
	}

	rows, err := tx.Query(ctx, `SELECT role_id::text FROM user_role WHERE user_id = $1`, userID)
	if err != nil {
		return authz.Subject{}, err
	}
	for rows.Next() {
		var r string
		if err := rows.Scan(&r); err != nil {
			rows.Close()
			return authz.Subject{}, err
		}
		s.RoleIDs = append(s.RoleIDs, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return authz.Subject{}, err
	}

	rows, err = tx.Query(ctx, `SELECT group_id::text FROM group_member WHERE user_id = $1`, userID)
	if err != nil {
		return authz.Subject{}, err
	}
	for rows.Next() {
		var g string
		if err := rows.Scan(&g); err != nil {
			rows.Close()
			return authz.Subject{}, err
		}
		s.GroupIDs = append(s.GroupIDs, g)
	}
	rows.Close()
	return s, rows.Err()
}

// LoadForNode 取出某个文件/目录的有效 ACE 集合：
// 空间根（depth 0）+ 祖先链（越深 depth 越大，用于"就近显式优先"）。
//
// 继承断点：链上任一节点 inherit_broken=true 时，该节点以上（含空间根）的 ACE
// 一律不参与判定。断开继承时由 BreakInheritance 把当时的祖先 ACE 复制成本对象
// 的 inherited 快照，因此"断开"不会让对象瞬间失去访问，也不会成为绕过上层 deny
// 的提权路径（快照里包含 deny，且快照条目不允许单独删除）。
func LoadForNode(ctx context.Context, tx pgx.Tx, spaceID, nodeID string) ([]authz.ACE, error) {
	rows, err := tx.Query(ctx, `
		WITH RECURSIVE chain AS (
			SELECT id, parent_id, 0 AS hop, inherit_broken FROM node WHERE id = $1
			UNION ALL
			SELECT n.id, n.parent_id, c.hop + 1, n.inherit_broken
			  FROM node n JOIN chain c ON n.id = c.parent_id
			 WHERE NOT c.inherit_broken
		)
		SELECT a.id::text, a.subject_type, COALESCE(a.subject_id::text,''),
		       a.allow_bits, a.deny_bits, a.conditions, a.expires_at,
		       -- depth 只用于"就近显式优先"的比较，数值本身没有业务含义。
		       -- 基数必须远大于任何可能的树深：曾经用 100 - hop，深度超过 100 层的节点
		       -- 会得到 0 或负值，于是"更靠近对象的 ACE"反而比空间级 ACE 还小，
		       -- 就近优先被反转，深层那条带条件的授权可以被浅层的无条件授权顶替。
		       CASE WHEN a.object_type = 'space' THEN 0 ELSE 1000000 - c.hop END AS depth
		  FROM ace a
		  LEFT JOIN chain c ON a.object_type = 'node' AND a.object_id = c.id
		 WHERE (a.object_type = 'node'  AND a.object_id IN (SELECT id FROM chain))
		    OR (a.object_type = 'space' AND a.object_id = $2
		        AND (
		              -- 判定对象就是空间本身：空间 ACE 永远有效
		              $1::uuid = $2::uuid
		              -- 否则只有"链一直走到树根、且根节点未断开继承"才继承空间 ACE
		              OR COALESCE((SELECT NOT inherit_broken FROM chain WHERE parent_id IS NULL), false)
		            ))`,
		nodeID, spaceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []authz.ACE
	for rows.Next() {
		var (
			a       authz.ACE
			allow   int64
			deny    int64
			condRaw []byte
			depth   int
		)
		if err := rows.Scan(&a.ID, &a.SubjectType, &a.SubjectID, &allow, &deny, &condRaw, &a.ExpiresAt, &depth); err != nil {
			return nil, err
		}
		a.Allow = authz.Bit(allow)
		a.Deny = authz.Bit(deny)
		a.Depth = depth
		if len(condRaw) > 0 {
			if err := json.Unmarshal(condRaw, &a.Conditions); err != nil {
				return nil, err
			}
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// Source 实现 authz.RuleSource，把"取 ACE"绑到具体对象上。
type Source struct {
	Aces []authz.ACE
	Err  error
}

// Load 实现 authz.RuleSource。
func (s *Source) Load(_ context.Context, _ authz.Subject, _ authz.Object) ([]authz.ACE, error) {
	if s.Err != nil {
		return nil, s.Err
	}
	return s.Aces, nil
}

// ErrNoACE 表示对象上没有任何权限条目。
var ErrNoACE = errors.New("对象未配置任何权限")

// ---------------------------------------------------------------------------
// 授权管理：授予、撤销、列出
// ---------------------------------------------------------------------------

// ACERow 是对外展示的权限条目。
type ACERow struct {
	ID          string
	ObjectType  string
	ObjectID    string
	SubjectType string
	SubjectID   string
	Allow       []string
	Preset      string
	ExpiresAt   *time.Time
	// Origin 为 direct（直接授予）或 inherited（断开继承时的祖先快照）
	Origin string
	Deny   []string
}

// ErrCeilingExceeded 表示授权方试图授出超过自身封顶的档位。
var ErrCeilingExceeded = errors.New("超过自身可授出的权限档位")

// Grant 在对象上给某主体授权。
//
// 两道校验缺一不可：
//  1. 授权方自身对该对象必须有 manage_acl；
//  2. 目标档位不得高于授权方的封顶（防"低权限用户把自己人提成所有者"）。
func Grant(ctx context.Context, tx pgx.Tx, tenantID, objectType, objectID,
	subjectType, subjectID string, preset authz.Preset, grantedBy string, expiresAt *time.Time) (string, error) {

	if !preset.Valid() {
		return "", errors.New("未知权限档位")
	}
	// 匿名主体只能由分享流程生成，不允许手工授予：
	// 一条 anonymous ACE 等价于"任何人可访问"，手工开口子会让
	// 分享的密码/有效期/审批全部被绕过。
	if subjectType == "anonymous" {
		return "", errors.New("匿名主体不能手工授权，只能通过分享生成")
	}
	if subjectType != "user" && subjectType != "group" && subjectType != "dept" && subjectType != "role" {
		return "", errors.New("未知主体类型")
	}

	// 授权方封顶
	var ceiling int
	if err := tx.QueryRow(ctx, `SELECT ceiling FROM app_user WHERE id = $1`, grantedBy).Scan(&ceiling); err != nil {
		return "", err
	}
	if err := authz.Grantable(ceiling, preset); err != nil {
		return "", ErrCeilingExceeded
	}

	bits := int64(preset.Bits())
	var id string
	err := tx.QueryRow(ctx, `
		INSERT INTO ace (id, tenant_id, object_type, object_id, subject_type, subject_id,
		                 allow_bits, preset, granted_by, expires_at)
		VALUES (gen_random_uuid(), $1, $2, $3, $4, nullif($5,'')::uuid, $6, $7, $8, $9)
		ON CONFLICT (tenant_id, object_type, object_id, subject_type,
		             COALESCE(subject_id, '00000000-0000-0000-0000-000000000000'::uuid))
		DO UPDATE SET allow_bits = EXCLUDED.allow_bits,
		              preset = EXCLUDED.preset,
		              granted_by = EXCLUDED.granted_by,
		              expires_at = EXCLUDED.expires_at,
		              updated_at = now()
		RETURNING id`,
		tenantID, objectType, objectID, subjectType, subjectID, bits, string(preset), grantedBy, expiresAt).Scan(&id)
	if err != nil {
		return "", err
	}
	return id, nil
}

// List 列出某对象上的全部权限条目。
func List(ctx context.Context, tx pgx.Tx, objectType, objectID string) ([]ACERow, error) {
	rows, err := tx.Query(ctx, `
		SELECT id::text, object_type, object_id::text, subject_type, COALESCE(subject_id::text,''),
		       allow_bits, deny_bits, COALESCE(preset,''), expires_at, origin
		  FROM ace WHERE object_type = $1 AND object_id = $2
		 ORDER BY origin, subject_type, subject_id`, objectType, objectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []ACERow
	for rows.Next() {
		var r ACERow
		var bits, deny int64
		if err := rows.Scan(&r.ID, &r.ObjectType, &r.ObjectID, &r.SubjectType, &r.SubjectID,
			&bits, &deny, &r.Preset, &r.ExpiresAt, &r.Origin); err != nil {
			return nil, err
		}
		r.Allow = authz.Bit(bits).Names()
		r.Deny = authz.Bit(deny).Names()
		out = append(out, r)
	}
	return out, rows.Err()
}

// ErrLastOwner 表示这次撤销会把对象变成"无人可管理"。
var ErrLastOwner = errors.New("不能移除对象的最后一个所有者")

// ErrInheritedACE 表示试图直接删除/修改一条继承快照。
//
// 继承快照只能通过"恢复继承"整体移除。允许单删等于给了一条提权路径：
// 先断开继承拿到快照（含祖先的 deny），再把 deny 删掉——上层拒绝就被绕过了。
var ErrInheritedACE = errors.New("继承而来的权限条目不能单独修改，请先恢复继承")

// Revoke 删除一条权限条目。
//
// 防锁死：若该条目是对象上最后一个 owner 级授权，直接拒绝——
// 否则一次误操作就会让对象永久失去管理入口（只能由平台管理员介入）。
func Revoke(ctx context.Context, tx pgx.Tx, aceID string) error {
	var objectType, objectID, origin string
	var bits int64
	if err := tx.QueryRow(ctx,
		`SELECT object_type, object_id::text, allow_bits, origin FROM ace WHERE id = $1`, aceID).
		Scan(&objectType, &objectID, &bits, &origin); err != nil {
		return err
	}
	if origin == "inherited" {
		return ErrInheritedACE
	}

	ownerBit := int64(authz.Owner)
	if bits&ownerBit != 0 {
		var owners int
		if err := tx.QueryRow(ctx, `
			SELECT count(*) FROM ace
			 WHERE object_type = $1 AND object_id = $2 AND (allow_bits & $3) <> 0`,
			objectType, objectID, ownerBit).Scan(&owners); err != nil {
			return err
		}
		if owners <= 1 {
			return ErrLastOwner
		}
	}

	_, err := tx.Exec(ctx, `DELETE FROM ace WHERE id = $1`, aceID)
	return err
}

// Update 修改一条权限条目的档位与有效期。
//
// 为什么单独做接口而不是"删了重授"：
//
//	删+授是两步，中间若失败会留下"权限空窗"；而且审计上会呈现成
//	"撤销 + 新增"，看不出这是同一次变更。改档位是一条 UPDATE，可一次成功。
//
// 约束：
//  1. 继承快照不可改（见 ErrInheritedACE）；
//  2. 新档位不得高于操作人封顶（AC-33：把 ACE 改成永不过期/提档都要过封顶）；
//  3. 不提供"改主体"——改主体等价于重新授权，必须走 Grant 走一次完整判定。
func Update(ctx context.Context, tx pgx.Tx, aceID string, preset authz.Preset,
	expiresAt *time.Time, clearExpiry bool, grantedBy string) error {

	if !preset.Valid() {
		return errors.New("未知权限档位")
	}

	var origin string
	if err := tx.QueryRow(ctx, `SELECT origin FROM ace WHERE id = $1`, aceID).Scan(&origin); err != nil {
		return err
	}
	if origin == "inherited" {
		return ErrInheritedACE
	}

	var ceiling int
	if err := tx.QueryRow(ctx, `SELECT ceiling FROM app_user WHERE id = $1`, grantedBy).Scan(&ceiling); err != nil {
		return err
	}
	if err := authz.Grantable(ceiling, preset); err != nil {
		return ErrCeilingExceeded
	}

	if clearExpiry {
		_, err := tx.Exec(ctx, `
			UPDATE ace SET allow_bits = $2, preset = $3, expires_at = NULL,
			               granted_by = $4, updated_at = now()
			 WHERE id = $1`, aceID, int64(preset.Bits()), string(preset), grantedBy)
		return err
	}

	_, err := tx.Exec(ctx, `
		UPDATE ace SET allow_bits = $2, preset = $3, expires_at = $4,
		               granted_by = $5, updated_at = now()
		 WHERE id = $1`, aceID, int64(preset.Bits()), string(preset), expiresAt, grantedBy)
	return err
}
