package content

// 版本列表与历史回退。
//
// 设计要点（docs/21）：
//   - 当前内容的唯一事实源是 max(version_no)，不是 node.effective_version_id；
//   - 回退 = 以历史版本的内容追加一个新版本（append-only），不是切换指针。
//     这样读取链路（OpenContent）一行都不用改，且版本历史保持线性；
//   - 回退只回退内容，密级 / ACL / 分享 / 水印一概不动。

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"docvault/internal/db"

	"github.com/jackc/pgx/v5"
)

var (
	// ErrVersionNotFound 表示节点下不存在该版本号。
	ErrVersionNotFound = errors.New("版本不存在")
	// ErrVersionVoid 表示目标版本已作废，不能设为生效版或回退到它。
	ErrVersionVoid = errors.New("作废版本不能设为生效版")
	// ErrVersionAlreadyCurrent 表示目标版本就是当前版本。
	ErrVersionAlreadyCurrent = errors.New("该版本已是当前版本")
	// ErrVersionContentSame 表示目标版本与当前版本内容相同（含重复点击回退）。
	ErrVersionContentSame = errors.New("当前内容已与该版本相同")
	// ErrContentMissing 表示该版本的物理内容已丢失，回退过去只会得到一个打不开的文件。
	ErrContentMissing = errors.New("版本内容已丢失")
	// ErrNodeEditing 表示文件正在被在线编辑，回退会与保存冲突。
	ErrNodeEditing = errors.New("文件正在编辑中，请先关闭编辑窗口")
)

// restoreRetries 是版本号冲突的重试次数。
// max(version_no)+1 在并发下会撞唯一约束，重试比全局序列更简单，也不会留空洞。
const restoreRetries = 3

// Version 是版本列表的一行。
type Version struct {
	ID             string
	VersionNo      int
	SizeBytes      int64
	SHA256         string
	State          string
	Origin         string
	RestoredFromNo *int
	CreatedBy      string
	Note           string
	CreatedAt      time.Time
	IsCurrent      bool // 是否为当前版本（即最大 version_no）
	IsEffective    bool // 历史字段，现与 IsCurrent 等价，保留供旧前端兼容
}

// RestoreResult 是回退成功后的结果。
type RestoreResult struct {
	VersionID     string
	VersionNo     int
	FromVersionNo int
	SizeBytes     int64
}

// ListVersions 列出节点的全部版本（新→旧）。
func (s *Store) ListVersions(ctx context.Context, tenantID, nodeID string) ([]Version, error) {
	var out []Version
	err := db.WithTenant(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		var curID, effID *string
		if err := tx.QueryRow(ctx,
			`SELECT current_version_id::text, effective_version_id::text FROM node WHERE id = $1`,
			nodeID).Scan(&curID, &effID); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrNotFound
			}
			return err
		}

		rows, err := tx.Query(ctx, `
			SELECT id::text, version_no, size_bytes, encode(sha256,'hex'), state,
			       origin, restored_from_no,
			       created_by::text, COALESCE(note,''), created_at
			  FROM version WHERE node_id = $1 ORDER BY version_no DESC`, nodeID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var v Version
			if err := rows.Scan(&v.ID, &v.VersionNo, &v.SizeBytes, &v.SHA256, &v.State,
				&v.Origin, &v.RestoredFromNo,
				&v.CreatedBy, &v.Note, &v.CreatedAt); err != nil {
				return err
			}
			v.IsCurrent = curID != nil && *curID == v.ID
			// state 由触发器维护，正常情况下与 IsCurrent 一致；
			// 这里仍按 current_version_id 判定，避免历史脏数据让界面显示错位。
			v.IsEffective = v.IsCurrent
			out = append(out, v)
		}
		return rows.Err()
	})
	return out, err
}

// RestoreVersion 把某个历史版本的内容恢复为当前版本。
//
// 实现方式是追加一个新版本，而不是把指针指回去：
// 新版本号最大，读取链路天然取到它；内容复用源版本的 blob，磁盘零增量。
//
// 五个拒绝条件是这类功能最容易漏的，逐条对应一个真实故障：
//  1. 源版本行要 FOR SHARE 锁住——否则并发清理删掉它时，
//     INSERT ... SELECT 会插入 0 行，随后把 node.current_version_id 写成 NULL，
//     文件变成打不开的空壳且不报错；
//  2. 作废版本不能复活；
//  3. 已经是当前版本、或内容与当前完全相同（含双击回退）时直接拒绝，
//     否则会白占一个版本名额；
//  4. 物理内容必须存在，否则"回退成功"却打不开，比报错更糟；
//  5. 有人正在在线编辑时拒绝，否则对方一保存就把回退覆盖掉。
func (s *Store) RestoreVersion(ctx context.Context, tenantID, nodeID string, versionNo int, actorID string) (RestoreResult, error) {
	if versionNo <= 0 {
		return RestoreResult{}, ErrBadInput
	}

	var out RestoreResult
	var lastErr error
	for attempt := 0; attempt < restoreRetries; attempt++ {
		out, lastErr = s.restoreVersionOnce(ctx, tenantID, nodeID, versionNo, actorID)
		if lastErr == nil {
			return out, nil
		}
		if !isUniqueViolation(lastErr) {
			return RestoreResult{}, lastErr
		}
	}
	return RestoreResult{}, lastErr
}

func (s *Store) restoreVersionOnce(ctx context.Context, tenantID, nodeID string, versionNo int, actorID string) (RestoreResult, error) {
	var out RestoreResult

	err := db.WithTenant(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		// 与 appendVersionOnce 用同一把 advisory 锁：回退与在线编辑保存必须串行取号，
		// 否则两边都会算出同一个 max+1，只能靠唯一约束兜底重试。
		if _, err := tx.Exec(ctx,
			`SELECT pg_advisory_xact_lock(hashtextextended($1::text, 0))`, nodeID); err != nil {
			return err
		}

		// 锁节点：同一文件的并发回退必须串行，否则两个事务都算同一个 max+1。
		var spaceID, curVersionID string
		var curSize int64
		if err := tx.QueryRow(ctx, `
			SELECT space_id::text, COALESCE(current_version_id::text, ''), size_bytes
			  FROM node WHERE id = $1 AND deleted_at IS NULL
			 FOR UPDATE`, nodeID).Scan(&spaceID, &curVersionID, &curSize); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrNotFound
			}
			return err
		}

		// 有活跃编辑会话时拒绝。阈值内联成字面量，避免 interval 参数解析差异。
		var editing bool
		if err := tx.QueryRow(ctx, `
			SELECT EXISTS (
				SELECT 1 FROM doc_session
				 WHERE node_id = $1
				   AND invalidated_at IS NULL
				   AND last_seen_at > now() - interval '10 minutes')`, nodeID).Scan(&editing); err != nil {
			return err
		}
		if editing {
			return ErrNodeEditing
		}

		// 锁源版本行（FOR SHARE）：阻止并发的版本清理把它删掉。
		var srcID, srcBlobID, srcSHA, srcState, storageKey string
		var srcSize int64
		if err := tx.QueryRow(ctx, `
			SELECT v.id::text, v.blob_id::text, v.size_bytes, encode(v.sha256,'hex'),
			       v.state, b.storage_key
			  FROM version v JOIN blob b ON b.id = v.blob_id
			 WHERE v.node_id = $1 AND v.version_no = $2
			 FOR SHARE OF v`, nodeID, versionNo).
			Scan(&srcID, &srcBlobID, &srcSize, &srcSHA, &srcState, &storageKey); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrVersionNotFound
			}
			return err
		}
		if srcState == "void" {
			return ErrVersionVoid
		}
		if srcID == curVersionID {
			return ErrVersionAlreadyCurrent
		}

		// 内容相同就不必新增版本：这一条同时解决"双击回退"产生冗余版本的问题。
		var curSHA string
		if curVersionID != "" {
			if err := tx.QueryRow(ctx,
				`SELECT encode(sha256,'hex') FROM version WHERE id = $1`, curVersionID).
				Scan(&curSHA); err != nil && !errors.Is(err, pgx.ErrNoRows) {
				return err
			}
		}
		if curSHA != "" && curSHA == srcSHA {
			return ErrVersionContentSame
		}

		// 物理内容存在性：历史事故或磁盘故障可能让 blob 行在、文件不在。
		if len(storageKey) < 2 {
			return ErrContentMissing
		}
		path := filepath.Join(s.root, tenantID, storageKey[:2], storageKey)
		if _, statErr := os.Stat(path); statErr != nil {
			return ErrContentMissing
		}

		// 追加新版本。触发器会把它置为唯一的 effective，并把旧 effective 降级。
		//
		// sha256 是 bytea 列：srcSHA 是 hex 文本，必须 decode 成字节再写。
		// 直接把字符串塞进 bytea 会被当成 UTF-8 字节存成 64 字节文本，
		// 后果是"内容相同"的判断永远不成立（同一份内容算出两个不同的 sha）。
		var newID string
		var newNo int
		if err := tx.QueryRow(ctx, `
			INSERT INTO version (id, tenant_id, node_id, version_no, blob_id,
			                     size_bytes, sha256, created_by, note,
			                     origin, restored_from_no)
			VALUES (gen_random_uuid(), $1, $2,
			        (SELECT COALESCE(max(version_no), 0) + 1 FROM version WHERE node_id = $2),
			        $3, $4, decode($5, 'hex'), $6, $7, 'restore', $8)
			RETURNING id::text, version_no`,
			tenantID, nodeID, srcBlobID, srcSize, srcSHA, actorID,
			fmt.Sprintf("回退自 v%d", versionNo), versionNo).
			Scan(&newID, &newNo); err != nil {
			return err
		}

		// 三个指针同步指向新版本，大小跟着内容变。
		if _, err := tx.Exec(ctx, `
			UPDATE node
			   SET current_version_id = $2, effective_version_id = $2,
			       size_bytes = $3, updated_at = now()
			 WHERE id = $1`, nodeID, newID, srcSize); err != nil {
			return err
		}

		// 空间用量按 delta 维护。旧实现只有 used_bytes + size，
		// 回退时若再直接加一次，空间用量会比实际更离谱。
		if _, err := tx.Exec(ctx, `
			UPDATE space SET used_bytes = GREATEST(used_bytes + $2 - $3, 0)
			 WHERE id = $1`, spaceID, srcSize, curSize); err != nil {
			return err
		}

		// 回退成功后让该文件的编辑会话立即失效，后续保存会被文档服务拒绝。
		if _, err := tx.Exec(ctx, `
			UPDATE doc_session SET invalidated_at = now()
			 WHERE node_id = $1 AND invalidated_at IS NULL`, nodeID); err != nil {
			return err
		}

		out = RestoreResult{
			VersionID:     newID,
			VersionNo:     newNo,
			FromVersionNo: versionNo,
			SizeBytes:     srcSize,
		}
		return nil
	})
	if err != nil {
		return RestoreResult{}, err
	}
	return out, nil
}

// SetEffectiveVersion 保留旧签名，行为改为回退。
//
// 旧的"只改 effective 指针"实现不会被任何读取路径读取（OpenContent 取 max(version_no)），
// 属于"接口存在但不生效"。现在两条路径合一，避免再出现两个事实源。
//
// Deprecated: 新代码请用 RestoreVersion。
func (s *Store) SetEffectiveVersion(ctx context.Context, tenantID, nodeID string, versionNo int, actorID string) (string, error) {
	res, err := s.RestoreVersion(ctx, tenantID, nodeID, versionNo, actorID)
	if err != nil {
		return "", err
	}
	return res.VersionID, nil
}

// VersionSHA 返回版本的 sha256（hex），供审计与一致性核对使用。
func (s *Store) VersionSHA(ctx context.Context, tenantID, nodeID string, versionNo int) (string, error) {
	var out string
	err := db.WithTenant(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT encode(sha256,'hex') FROM version WHERE node_id = $1 AND version_no = $2`,
			nodeID, versionNo).Scan(&out)
	})
	return out, err
}

// VersionContent 返回某个版本的存储键与文件信息，供"按版本下载"使用。
type VersionContent struct {
	StorageKey string
	SizeBytes  int64
	SHA256     string
}

// GetVersionContent 定位某个版本的内容，不改变当前版本。
func (s *Store) GetVersionContent(ctx context.Context, tenantID, nodeID string, versionNo int) (VersionContent, error) {
	var vc VersionContent
	err := db.WithTenant(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
			SELECT b.storage_key, v.size_bytes, encode(v.sha256,'hex')
			  FROM version v JOIN blob b ON b.id = v.blob_id
			 WHERE v.node_id = $1 AND v.version_no = $2`, nodeID, versionNo).
			Scan(&vc.StorageKey, &vc.SizeBytes, &vc.SHA256)
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return VersionContent{}, ErrVersionNotFound
		}
		return VersionContent{}, err
	}
	return vc, nil
}

// OpenVersionContent 打开某个版本的内容流（按版本下载用），不改变当前版本。
// 返回的 size 是**该版本**的大小，不是 node 当前版本的大小——
// 下载旧版本时若用 node.SizeBytes 设置 Content-Length，响应会被截断或挂起。
func (s *Store) OpenVersionContent(ctx context.Context, tenantID, nodeID string, versionNo int) (io.ReadCloser, Node, int64, error) {
	vc, err := s.GetVersionContent(ctx, tenantID, nodeID, versionNo)
	if err != nil {
		return nil, Node{}, 0, err
	}
	n, err := s.GetNode(ctx, tenantID, nodeID)
	if err != nil {
		return nil, Node{}, 0, err
	}
	if len(vc.StorageKey) < 2 {
		return nil, Node{}, 0, ErrContentMissing
	}
	f, err := os.Open(filepath.Join(s.root, tenantID, vc.StorageKey[:2], vc.StorageKey))
	if err != nil {
		return nil, Node{}, 0, fmt.Errorf("内容缺失: %w", err)
	}
	return f, n, vc.SizeBytes, nil
}
