// Package content 负责文档内容：空间、目录、文件、版本与内容寻址存储。
//
// 三层结构：node（逻辑对象）→ version（内容快照）→ blob（内容寻址）。
// 同一份内容只存一次，多版本/多副本/重复上传都只是多行引用。
package content

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"docvault/internal/db"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// 常用错误。
var (
	ErrNotFound  = errors.New("对象不存在")
	ErrBadInput  = errors.New("参数不合法")
	ErrNameTaken = errors.New("同目录下已存在同名对象")
	ErrTooLarge  = errors.New("文件超过大小上限")
)

// Node 是目录或文件的逻辑对象。
type Node struct {
	ID             string
	SpaceID        string
	ParentID       *string
	Kind           string
	Name           string
	Depth          int
	SizeBytes      int64
	Mime           string
	Classification int
	OwnerID        string
	// OwnerName / UpdatedByName 是给界面用的"谁的东西、谁最后改的"。
	// 只暴露显示名，不暴露邮箱等其它字段：列表接口的读者可能只有 display 权限。
	OwnerName     string
	UpdatedByName string
	VersionNo     int
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// Store 提供内容服务。
type Store struct {
	pool *pgxpool.Pool
	root string
}

// New 创建内容服务，并确保存储根目录存在。
func New(pool *pgxpool.Pool, root string) (*Store, error) {
	if root == "" {
		return nil, errors.New("存储根目录不能为空")
	}
	if err := os.MkdirAll(root, 0o750); err != nil {
		return nil, fmt.Errorf("创建存储目录失败: %w", err)
	}
	return &Store{pool: pool, root: root}, nil
}

// CreateSpace 创建空间，并给创建者授予所有者 ACE。
func (s *Store) CreateSpace(ctx context.Context, tenantID, ownerID, kind, name string) (string, error) {
	if name == "" || len([]rune(name)) > 100 {
		return "", ErrBadInput
	}
	switch kind {
	case "personal", "dept", "project", "knowledge", "archive":
	default:
		return "", ErrBadInput
	}

	var id string
	err := db.WithTenant(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `
			INSERT INTO space (id, tenant_id, kind, name, owner_id)
			VALUES (gen_random_uuid(), $1, $2, $3, $4) RETURNING id`,
			tenantID, kind, name, ownerID).Scan(&id); err != nil {
			return err
		}
		// 创建者即所有者：授权位与 authz 包的 owner 位一致
		_, err := tx.Exec(ctx, `
			INSERT INTO ace (id, tenant_id, object_type, object_id, subject_type, subject_id,
			                 allow_bits, preset, granted_by)
			VALUES (gen_random_uuid(), $1, 'space', $2, 'user', $3, $4, 'owner', $3)`,
			tenantID, id, ownerID, int64(ownerBits))
		return err
	})
	if err != nil {
		return "", fmt.Errorf("创建空间失败: %w", err)
	}
	return id, nil
}

// ownerBits 对应 authz.AllBits（15 位全开）。放在这里避免在 SQL 里写魔数。
const ownerBits = (1 << 15) - 1

// CreateFolder 在指定父目录下建目录；parentID 为空表示空间根。
func (s *Store) CreateFolder(ctx context.Context, tenantID, spaceID, parentID, ownerID, name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" || len([]rune(name)) > 255 || strings.ContainsAny(name, `/\`) {
		return "", ErrBadInput
	}

	var id string
	err := db.WithTenant(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		depth := 0
		var parent any
		if parentID != "" {
			var d int
			if err := tx.QueryRow(ctx,
				`SELECT depth FROM node WHERE id = $1 AND space_id = $2 AND deleted_at IS NULL`,
				parentID, spaceID).Scan(&d); err != nil {
				if errors.Is(err, pgx.ErrNoRows) {
					return ErrNotFound
				}
				return err
			}
			depth = d + 1
			parent = parentID
		}

		err := tx.QueryRow(ctx, `
			INSERT INTO node (id, tenant_id, space_id, parent_id, kind, name, depth, owner_id)
			VALUES (gen_random_uuid(), $1, $2, $3, 'folder', $4, $5, $6) RETURNING id`,
			tenantID, spaceID, parent, name, depth, ownerID).Scan(&id)
		if err != nil {
			if isUniqueViolation(err) {
				return ErrNameTaken
			}
			return err
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	return id, nil
}

// UploadFile 写入内容并按需创建节点或新版本。
//
// 去重策略：先按内容哈希落盘，若已存在同哈希内容则不重复写。
// 版本号由数据库唯一约束兜底，冲突时重试一次（并发上传同名文件时会发生）。
func (s *Store) UploadFile(ctx context.Context, tenantID, spaceID, parentID, ownerID, name, mime string, data io.Reader, maxBytes int64) (nodeID, versionID string, size int64, err error) {
	name = strings.TrimSpace(name)
	if name == "" || len([]rune(name)) > 255 || strings.ContainsAny(name, `/\`) {
		return "", "", 0, ErrBadInput
	}

	blobID, sha, size, err := s.putBlob(ctx, tenantID, data, maxBytes)
	if err != nil {
		return "", "", 0, err
	}

	err = db.WithTenant(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		depth := 0
		var parent any
		if parentID != "" {
			var d int
			if err := tx.QueryRow(ctx,
				`SELECT depth FROM node WHERE id = $1 AND space_id = $2 AND deleted_at IS NULL`,
				parentID, spaceID).Scan(&d); err != nil {
				if errors.Is(err, pgx.ErrNoRows) {
					return ErrNotFound
				}
				return err
			}
			depth = d + 1
			parent = parentID
		}

		// 已存在同名文件则作为新版本追加，否则新建节点
		var existing string
		var oldSize int64 // 追加版本时用于按 delta 维护空间用量
		findErr := tx.QueryRow(ctx, `
			SELECT id FROM node
			 WHERE space_id = $1 AND parent_id IS NOT DISTINCT FROM $2
			   AND lower(name) = lower($3) AND kind = 'file' AND deleted_at IS NULL`,
			spaceID, parent, name).Scan(&existing)

		if findErr == nil {
			nodeID = existing
			if err := tx.QueryRow(ctx,
				`SELECT size_bytes FROM node WHERE id = $1`, nodeID).Scan(&oldSize); err != nil {
				return err
			}
		} else if errors.Is(findErr, pgx.ErrNoRows) {
			if err := tx.QueryRow(ctx, `
				INSERT INTO node (id, tenant_id, space_id, parent_id, kind, name, depth, size_bytes, mime, owner_id)
				VALUES (gen_random_uuid(), $1, $2, $3, 'file', $4, $5, $6, $7, $8) RETURNING id`,
				tenantID, spaceID, parent, name, depth, size, mime, ownerID).Scan(&nodeID); err != nil {
				if isUniqueViolation(err) {
					return ErrNameTaken
				}
				return err
			}
		} else {
			return findErr
		}

		// 版本号：max+1 在并发下会撞唯一约束，冲突由上层重试
		var nextNo int
		if err := tx.QueryRow(ctx,
			`SELECT COALESCE(max(version_no), 0) + 1 FROM version WHERE node_id = $1`, nodeID).Scan(&nextNo); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `
			INSERT INTO version (id, tenant_id, node_id, version_no, blob_id, size_bytes, sha256, created_by)
			VALUES (gen_random_uuid(), $1, $2, $3, $4, $5, $6, $7) RETURNING id`,
			tenantID, nodeID, nextNo, blobID, size, sha, ownerID).Scan(&versionID); err != nil {
			if isUniqueViolation(err) {
				return fmt.Errorf("版本号冲突，请重试")
			}
			return err
		}

		if _, err := tx.Exec(ctx, `
			UPDATE node SET current_version_id = $2, size_bytes = $3, mime = $4, updated_at = now()
			 WHERE id = $1`, nodeID, versionID, size, mime); err != nil {
			return err
		}
		// 空间用量按 delta 维护：旧实现只有 +size，覆盖上传会让空间用量虚高。
		_, err := tx.Exec(ctx, `
			UPDATE space SET used_bytes = GREATEST(used_bytes + $2 - $3, 0) WHERE id = $1`,
			spaceID, size, oldSize)
		return err
	})
	if err != nil {
		return "", "", 0, err
	}
	return nodeID, versionID, size, nil
}

// putBlob 把内容写到内容寻址路径，并登记 blob 记录（去重）。
func (s *Store) putBlob(ctx context.Context, tenantID string, data io.Reader, maxBytes int64) (string, []byte, int64, error) {
	dir := filepath.Join(s.root, tenantID)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return "", nil, 0, fmt.Errorf("创建租户存储目录失败: %w", err)
	}
	tmp, err := os.CreateTemp(dir, ".upload-*")
	if err != nil {
		return "", nil, 0, err
	}
	tmpName := tmp.Name()
	// 注意：Windows 上文件仍打开时 os.Rename 会失败，
	// 因此必须先 Close 再改名；只在 Linux 测试会漏掉这个差异。
	closed := false
	defer func() {
		if !closed {
			_ = tmp.Close()
		}
		_ = os.Remove(tmpName) // 改名成功后此处为空操作
	}()

	h := sha256.New()
	limited := io.LimitReader(data, maxBytes+1)
	size, err := io.Copy(io.MultiWriter(tmp, h), limited)
	if err != nil {
		return "", nil, 0, err
	}
	if size > maxBytes {
		return "", nil, 0, ErrTooLarge
	}
	if err := tmp.Sync(); err != nil {
		return "", nil, 0, err
	}
	if err := tmp.Close(); err != nil {
		return "", nil, 0, err
	}
	closed = true

	sum := h.Sum(nil)
	hexSum := hex.EncodeToString(sum)
	sub := filepath.Join(dir, hexSum[:2])
	if err := os.MkdirAll(sub, 0o750); err != nil {
		return "", nil, 0, err
	}
	final := filepath.Join(sub, hexSum)

	if _, statErr := os.Stat(final); statErr != nil {
		if err := os.Rename(tmpName, final); err != nil {
			return "", nil, 0, err
		}
	}

	var blobID string
	err = db.WithTenant(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		// ref_count 由 version 的 INSERT/DELETE 触发器维护，这里只负责建行。
		//
		// 曾经写成 ON CONFLICT DO UPDATE ref_count + 1，在触发器上线后会变成双倍计数；
		// 改为 DO NOTHING，冲突时用 UNION ALL 回查一次拿到既有 id。
		return tx.QueryRow(ctx, `
			WITH ins AS (
				INSERT INTO blob (id, tenant_id, size_bytes, sha256, storage_key, ref_count)
				VALUES (gen_random_uuid(), $1, $2, $3, $4, 0)
				ON CONFLICT (tenant_id, sha256, size_bytes) DO NOTHING
				RETURNING id::text
			)
			SELECT id::text FROM ins
			UNION ALL
			SELECT id::text FROM blob
			 WHERE tenant_id = $1 AND sha256 = $3 AND size_bytes = $2
			LIMIT 1`, tenantID, size, sum, hexSum).Scan(&blobID)
	})
	if err != nil {
		return "", nil, 0, fmt.Errorf("登记内容失败: %w", err)
	}
	return blobID, sum, size, nil
}

// ListNodes 列出某目录下的直接子项（不递归）。
func (s *Store) ListNodes(ctx context.Context, tenantID, spaceID, parentID string) ([]Node, error) {
	var out []Node
	err := db.WithTenant(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		var parent any
		if parentID != "" {
			parent = parentID
		}
		// 归属与最新贡献者在同一条 SQL 里带出来：列表页每行都要显示
		// "所有者 / 最近编辑"，逐行再查一次会变成 N+1 次往返。
		rows, err := tx.Query(ctx, `
			SELECT n.id, n.space_id, n.parent_id::text, n.kind, n.name, n.depth, n.size_bytes,
			       COALESCE(n.mime,''), n.classification, n.owner_id,
			       COALESCE(u.display_name, ''), n.created_at, n.updated_at,
			       COALESCE(v.version_no, 0), COALESCE(vu.display_name, '')
			  FROM node n
			  LEFT JOIN app_user u ON u.id = n.owner_id
			  LEFT JOIN LATERAL (
			       SELECT ver.version_no, ver.created_by
			         FROM version ver
			        WHERE ver.node_id = n.id
			        ORDER BY ver.version_no DESC
			        LIMIT 1
			  ) v ON true
			  LEFT JOIN app_user vu ON vu.id = v.created_by
			 WHERE n.space_id = $1 AND n.parent_id IS NOT DISTINCT FROM $2 AND n.deleted_at IS NULL
			 ORDER BY n.kind DESC, lower(n.name)`, spaceID, parent)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var n Node
			if err := rows.Scan(&n.ID, &n.SpaceID, &n.ParentID, &n.Kind, &n.Name, &n.Depth,
				&n.SizeBytes, &n.Mime, &n.Classification, &n.OwnerID,
				&n.OwnerName, &n.CreatedAt, &n.UpdatedAt, &n.VersionNo, &n.UpdatedByName); err != nil {
				return err
			}
			out = append(out, n)
		}
		return rows.Err()
	})
	return out, err
}

// Crumb 是面包屑的一段。
type Crumb struct {
	ID   string
	Name string
}

// NodePath 返回从空间根到目标节点的祖先链（含目标本身，不含空间）。
//
// 为什么需要它：页面地址里只能带一个 folderId，刷新时要把面包屑还原出来，
// 就必须能"由深到浅"反查。把这件事放在服务端，前端不必为每一级各发一次请求，
// 也不会因为某一级被删而卡在半路（递归 CTE 自然停在断点）。
func (s *Store) NodePath(ctx context.Context, tenantID, nodeID string) ([]Crumb, error) {
	var out []Crumb
	err := db.WithTenant(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `
			WITH RECURSIVE chain AS (
				SELECT id, parent_id, name, 0 AS hop
				  FROM node WHERE id = $1 AND deleted_at IS NULL
				UNION ALL
				SELECT n.id, n.parent_id, n.name, c.hop + 1
				  FROM node n JOIN chain c ON n.id = c.parent_id
				 WHERE n.deleted_at IS NULL
			)
			SELECT id::text, name FROM chain ORDER BY hop DESC`, nodeID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var c Crumb
			if err := rows.Scan(&c.ID, &c.Name); err != nil {
				return err
			}
			out = append(out, c)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, ErrNotFound
	}
	return out, nil
}

// GetNode 读取单个节点。
func (s *Store) GetNode(ctx context.Context, tenantID, nodeID string) (Node, error) {
	var n Node
	err := db.WithTenant(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
			SELECT n.id, n.space_id, n.parent_id::text, n.kind, n.name, n.depth, n.size_bytes,
			       COALESCE(n.mime,''), n.classification, n.owner_id,
			       COALESCE(u.display_name, ''), n.created_at, n.updated_at,
			       COALESCE(v.version_no, 0), COALESCE(vu.display_name, '')
			  FROM node n
			  LEFT JOIN app_user u ON u.id = n.owner_id
			  LEFT JOIN LATERAL (
			       SELECT ver.version_no, ver.created_by
			         FROM version ver
			        WHERE ver.node_id = n.id
			        ORDER BY ver.version_no DESC
			        LIMIT 1
			  ) v ON true
			  LEFT JOIN app_user vu ON vu.id = v.created_by
			 WHERE n.id = $1 AND n.deleted_at IS NULL`, nodeID).
			Scan(&n.ID, &n.SpaceID, &n.ParentID, &n.Kind, &n.Name, &n.Depth,
				&n.SizeBytes, &n.Mime, &n.Classification, &n.OwnerID,
				&n.OwnerName, &n.CreatedAt, &n.UpdatedAt, &n.VersionNo, &n.UpdatedByName)
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Node{}, ErrNotFound
		}
		return Node{}, err
	}
	return n, nil
}

// OpenContent 打开当前版本的内容流。
func (s *Store) OpenContent(ctx context.Context, tenantID, nodeID string) (io.ReadCloser, Node, error) {
	n, err := s.GetNode(ctx, tenantID, nodeID)
	if err != nil {
		return nil, Node{}, err
	}

	var key string
	err = db.WithTenant(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
			SELECT b.storage_key FROM version v JOIN blob b ON b.id = v.blob_id
			 WHERE v.node_id = $1 ORDER BY v.version_no DESC LIMIT 1`, nodeID).Scan(&key)
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, Node{}, ErrNotFound
		}
		return nil, Node{}, err
	}

	f, err := os.Open(filepath.Join(s.root, tenantID, key[:2], key))
	if err != nil {
		return nil, Node{}, fmt.Errorf("内容缺失: %w", err)
	}
	return f, n, nil
}

// isUniqueViolation 判断是否为唯一约束冲突（PG 错误码 23505）。
func isUniqueViolation(err error) bool {
	type sqlStater interface{ SQLState() string }
	var se sqlStater
	if errors.As(err, &se) {
		return se.SQLState() == "23505"
	}
	return strings.Contains(err.Error(), "23505")
}

// AppendVersion 给已存在的文件节点追加一个新版本（用于在线编辑保存、预览转换结果写回等）。
//
// 与 UploadFile 的区别：UploadFile 按"目录 + 文件名"定位节点，
// 而这里由调用方给出确定的 nodeID——回调场景下不能让"文件名"决定写到哪，
// 否则构造一个同名文件就能覆盖别人的内容。
func (s *Store) AppendVersion(ctx context.Context, tenantID, nodeID, ownerID string, data io.Reader, maxBytes int64) (versionID string, size int64, err error) {
	blobID, sha, size, err := s.putBlob(ctx, tenantID, data, maxBytes)
	if err != nil {
		return "", 0, err
	}

	// 并发追加版本会撞 UNIQUE (node_id, version_no)：
	// max(version_no)+1 是典型的读后写，两个请求同时读到同一个 max。
	// 正确做法不是加全局锁（会串行化所有写入），而是**乐观重试**：
	// 撞唯一约束就重算版本号，几次之内必然收敛。
	const attempts = 5
	var lastErr error
	for i := 0; i < attempts; i++ {
		versionID, err = s.appendVersionOnce(ctx, tenantID, nodeID, ownerID, blobID, sha, size)
		if err == nil {
			return versionID, size, nil
		}
		if !isUniqueViolation(err) {
			return "", 0, err
		}
		lastErr = err
		// 退避几毫秒，避免多个失败者同时重试再次相撞
		select {
		case <-ctx.Done():
			return "", 0, ctx.Err()
		case <-time.After(time.Duration(i+1) * 5 * time.Millisecond):
		}
	}
	return "", 0, fmt.Errorf("版本号竞争重试耗尽: %w", lastErr)
}

// appendVersionOnce 执行一次"取号 + 插入 + 更新指针"。
func (s *Store) appendVersionOnce(ctx context.Context, tenantID, nodeID, ownerID, blobID string, sha []byte, size int64) (string, error) {
	var versionID string
	err := db.WithTenant(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		// 同一节点的版本号必须串行取号。用事务级 advisory 锁而不是表锁/行锁：
		// 锁粒度恰好是"这一个节点"，不同文件之间完全不互相阻塞。
		// 只靠乐观重试在极端并发下会反复相撞（20 并发实测 5 次重试仍失败）。
		if _, err := tx.Exec(ctx,
			`SELECT pg_advisory_xact_lock(hashtextextended($1::text, 0))`, nodeID); err != nil {
			return err
		}

		var spaceID, kind, ownerOfNode string
		var oldSize int64
		if err := tx.QueryRow(ctx,
			`SELECT space_id::text, kind, owner_id::text, size_bytes
			   FROM node WHERE id = $1 AND deleted_at IS NULL`, nodeID).
			Scan(&spaceID, &kind, &ownerOfNode, &oldSize); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrNotFound
			}
			return err
		}
		if kind != "file" {
			return ErrBadInput
		}
		// 回调场景下来源用户可能为空（文档服务不带用户身份），
		// 此时记在节点所有者名下：version.created_by 不允许为空，
		// 而"谁保存的"在这里本来也无法精确到人。
		if ownerID == "" {
			ownerID = ownerOfNode
		}

		var nextNo int
		if err := tx.QueryRow(ctx,
			`SELECT COALESCE(max(version_no), 0) + 1 FROM version WHERE node_id = $1`, nodeID).Scan(&nextNo); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `
			INSERT INTO version (id, tenant_id, node_id, version_no, blob_id, size_bytes, sha256, created_by, origin)
			VALUES (gen_random_uuid(), $1, $2, $3, $4, $5, $6, nullif($7,'')::uuid, 'edit') RETURNING id`,
			tenantID, nodeID, nextNo, blobID, size, sha, ownerID).Scan(&versionID); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `
			UPDATE node SET current_version_id = $2, size_bytes = $3, updated_at = now()
			 WHERE id = $1`, nodeID, versionID, size); err != nil {
			return err
		}
		_, err := tx.Exec(ctx,
			`UPDATE space SET used_bytes = GREATEST(used_bytes + $2 - $3, 0) WHERE id = $1`,
			spaceID, size, oldSize)
		return err
	})
	if err != nil {
		return "", err
	}
	return versionID, nil
}
