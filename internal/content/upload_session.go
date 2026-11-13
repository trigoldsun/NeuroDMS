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
)

// 分片上传的错误。
var (
	ErrSessionNotFound = errors.New("上传会话不存在")
	ErrSessionDone     = errors.New("上传会话已结束")
	ErrSizeMismatch    = errors.New("实际大小与声明不一致")
	ErrHashMismatch    = errors.New("内容哈希与声明不一致")
	ErrPartsIncomplete = errors.New("分片不完整")
)

// Session 是上传会话的读模型。
type Session struct {
	ID            string
	SpaceID       string
	ParentID      string
	Name          string
	DeclaredSize  int64
	ReceivedBytes int64
	Status        string
	NodeID        string
	VersionID     string
	Deduped       bool

	// PartSize 是会话的分片边界，续传必须沿用它而不是客户端当前的选择。
	// 前后端片大小不一致会拼出错位内容，且只有到 complete 校验哈希时才会暴露。
	PartSize int64
	// Parts 是服务端已收的分片号（从 1 开始，升序）。
	// 续传时前端跳过这些号，只补缺口。
	Parts []int
	// Resumed 表示本次 CreateSession 复用了已有会话，不是新建。
	Resumed bool
}

// resumeWindow 是"可以接着传"的时间窗口。
//
// 太短（比如 1 小时）会让"下班前传一半、第二天上班接着传"变成从零开始；
// 太长会让废弃会话长期占磁盘。24 小时覆盖了绝大多数真实中断场景。
const resumeWindow = "24 hours"

// 分片边界的合理区间（与迁移 0037 的约束一致）。
// 下界防请求洪水，上界防"单片几十 MB，一失败就重传半天"。
const (
	minPartSize = 1 << 20  // 1 MiB
	maxPartSize = 64 << 20 // 64 MiB
)

// CreateSession 开启分片上传会话；若存在可续的同类会话则直接复用。
//
// 秒传判定只看**服务端已有内容**：同租户内存在 (sha256,size) 相同的 blob 时，
// 直接引用现成 blob 创建节点/版本。声明值只用来"找候选"，
// 最终仍会在 Complete 时校验实际字节——否则"声明一个已存在的哈希"就能拿到任意文件。
//
// 续传判定同上：客户端声明的 (sha256, size, 名称, 目标目录) 只用来**找会话**，
// 服务端不会因此认为内容已经上传成功——真正的完成仍要过 Complete 的哈希校验。
func (s *Store) CreateSession(ctx context.Context, tenantID, spaceID, parentID, name, ownerID string,
	declaredSize int64, declaredSHA string, partSize int64) (Session, bool, error) {

	if err := validateName(name); err != nil {
		return Session{}, false, err
	}
	if declaredSize < 0 {
		return Session{}, false, ErrBadInput
	}
	// 分片边界由服务端定死合理区间：客户端传 0 或 1 字节会让请求数爆炸
	if partSize < minPartSize || partSize > maxPartSize {
		return Session{}, false, ErrBadInput
	}

	var (
		out   Session
		dedup bool
		sha   []byte
	)
	if declaredSHA != "" {
		b, err := hex.DecodeString(strings.ToLower(strings.TrimSpace(declaredSHA)))
		if err != nil || len(b) != 32 {
			return Session{}, false, ErrBadInput
		}
		sha = b
	}

	err := db.WithTenant(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		// 已有相同内容 → 秒传
		if sha != nil {
			var blobID string
			err := tx.QueryRow(ctx, `
				SELECT id::text FROM blob WHERE sha256 = $1 AND size_bytes = $2 LIMIT 1`,
				sha, declaredSize).Scan(&blobID)
			if err == nil {
				nodeID, versionID, e := s.createNodeFromBlob(ctx, tx, tenantID, spaceID, parentID,
					ownerID, name, blobID, declaredSize)
				if e != nil {
					return e
				}
				out = Session{SpaceID: spaceID, ParentID: parentID, Name: name,
					DeclaredSize: declaredSize, Status: "completed",
					NodeID: nodeID, VersionID: versionID, Deduped: true}
				dedup = true
				return nil
			}
			if !errors.Is(err, pgx.ErrNoRows) {
				return err
			}
		}

		var parent any
		if parentID != "" {
			parent = parentID
		}

		// 可续会话：同一用户、同一内容、同一目标目录、仍未完成。
		//
		// 必须带上 parent（目标目录）：同名同内容传到另一个目录是**另一个任务**，
		// 复用会把内容落到上次的目录，用户会看到文件"传到了别处"。
		if sha != nil {
			var sid string
			var ps int64
			perr := tx.QueryRow(ctx, `
				SELECT id::text, part_size FROM upload_session
				 WHERE tenant_id = $1 AND created_by = $2 AND declared_sha256 = $3
				   AND declared_size = $4 AND space_id = $5
				   AND parent_id IS NOT DISTINCT FROM $6
				   AND name = $7 AND status = 'open'
				   AND created_at > now() - $8::interval
				 ORDER BY created_at DESC LIMIT 1`,
				tenantID, ownerID, sha, declaredSize, spaceID, parent, name, resumeWindow).
				Scan(&sid, &ps)
			if perr == nil {
				parts, e := listParts(ctx, tx, sid)
				if e != nil {
					return e
				}
				out = Session{ID: sid, SpaceID: spaceID, ParentID: parentID, Name: name,
					DeclaredSize: declaredSize, Status: "open", PartSize: ps,
					Parts: parts, Resumed: true}
				return nil
			}
			if !errors.Is(perr, pgx.ErrNoRows) {
				return perr
			}
		}

		return tx.QueryRow(ctx, `
			INSERT INTO upload_session
				(id, tenant_id, space_id, parent_id, name, declared_size, declared_sha256,
				 created_by, part_size)
			VALUES (gen_random_uuid(), $1, $2, $3, $4, $5, $6, $7, $8)
			RETURNING id::text`,
			tenantID, spaceID, parent, name, declaredSize, sha, ownerID, partSize).Scan(&out.ID)
	})
	if err != nil {
		return Session{}, false, err
	}
	out.SpaceID, out.ParentID, out.Name = spaceID, parentID, name
	out.DeclaredSize = declaredSize
	if !dedup && !out.Resumed {
		out.Status = "open"
	}
	if out.PartSize == 0 {
		out.PartSize = partSize
	}
	return out, dedup, nil
}

// listParts 读会话已收的分片号。
func listParts(ctx context.Context, tx pgx.Tx, sessionID string) ([]int, error) {
	rows, err := tx.Query(ctx,
		`SELECT part_no FROM upload_part WHERE session_id = $1 ORDER BY part_no`, sessionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []int
	for rows.Next() {
		var n int
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

// GetSession 读取会话与已收分片（刷新页面后恢复续传用）。
//
// 只返回本人的会话：会话里含目标目录与文件名，跨用户可见等于泄露他人目录结构。
func (s *Store) GetSession(ctx context.Context, tenantID, sessionID, ownerID string) (Session, error) {
	var out Session
	var parent *string
	err := db.WithTenant(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		var pid *string
		if err := tx.QueryRow(ctx, `
			SELECT id::text, space_id::text, parent_id::text, name, declared_size,
			       received_bytes, status, part_size,
			       COALESCE(node_id::text, ''), COALESCE(version_id::text, ''), deduped
			  FROM upload_session
			 WHERE id = $1 AND created_by = $2`, sessionID, ownerID).
			Scan(&out.ID, &out.SpaceID, &pid, &out.Name, &out.DeclaredSize,
				&out.ReceivedBytes, &out.Status, &out.PartSize,
				&out.NodeID, &out.VersionID, &out.Deduped); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrSessionNotFound
			}
			return err
		}
		parent = pid
		parts, e := listParts(ctx, tx, sessionID)
		if e != nil {
			return e
		}
		out.Parts = parts
		return nil
	})
	if err != nil {
		return Session{}, err
	}
	if parent != nil {
		out.ParentID = *parent
	}
	return out, nil
}

// createNodeFromBlob 用已存在的 blob 直接建节点/版本（秒传的落库部分）。
func (s *Store) createNodeFromBlob(ctx context.Context, tx pgx.Tx, tenantID, spaceID, parentID,
	ownerID, name, blobID string, size int64) (nodeID, versionID string, err error) {

	var parent any
	if parentID != "" {
		parent = parentID
	}

	// 同名文件已存在 → 追加版本；否则新建节点
	err = tx.QueryRow(ctx, `
		SELECT id::text, current_version_id::text FROM node
		 WHERE space_id = $1 AND parent_id IS NOT DISTINCT FROM $2
		   AND lower(name) = lower($3) AND kind = 'file' AND deleted_at IS NULL`,
		spaceID, parent, name).Scan(&nodeID, new(string))
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return "", "", err
	}

	if nodeID == "" {
		if err := tx.QueryRow(ctx, `
			INSERT INTO node (id, tenant_id, space_id, parent_id, kind, name, size_bytes, owner_id)
			VALUES (gen_random_uuid(), $1, $2, $3, 'file', $4, $5, $6) RETURNING id::text`,
			tenantID, spaceID, parent, name, size, ownerID).Scan(&nodeID); err != nil {
			return "", "", err
		}
	}

	var nextNo int
	if err := tx.QueryRow(ctx,
		`SELECT COALESCE(max(version_no),0)+1 FROM version WHERE node_id = $1`, nodeID).Scan(&nextNo); err != nil {
		return "", "", err
	}

	var sha []byte
	if err := tx.QueryRow(ctx, `SELECT sha256 FROM blob WHERE id = $1`, blobID).Scan(&sha); err != nil {
		return "", "", err
	}

	if err := tx.QueryRow(ctx, `
		INSERT INTO version (id, tenant_id, node_id, version_no, blob_id, size_bytes, sha256, created_by)
		VALUES (gen_random_uuid(), $1, $2, $3, $4, $5, $6, $7) RETURNING id::text`,
		tenantID, nodeID, nextNo, blobID, size, sha, ownerID).Scan(&versionID); err != nil {
		return "", "", err
	}

	if _, err := tx.Exec(ctx, `
		UPDATE node SET size_bytes = $2, current_version_id = $3, updated_at = now() WHERE id = $1`,
		nodeID, size, versionID); err != nil {
		return "", "", err
	}
	// 这里曾经手动 ref_count + 1。现在计数由 version 触发器统一维护，
	// 再补一次就会变成双倍——删旧版本时永远减不到 0，将来 GC 不敢回收。
	return nodeID, versionID, nil
}

// sessionDir 是某会话的分片临时目录。
//
// sessionID 来自 URL，必须先做形状校验再拼路径：filepath.Join 会折叠 ".."，
// 一个形如 "../../etc" 的 id 足以把分片写到数据目录之外（AbortSession 里更是
// 直接 RemoveAll）。当前之所以没出事，只是因为前面那条 SQL 用了 uuid 类型的列，
// 非法 id 会先被数据库拒绝——那是"依赖调用顺序"的隐式防护，不是防护。
// PruneStaleSessions 清理超过 ttl 仍未完成的上传会话及其磁盘分片。
//
// 只删 status='open'：已完成/已中止的会话本身不带分片，删不删无所谓，
// 但保留它们能让"这个上传曾经完成过"在审计里查得到。
//
// 顺序是先库后盘：库里的行删掉后，磁盘目录即使删除失败也只是占空间，
// 不影响任何业务；反过来先删盘再删行，行还在但分片没了，
// 续传会拼出一份缺片的文件，要到 complete 才报错。
func (s *Store) PruneStaleSessions(ctx context.Context, ttl time.Duration) (int, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT sid::text FROM platform_prune_upload_sessions($1)`, ttl.String())
	if err != nil {
		return 0, err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return 0, err
		}
		ids = append(ids, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}

	for _, id := range ids {
		dir, derr := s.sessionDir(id)
		if derr != nil {
			continue
		}
		_ = os.RemoveAll(dir)
	}
	return len(ids), nil
}

func (s *Store) sessionDir(sessionID string) (string, error) {
	if !isUUIDShape(sessionID) {
		return "", ErrSessionNotFound
	}
	return filepath.Join(s.root, "..", "upload", sessionID), nil
}

// isUUIDShape 只校验形状（8-4-4-4-12 的十六进制），不做版本位检查。
// 目的不是"验证这是个真 UUID"，而是保证拼进路径的字符集与结构可控。
func isUUIDShape(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i := 0; i < 36; i++ {
		c := s[i]
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return false
			}
			continue
		}
		if !(c >= '0' && c <= '9') && !(c >= 'a' && c <= 'f') && !(c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}

// PutPart 保存一个分片。重复上传同一分片按覆盖处理（幂等）。
func (s *Store) PutPart(ctx context.Context, tenantID, sessionID, ownerID string, partNo int,
	data io.Reader, maxBytes int64) (int64, error) {

	if partNo < 1 {
		return 0, ErrBadInput
	}

	var status string
	var declared, partSize int64
	err := db.WithTenant(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
			SELECT status, declared_size, part_size FROM upload_session
			 WHERE id = $1 AND created_by = $2`, sessionID, ownerID).Scan(&status, &declared, &partSize)
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, ErrSessionNotFound
		}
		return 0, err
	}
	if status != "open" {
		return 0, ErrSessionDone
	}
	// 分片号必须落在声明的片数内。
	// 不校验的话，一个写错的 partNo 会永久留在磁盘与 upload_part 里，
	// complete 时既不会被合并也不会被清理，白占空间且没有任何报错。
	if partSize > 0 && declared >= 0 {
		total := int((declared + partSize - 1) / partSize)
		if total == 0 {
			total = 1
		}
		if partNo > total {
			return 0, ErrBadInput
		}
	}

	dir, derr := s.sessionDir(sessionID)
	if derr != nil {
		return 0, derr
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return 0, err
	}
	path := filepath.Join(dir, fmt.Sprintf("%06d.part", partNo))

	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o640)
	if err != nil {
		return 0, err
	}
	h := sha256.New()
	// 分片上限：不能超过声明总大小（防"单个分片塞满磁盘"）
	limit := maxBytes
	if declared > 0 && declared < limit {
		limit = declared
	}
	n, cerr := io.Copy(io.MultiWriter(f, h), io.LimitReader(data, limit+1))
	cerr2 := f.Close()
	if cerr != nil {
		_ = os.Remove(path)
		return 0, cerr
	}
	if cerr2 != nil {
		return 0, cerr2
	}
	if n > limit {
		_ = os.Remove(path)
		return 0, ErrTooLarge
	}

	err = db.WithTenant(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		if _, e := tx.Exec(ctx, `
			INSERT INTO upload_part (tenant_id, session_id, part_no, size_bytes, sha256)
			VALUES ($1, $2, $3, $4, $5)
			ON CONFLICT (session_id, part_no)
			DO UPDATE SET size_bytes = EXCLUDED.size_bytes, sha256 = EXCLUDED.sha256,
			              created_at = now()`,
			tenantID, sessionID, partNo, n, h.Sum(nil)); e != nil {
			return e
		}
		_, e := tx.Exec(ctx, `
			UPDATE upload_session SET received_bytes =
			       (SELECT COALESCE(sum(size_bytes),0) FROM upload_part WHERE session_id = $1),
			       updated_at = now()
			 WHERE id = $1`, sessionID)
		return e
	})
	return n, err
}

// CompleteSession 合并分片并落库。
//
// 幂等：已完成（status=completed）直接返回上次结果。
// 这正是 AC-78 要防的"重复调用 complete"——没有状态判断就会产生重复版本。
func (s *Store) CompleteSession(ctx context.Context, tenantID, sessionID, ownerID string) (Session, error) {
	var (
		status       string
		declared     int64
		declaredSHA  []byte
		spaceID      string
		parentID     *string
		name         string
		nodeID       *string
		versionID    *string
		deduped      bool
		receivedByDB int64
	)
	err := db.WithTenant(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
			SELECT status, declared_size, declared_sha256, space_id::text, parent_id::text, name,
			       node_id::text, version_id::text, deduped, received_bytes
			  FROM upload_session WHERE id = $1 AND created_by = $2 FOR UPDATE`,
			sessionID, ownerID).Scan(&status, &declared, &declaredSHA, &spaceID, &parentID, &name,
			&nodeID, &versionID, &deduped, &receivedByDB)
	})
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Session{}, ErrSessionNotFound
		}
		return Session{}, err
	}
	if status == "completed" {
		return Session{ID: sessionID, SpaceID: spaceID, ParentID: deref(parentID), Name: name,
			DeclaredSize: declared, Status: "completed",
			NodeID: deref(nodeID), VersionID: deref(versionID), Deduped: deduped}, nil
	}
	if status != "open" {
		return Session{}, ErrSessionDone
	}

	// 分片完整性：按 part_no 连续、总字节等于声明值
	var (
		cnt   int
		total int64
		maxNo int
		minNo int
	)
	if err := db.WithTenant(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `
			SELECT count(*), COALESCE(sum(size_bytes),0), COALESCE(max(part_no),0), COALESCE(min(part_no),0)
			  FROM upload_part WHERE session_id = $1`, sessionID).Scan(&cnt, &total, &maxNo, &minNo)
	}); err != nil {
		return Session{}, err
	}
	if cnt == 0 || minNo != 1 || maxNo != cnt {
		return Session{}, ErrPartsIncomplete
	}
	if total != declared {
		return Session{}, fmt.Errorf("%w: 收到 %d 字节，声明 %d 字节", ErrSizeMismatch, total, declared)
	}

	// 合并到一个临时文件，同时算哈希
	dir, derr := s.sessionDir(sessionID)
	if derr != nil {
		return Session{}, derr
	}
	merged, err := os.CreateTemp(dir, "merged-*.bin")
	if err != nil {
		return Session{}, err
	}
	mergedPath := merged.Name()
	defer func() {
		_ = merged.Close()
		_ = os.Remove(mergedPath)
	}()

	h := sha256.New()
	for i := 1; i <= cnt; i++ {
		p := filepath.Join(dir, fmt.Sprintf("%06d.part", i))
		f, err := os.Open(p)
		if err != nil {
			return Session{}, ErrPartsIncomplete
		}
		_, cerr := io.Copy(io.MultiWriter(merged, h), f)
		_ = f.Close()
		if cerr != nil {
			return Session{}, cerr
		}
	}
	if err := merged.Sync(); err != nil {
		return Session{}, err
	}
	if _, err := merged.Seek(0, io.SeekStart); err != nil {
		return Session{}, err
	}

	// 声明了哈希就必须匹配：这是"秒传伪造 size/哈希"的最后一道闸
	if len(declaredSHA) == 32 {
		if !equalBytes(h.Sum(nil), declaredSHA) {
			return Session{}, ErrHashMismatch
		}
	}

	nid, vid, _, err := s.UploadFile(ctx, tenantID, spaceID, deref(parentID), ownerID, name,
		"", merged, declared+1)
	if err != nil {
		return Session{}, err
	}

	if err := db.WithTenant(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `
			UPDATE upload_session
			   SET status = 'completed', node_id = $2, version_id = $3, updated_at = now()
			 WHERE id = $1 AND status = 'open'`, sessionID, nid, vid)
		return e
	}); err != nil {
		return Session{}, err
	}

	// 清理分片（失败不影响结果）
	_ = os.RemoveAll(dir)

	return Session{ID: sessionID, SpaceID: spaceID, ParentID: deref(parentID), Name: name,
		DeclaredSize: declared, Status: "completed", NodeID: nid, VersionID: vid}, nil
}

// AbortSession 中止会话并清理临时文件。
func (s *Store) AbortSession(ctx context.Context, tenantID, sessionID, ownerID string) error {
	err := db.WithTenant(ctx, s.pool, tenantID, func(tx pgx.Tx) error {
		tag, e := tx.Exec(ctx, `
			UPDATE upload_session SET status = 'aborted', updated_at = now()
			 WHERE id = $1 AND created_by = $2 AND status = 'open'`, sessionID, ownerID)
		if e != nil {
			return e
		}
		if tag.RowsAffected() == 0 {
			return ErrSessionNotFound
		}
		_, e = tx.Exec(ctx, `DELETE FROM upload_part WHERE session_id = $1`, sessionID)
		return e
	})
	if err != nil {
		return err
	}
	if dir, derr := s.sessionDir(sessionID); derr == nil {
		_ = os.RemoveAll(dir)
	}
	return nil
}

func deref[T any](p *T) string {
	if p == nil {
		return ""
	}
	return fmt.Sprint(*p)
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
