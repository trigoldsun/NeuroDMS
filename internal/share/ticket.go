package share

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net"
	"time"

	"docvault/internal/db"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// 票据有效期。5 分钟足够"打开页面 → 点下载"这段交互，
// 又短到即使票据泄漏（复制链接、日志）也几乎无法利用。
const DefaultTicketTTL = 5 * time.Minute

// ErrTicketInvalid 是票据不可用的唯一对外原因（不存在/过期/已撤销/分享已撤）。
var ErrTicketInvalid = errors.New("访问票据无效或已过期")

// Ticket 是解析后的票据上下文。
type Ticket struct {
	ID            string
	ShareID       string
	TenantID      string
	ObjectType    string
	ObjectID      string
	AllowDownload bool
	Watermark     bool
	ExpiresAt     time.Time
	// MaxClass 是分享创建时的密级上界（见 Redeemed.MaxClass）。
	// 取内容时必须校验 node.classification <= MaxClass，否则空间级外链
	// 会把发起人也看不到的高密文件一并交出去。
	MaxClass int
}

// IssueTicket 兑换成功后签发短期票据。
//
// 票据是随机串，库中只存 SHA-256：即使备份泄露也无法直接使用。
// ip 用于绑定来源网段——票据被复制到另一台机器/另一个网络后立刻失效，
// 这是"链接可收回"之外的第二道护栏。
func IssueTicket(ctx context.Context, pool *pgxpool.Pool, r Redeemed, ip string, ttl time.Duration) (string, time.Time, error) {
	if ttl <= 0 {
		ttl = DefaultTicketTTL
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", time.Time{}, err
	}
	ticket := base64.RawURLEncoding.EncodeToString(raw)
	sum := sha256.Sum256([]byte(ticket))
	expires := time.Now().Add(ttl)

	var prefix any
	if p := ipPrefix(ip); p != "" {
		prefix = p
	}

	err := db.WithTenant(ctx, pool, r.TenantID, func(tx pgx.Tx) error {
		_, e := tx.Exec(ctx, `
			INSERT INTO share_ticket (id, tenant_id, share_id, ticket_hash, ip_prefix, expires_at)
			VALUES (gen_random_uuid(), $1, $2, $3, $4::cidr, $5)`,
			r.TenantID, r.ShareID, sum[:], prefix, expires)
		return e
	})
	if err != nil {
		return "", time.Time{}, err
	}
	return ticket, expires, nil
}

// ResolveTicket 校验票据并返回取字节所需的最小信息。
//
// 这里必须 join 回 share：分享被撤销后，已发出的票据要在下一次请求时立刻失效。
// 只查票据表是不够的——那正是"撤销了但还能下载"的经典漏洞。
func ResolveTicket(ctx context.Context, pool *pgxpool.Pool, ticket, ip string) (Ticket, error) {
	sum := sha256.Sum256([]byte(ticket))

	var tenantID string
	if err := pool.QueryRow(ctx,
		`SELECT tenant_id FROM share_ticket WHERE ticket_hash = $1`, sum[:]).Scan(&tenantID); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Ticket{}, ErrTicketInvalid
		}
		return Ticket{}, err
	}

	var out Ticket
	err := db.WithTenant(ctx, pool, tenantID, func(tx pgx.Tx) error {
		var allowDownload, watermark bool
		var objType, objID string
		var shareID string
		var maxClass int
		var ticketExpires time.Time
		var ticketRevoked, shareRevoked, shareExpires *time.Time
		var approval string

		err := tx.QueryRow(ctx, `
			SELECT t.id::text, t.share_id::text, t.expires_at, t.revoked_at,
			       s.object_type, s.object_id::text, s.allow_download, s.watermark,
			       s.revoked_at, s.expires_at, s.approval_status, s.max_class
			  FROM share_ticket t JOIN share s ON s.id = t.share_id
			 WHERE t.ticket_hash = $1`, sum[:]).
			Scan(&out.ID, &shareID, &ticketExpires, &ticketRevoked,
				&objType, &objID, &allowDownload, &watermark,
				&shareRevoked, &shareExpires, &approval, &maxClass)
		if err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return ErrTicketInvalid
			}
			return err
		}

		now := time.Now()
		if ticketRevoked != nil || ticketExpires.Before(now) {
			return ErrTicketInvalid
		}
		if shareRevoked != nil {
			return ErrTicketInvalid
		}
		if shareExpires != nil && shareExpires.Before(now) {
			return ErrTicketInvalid
		}
		if approval == "pending" || approval == "rejected" {
			return ErrTicketInvalid
		}

		out.ShareID = shareID
		out.TenantID = tenantID
		out.ObjectType = objType
		out.ObjectID = objID
		out.AllowDownload = allowDownload
		out.Watermark = watermark
		out.MaxClass = maxClass
		out.ExpiresAt = ticketExpires
		return nil
	})
	if err != nil {
		return Ticket{}, err
	}

	// IP 绑定：票据发出时记录的网段必须覆盖本次请求来源
	if !ipMatchesPrefix(ctx, pool, tenantID, out.ID, ip) {
		return Ticket{}, ErrTicketInvalid
	}
	return out, nil
}

// TooClassified 判断某密级的节点是否超出本票据的可取范围。
//
// 单独抽成方法而不是在各处写 n.Classification > t.MaxClass：
// 这个比较在"元信息、列目录、取内容"三处都要用，写法一旦不一致
// 就会出现"列表里看不到、但猜 id 能下载"的经典漏洞。
func (t Ticket) TooClassified(nodeClass int) bool { return nodeClass > t.MaxClass }

// RevokeTickets 让某个分享的全部票据立即失效（撤销分享时调用）。
func RevokeTickets(ctx context.Context, tx pgx.Tx, shareID string) error {
	_, err := tx.Exec(ctx,
		`UPDATE share_ticket SET revoked_at = now() WHERE share_id = $1 AND revoked_at IS NULL`, shareID)
	return err
}

func ipMatchesPrefix(ctx context.Context, pool *pgxpool.Pool, tenantID, ticketID, ip string) bool {
	prefix := ipPrefix(ip)
	if prefix == "" {
		// 来源 IP 不可解析（例如本机 Unix socket 或测试）时不强制绑定，
		// 但要靠票据本身的高熵与短 TTL 兜底。
		return true
	}
	var stored *string
	_ = db.WithTenant(ctx, pool, tenantID, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT ip_prefix::text FROM share_ticket WHERE id = $1`, ticketID).Scan(&stored)
	})
	if stored == nil || *stored == "" {
		return true
	}
	_, netw, err := net.ParseCIDR(*stored)
	if err != nil {
		return false
	}
	addr := net.ParseIP(ip)
	if addr == nil {
		return false
	}
	return netw.Contains(addr)
}

// ipPrefix 把来源 IP 归一化为网段：
// IPv4 取 /24（同一办公网络）、IPv6 取 /64（同一接入点）。
// 不用 /32：移动网络与 NAT 环境下同一用户的出口 IP 会漂移，会造成刚打开就失效。
func ipPrefix(ip string) string {
	addr := net.ParseIP(ip)
	if addr == nil {
		return ""
	}
	var ones int
	if v4 := addr.To4(); v4 != nil {
		ones = 24
	} else {
		ones = 64
	}
	_, netw, err := net.ParseCIDR(addr.String() + func() string {
		if ones == 24 {
			return "/24"
		}
		return "/64"
	}())
	if err != nil {
		return ""
	}
	return netw.String()
}
