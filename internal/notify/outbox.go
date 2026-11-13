package notify

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Outbox 是通知外发队列。
type Outbox struct {
	pool    *pgxpool.Pool
	disp    *Dispatcher
	log     *slog.Logger
	channel string
	// MaxAttempts 超过后进入 dead（不再重试），避免坏地址无限占用队列。
	MaxAttempts int
	// BatchSize 单次扫描条数。
	BatchSize int
}

// NewOutbox 构造队列。channel 记录在行上，便于统计"哪个通道用得更多"。
func NewOutbox(pool *pgxpool.Pool, disp *Dispatcher, log *slog.Logger, channel string) *Outbox {
	if channel == "" {
		channel = "smtp"
	}
	return &Outbox{pool: pool, disp: disp, log: log, channel: channel, MaxAttempts: 5, BatchSize: 20}
}

// Enqueue 在业务事务内写入待发消息。
//
// 必须在业务事务里写：否则"业务成功但消息丢失"会静默发生，
// 用户以为发出去了、实际什么都没发。
func (o *Outbox) Enqueue(ctx context.Context, tx pgx.Tx, tenantID string, m Message, purpose string, refID *string) error {
	if err := validate(m); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `
		INSERT INTO notification (id, tenant_id, channel, to_addr, subject, body_text, body_html, purpose, ref_id)
		VALUES (gen_random_uuid(), $1, $2, $3, $4, $5, $6, $7, $8)`,
		tenantID, o.channel, m.To, m.Subject, m.Text, nullIfEmpty(m.HTML), purpose, refID)
	return err
}

// ProcessBatch 扫描并发送一批到期消息，返回成功/失败/终止条数。
func (o *Outbox) ProcessBatch(ctx context.Context) (sent, failed, dead int, err error) {
	rows, err := o.claim(ctx)
	if err != nil {
		return 0, 0, 0, err
	}
	for _, r := range rows {
		sendErr := o.disp.Send(ctx, Message{To: r.To, Subject: r.Subject, Text: r.Text, HTML: r.HTML})
		switch {
		case sendErr == nil:
			o.markSent(ctx, r.ID)
			sent++
		case errors.Is(sendErr, ErrPermanent) || r.Attempts >= o.MaxAttempts:
			o.markDead(ctx, r.ID, sendErr)
			o.log.Error("通知终止发送", "id", r.ID, "attempts", r.Attempts, "err", sendErr.Error())
			dead++
		default:
			o.markRetry(ctx, r.ID, sendErr, r.Attempts)
			o.log.Warn("通知发送失败，稍后重试", "id", r.ID, "attempts", r.Attempts, "err", sendErr.Error())
			failed++
		}
	}
	return sent, failed, dead, nil
}

type claimed struct {
	ID       string
	To       string
	Subject  string
	Text     string
	HTML     string
	Attempts int
}

// claim 用 FOR UPDATE SKIP LOCKED 抢占待发消息。
//
// SKIP LOCKED 是多实例安全的关键：两个 worker 同时扫描不会抢到同一条，
// 也不会因为等锁而串行化——否则加一个 worker 就等于没加。
func (o *Outbox) claim(ctx context.Context) ([]claimed, error) {
	size := o.BatchSize
	if size <= 0 {
		size = 20
	}
	rows, err := o.pool.Query(ctx, `
		WITH due AS (
			SELECT id FROM notification
			 WHERE status IN ('pending','failed') AND next_attempt_at <= now()
			 ORDER BY next_attempt_at
			 LIMIT $1
			 FOR UPDATE SKIP LOCKED
		)
		UPDATE notification n
		   SET status = 'sending', attempts = n.attempts + 1
		  FROM due
		 WHERE n.id = due.id
		RETURNING n.id::text, n.to_addr, n.subject, n.body_text,
		          COALESCE(n.body_html, ''), n.attempts`, size)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []claimed
	for rows.Next() {
		var c claimed
		if err := rows.Scan(&c.ID, &c.To, &c.Subject, &c.Text, &c.HTML, &c.Attempts); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (o *Outbox) markSent(ctx context.Context, id string) {
	_, err := o.pool.Exec(ctx,
		`UPDATE notification SET status='sent', sent_at=now(), last_error=NULL WHERE id=$1`, id)
	if err != nil {
		o.log.Error("更新通知状态失败", "id", id, "err", err.Error())
	}
}

func (o *Outbox) markDead(ctx context.Context, id string, cause error) {
	_, err := o.pool.Exec(ctx,
		`UPDATE notification SET status='dead', last_error=$2 WHERE id=$1`, id, truncErr(cause))
	if err != nil {
		o.log.Error("更新通知状态失败", "id", id, "err", err.Error())
	}
}

func (o *Outbox) markRetry(ctx context.Context, id string, cause error, attempts int) {
	next := time.Now().Add(backoff(attempts))
	_, err := o.pool.Exec(ctx,
		`UPDATE notification SET status='failed', last_error=$2, next_attempt_at=$3 WHERE id=$1`,
		id, truncErr(cause), next)
	if err != nil {
		o.log.Error("更新通知状态失败", "id", id, "err", err.Error())
	}
}

// RecoverStuck 把卡在 sending 超过 5 分钟的消息放回队列。
//
// 没有这一步，进程在"抢占之后、写结果之前"崩溃会让消息永久卡在 sending，
// 表现是"用户一直收不到，但队列里也没有待发项"——这类问题最难排查。
func (o *Outbox) RecoverStuck(ctx context.Context) (int64, error) {
	ct, err := o.pool.Exec(ctx, `
		UPDATE notification SET status='failed', next_attempt_at=now()
		 WHERE status='sending' AND created_at < now() - interval '5 minutes'`)
	if err != nil {
		return 0, err
	}
	return ct.RowsAffected(), nil
}

// Run 阻塞运行，直到 ctx 结束。间隔由调用方给出（默认 5 秒）。
func (o *Outbox) Run(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 5 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if n, err := o.RecoverStuck(ctx); err == nil && n > 0 {
				o.log.Warn("回收卡住的通知", "count", n)
			}
			if _, _, _, err := o.ProcessBatch(ctx); err != nil {
				o.log.Error("通知队列处理失败", "err", err.Error())
			}
		}
	}
}

func truncErr(err error) string {
	if err == nil {
		return ""
	}
	s := err.Error()
	if len(s) > 1000 {
		return s[:1000]
	}
	return s
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// DirectSender 同步发送并把结果落到 notification 表。
//
// 与 Outbox 的分工：
//   - 验证码、邀请这类"用户正在等待"的消息走 DirectSender（同步、错误立即上抛）
//   - 通知类消息走 Outbox（异步、可重试）
//
// 两者都写同一张表，因此"发了什么、发没发出去"只有一处真相。
type DirectSender struct {
	pool    *pgxpool.Pool
	disp    *Dispatcher
	log     *slog.Logger
	channel string
}

// NewDirectSender 构造同步发送器。
func NewDirectSender(pool *pgxpool.Pool, disp *Dispatcher, log *slog.Logger, channel string) *DirectSender {
	if channel == "" {
		channel = "smtp"
	}
	return &DirectSender{pool: pool, disp: disp, log: log, channel: channel}
}

// SendSync 发送一条消息并记录结果。返回错误表示"没有发出去"。
func (d *DirectSender) SendSync(ctx context.Context, tenantID string, m Message, purpose string, refID *string) error {
	if err := validate(m); err != nil {
		return err
	}
	var id string
	if err := d.pool.QueryRow(ctx, `
		INSERT INTO notification (id, tenant_id, channel, to_addr, subject, body_text, body_html,
		                          purpose, ref_id, status, attempts)
		VALUES (gen_random_uuid(), $1, $2, $3, $4, $5, $6, $7, $8, 'sending', 1)
		RETURNING id::text`,
		tenantID, d.channel, m.To, m.Subject, m.Text, nullIfEmpty(m.HTML), purpose, refID).Scan(&id); err != nil {
		return err
	}

	err := d.disp.Send(ctx, m)
	if err == nil {
		_, _ = d.pool.Exec(ctx,
			`UPDATE notification SET status='sent', sent_at=now() WHERE id=$1`, id)
		return nil
	}
	status := "failed"
	if errors.Is(err, ErrPermanent) {
		status = "dead"
	}
	_, _ = d.pool.Exec(ctx,
		`UPDATE notification SET status=$2, last_error=$3 WHERE id=$1`, id, status, truncErr(err))
	d.log.Error("同步通知发送失败", "id", id, "purpose", purpose, "err", err.Error())
	return err
}
