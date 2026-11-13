// Package notify 负责把系统消息发出去，并保证"发不出去"这件事可追溯。
//
// 设计要点：
//  1. 业务代码只写 notification 表（同事务），不直接调 SMTP/Graph；
//  2. 后台 worker 扫描待发队列，失败按指数退避重试，超过上限进入 dead；
//  3. 主通道失败自动切备用通道（SMTP ⇄ Graph），但通道切换不掩盖错误：
//     日志与 last_error 里会写明两条通道各自的结果。
package notify

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Message 是一条待发消息。
type Message struct {
	To      string
	Subject string
	Text    string
	HTML    string
}

// Sender 是一个可用的外发通道。
type Sender interface {
	// Name 返回通道名（smtp / graph），用于日志与状态记录。
	Name() string
	Send(ctx context.Context, m Message) error
}

// ErrPermanent 标记"重试也不会成功"的失败（如收件人地址非法）。
// 这类错误直接进 dead，不做无意义重试——无限重试会把队列打爆。
var ErrPermanent = errors.New("永久性失败")

// Permanent 包装一个永久性错误。
func Permanent(err error) error { return fmt.Errorf("%w: %v", ErrPermanent, err) }

// Dispatcher 按顺序尝试通道，全部失败才返回错误。
type Dispatcher struct {
	primary  Sender
	fallback Sender
}

// NewDispatcher 构造通道调度器。fallback 可为 nil。
func NewDispatcher(primary, fallback Sender) *Dispatcher {
	return &Dispatcher{primary: primary, fallback: fallback}
}

// Channels 返回已配置的通道名，用于启动日志（让运维一眼看出"到底配了几个通道"）。
func (d *Dispatcher) Channels() []string {
	var out []string
	if d.primary != nil {
		out = append(out, d.primary.Name())
	}
	if d.fallback != nil {
		out = append(out, d.fallback.Name())
	}
	return out
}

// Send 依次尝试通道。
func (d *Dispatcher) Send(ctx context.Context, m Message) error {
	if err := validate(m); err != nil {
		return err
	}
	if d.primary == nil && d.fallback == nil {
		return Permanent(errors.New("未配置任何通知通道"))
	}

	var errs []string
	for _, s := range []Sender{d.primary, d.fallback} {
		if s == nil {
			continue
		}
		err := s.Send(ctx, m)
		if err == nil {
			return nil
		}
		errs = append(errs, s.Name()+": "+err.Error())
		// 永久性失败不需要换通道重试（地址本身就是错的）
		if errors.Is(err, ErrPermanent) {
			return err
		}
	}
	return errors.New(strings.Join(errs, " | "))
}

func validate(m Message) error {
	if strings.TrimSpace(m.To) == "" {
		return Permanent(errors.New("收件人为空"))
	}
	// 只做最基本的形态校验：真正的地址合法性由 SMTP 服务器判定，
	// 在这里用复杂正则反而会误杀合法地址（如带 + 标签的地址）
	at := strings.LastIndex(m.To, "@")
	if at <= 0 || at == len(m.To)-1 || !strings.Contains(m.To[at+1:], ".") {
		return Permanent(fmt.Errorf("收件人地址非法: %s", m.To))
	}
	if strings.TrimSpace(m.Subject) == "" {
		return Permanent(errors.New("主题为空"))
	}
	return nil
}

// backoff 计算第 n 次失败后的等待时间：30s, 1m, 2m, 4m, 8m… 上限 30 分钟。
// 用指数退避而不是固定间隔：对端故障通常是分钟级恢复，
// 固定 30s 重试会在故障期间堆积大量无用请求。
func backoff(attempts int) time.Duration {
	if attempts <= 0 {
		return 0
	}
	d := 30 * time.Second
	for i := 1; i < attempts; i++ {
		d *= 2
		if d >= 30*time.Minute {
			return 30 * time.Minute
		}
	}
	return d
}
