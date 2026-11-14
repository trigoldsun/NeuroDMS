package notify

// 按租户路由的用例。
//
// 这一层最容易出的两个错都在这里守住：
//   - 没配自有通道时**必须**回落到平台默认（否则升级即静默失效）；
//   - 什么都没配时**必须**报错，而不是假装成功（否则"用户没收到"无声无息）。

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

type recordingSender struct {
	name string
	mu   sync.Mutex
	got  []Message
}

func (r *recordingSender) Name() string { return r.name }

func (r *recordingSender) Send(_ context.Context, m Message) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.got = append(r.got, m)
	return nil
}

func (r *recordingSender) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.got)
}

// 没有租户配置（inherit）→ 用平台默认通道。
func TestRouterInheritsPlatformDefault(t *testing.T) {
	fallbackSender := &recordingSender{name: "smtp"}
	router := NewRouter(NewDispatcher(fallbackSender, nil), func(context.Context, string) (Settings, error) {
		return Settings{Mode: ModeInherit, Source: "none"}, nil
	}, nil)

	if _, err := router.SendFor(context.Background(), "t1", Message{To: "a@example.com", Subject: "s"}); err != nil {
		t.Fatalf("发送失败: %v", err)
	}
	if fallbackSender.count() != 1 {
		t.Fatalf("inherit 应走平台默认通道，实际 %d 次", fallbackSender.count())
	}
}

// 租户配置了自己的 SMTP → 走自己的，不回落到平台默认。
func TestRouterUsesTenantSMTP(t *testing.T) {
	srv := startFakeSMTP(t)
	host, portStr, _ := net.SplitHostPort(srv.addr)
	var port int
	_, _ = fmt.Sscanf(portStr, "%d", &port)

	fallbackSender := &recordingSender{name: "smtp"}
	router := NewRouter(NewDispatcher(fallbackSender, nil), func(context.Context, string) (Settings, error) {
		return Settings{
			Mode: ModeSMTP, SMTPHost: host, SMTPPort: port, SMTPTLS: "none",
			FromAddr: "noreply@tenant.example", ReplyTo: "support@tenant.example",
		}, nil
	}, nil)

	ch, err := router.SendFor(context.Background(), "t1",
		Message{To: "user@example.com", Subject: "验证码", Text: "123456"})
	if err != nil {
		t.Fatalf("发送失败: %v", err)
	}
	if ch != "smtp" {
		t.Fatalf("通道应为 smtp，实际 %q", ch)
	}
	if fallbackSender.count() != 0 {
		t.Fatal("配置了自有通道时不应使用平台默认通道")
	}

	select {
	case data := <-srv.gotData:
		if !strings.Contains(data, "To: user@example.com") {
			t.Fatalf("收件人不正确: %s", data)
		}
		// 租户配置的 Reply-To 应写进邮件头：发件人是 noreply 时回信要能进客服邮箱
		if !strings.Contains(data, "Reply-To: support@tenant.example") {
			t.Fatalf("缺少 Reply-To: %s", data)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("邮件未送达测试 SMTP")
	}
}

// 什么都没配：必须明确失败，且标记为永久错误（避免无意义重试）。
func TestRouterNoChannelFailsPermanently(t *testing.T) {
	router := NewRouter(nil, func(context.Context, string) (Settings, error) {
		return Settings{Mode: ModeInherit}, nil
	}, nil)

	_, err := router.SendFor(context.Background(), "t1", Message{To: "a@example.com", Subject: "s"})
	if err == nil {
		t.Fatal("没有任何通道时应返回错误")
	}
	if !errors.Is(err, ErrPermanent) {
		t.Fatalf("应标记为永久错误，实际 %v", err)
	}
}

// 配置缓存：TTL 内只读一次库；Invalidate 后立刻重新读取。
func TestRouterCachesAndInvalidates(t *testing.T) {
	var loads int
	sender := &recordingSender{name: "smtp"}
	router := NewRouter(NewDispatcher(sender, nil), func(context.Context, string) (Settings, error) {
		loads++
		return Settings{Mode: ModeInherit}, nil
	}, nil)

	for i := 0; i < 3; i++ {
		if _, err := router.SendFor(context.Background(), "t1", Message{To: "a@example.com", Subject: "s"}); err != nil {
			t.Fatal(err)
		}
	}
	if loads != 1 {
		t.Fatalf("TTL 内应只读一次配置，实际 %d 次", loads)
	}

	router.Invalidate("t1")
	if _, err := router.SendFor(context.Background(), "t1", Message{To: "a@example.com", Subject: "s"}); err != nil {
		t.Fatal(err)
	}
	if loads != 2 {
		t.Fatalf("失效后应重新读取，实际 %d 次", loads)
	}
	if sender.count() != 4 {
		t.Fatalf("应发出 4 封，实际 %d", sender.count())
	}
}
