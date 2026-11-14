// Package sms 封装"发短信验证码"与"核验验证码"。
//
// 本项目用的是阿里云**短信认证服务**（号码认证服务 PNVS，dypnsapi），
// 不是短信服务 SMS：
//   - 发码：SendSmsVerifyCode，验证码由阿里云生成（TemplateParam 里用 ##code##）；
//   - 核验：CheckSmsVerifyCode，核验免费，以 Model.VerifyResult == "PASS" 为准。
//
// 边界约定：本包只回答"发出去了吗 / 这个码对不对"，
// 账号是否存在、能不能登录、频控与审计都在上层（auth / httpapi）。
package sms

import (
	"context"
	"errors"
	"sync"
)

var (
	// ErrNotConfigured 表示没有配置短信通道（缺 AccessKey/签名/模板）。
	// 上层必须据此 fail-closed：绝不能因为没配置就跳过验证。
	ErrNotConfigured = errors.New("短信认证服务未配置")
	// ErrUnavailable 表示调用失败（超时、签名错误、欠费、产品未开通等）。
	ErrUnavailable = errors.New("短信认证服务暂不可用")
)

// Provider 是登录链路需要的最小能力。
type Provider interface {
	// SendVerifyCode 向 E.164 号码（+86...）发送一条登录验证码。
	Send(ctx context.Context, phone string) error
	// Check 判断验证码是否正确。error 只表示"调用失败"，false 表示"码不对"。
	Check(ctx context.Context, phone, code string) (bool, error)
}

// Mock 是本地/测试用的实现：不联网，验证码固定。
//
// 只能在显式开启时使用（DOCVAULT_SMS_MOCK=1），且生产环境拒绝启动——
// 一个"永远返回通过"的短信通道，等于把所有账号变成免密登录。
type Mock struct {
	code string
	mu   sync.Mutex
	last map[string]string
}

// NewMock 构造固定验证码的模拟通道。
func NewMock(code string) *Mock {
	if code == "" {
		code = "123456"
	}
	return &Mock{code: code, last: map[string]string{}}
}

func (m *Mock) Send(_ context.Context, phone string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.last[phone] = m.code
	return nil
}

func (m *Mock) Check(_ context.Context, phone, code string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	want, ok := m.last[phone]
	if !ok {
		return false, nil
	}
	return code == want, nil
}
