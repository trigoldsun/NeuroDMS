package integrations

import "errors"

// 自检失败的原因分类。
//
// 为什么必须分类：把上游原文直接甩到界面上，用户看到的是
// "SignatureDoesNotMatch" 或 "isv.ValidateFail"，既不知道是谁的问题，
// 也不知道下一步做什么。分类之后前端可以给一句能照做的话，
// 上游原文只写服务端日志（其中可能含号码、密钥前缀）。
const (
	CodeOK              = "ok"
	CodeAuthFailed      = "auth_failed"      // 密钥无效/被禁用/签名不匹配
	CodeTemplateMissing = "template_missing" // 模板不存在或未审核
	CodeSignMissing     = "sign_missing"     // 签名未报备
	CodeQuota           = "quota"            // 欠费/超限/被限流
	CodeNetwork         = "network"          // 超时/DNS/出网被拦
	CodeNotConfigured   = "not_configured"   // 必填项缺失或密钥解不开
	CodeUnknown         = "unknown"
)

// ClassifiedError 把上游错误收敛成一个稳定码 + 一句人话。
type ClassifiedError struct {
	Code string
	Msg  string
	Err  error
}

func (e *ClassifiedError) Error() string {
	if e.Msg != "" {
		return e.Msg
	}
	if e.Err != nil {
		return e.Err.Error()
	}
	return e.Code
}

func (e *ClassifiedError) Unwrap() error { return e.Err }

// Classify 构造一个带分类的错误。provider 实现用它包装上游返回。
func Classify(code, msg string, err error) error {
	return &ClassifiedError{Code: code, Msg: msg, Err: err}
}

// CodeFromError 取错误分类；未分类的按 unknown 处理，
// 消息保留原文（调用方决定是否展示/截断）。
func CodeFromError(err error) (code, msg string) {
	if err == nil {
		return CodeOK, ""
	}
	var ce *ClassifiedError
	if errors.As(err, &ce) {
		m := ce.Msg
		if m == "" {
			m = ce.Error()
		}
		return ce.Code, m
	}
	return CodeUnknown, err.Error()
}
