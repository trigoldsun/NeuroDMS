package sms

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Aliyun 对接阿里云"短信认证服务"（dypnsapi 2017-05-25）。
//
// 刻意不引官方 SDK：这一层只用两个 Action，签名算法是公开且稳定的 RPC 风格，
// 手写 80 行比拖一个依赖树更容易审计——尤其是"到底调的是哪个产品"这件事，
// 在代码里写死 Action 名称比藏在 SDK 方法后面更不容易搞错。
type Aliyun struct {
	cfg    AliyunConfig
	client *http.Client
	now    func() time.Time
}

// AliyunConfig 是短信认证服务的凭据与签名模板。
type AliyunConfig struct {
	AccessKeyID     string
	AccessKeySecret string
	// SignName / TemplateCode 使用控制台赠送的签名与模板：
	// 短信认证服务暂不支持自定义签名，自申请签名的场景属于"短信服务 SMS"。
	SignName     string
	TemplateCode string
	// SchemeName 用于区分不同业务方案，发送与核验必须一致；留空即"默认方案"。
	SchemeName string
	// Endpoint 默认 dypnsapi.aliyuncs.com，测试时可指向 httptest。
	Endpoint string
}

const (
	actionSend  = "SendSmsVerifyCode"
	actionCheck = "CheckSmsVerifyCode"
	apiVersion  = "2017-05-25"
)

// NewAliyun 构造通道；缺关键字段直接报 ErrNotConfigured，不留"能构造但一调就错"的对象。
func NewAliyun(cfg AliyunConfig) (*Aliyun, error) {
	cfg.AccessKeyID = strings.TrimSpace(cfg.AccessKeyID)
	cfg.AccessKeySecret = strings.TrimSpace(cfg.AccessKeySecret)
	cfg.SignName = strings.TrimSpace(cfg.SignName)
	cfg.TemplateCode = strings.TrimSpace(cfg.TemplateCode)
	if cfg.Endpoint == "" {
		cfg.Endpoint = "https://dypnsapi.aliyuncs.com"
	}
	if cfg.AccessKeyID == "" || cfg.AccessKeySecret == "" || cfg.SignName == "" || cfg.TemplateCode == "" {
		return nil, ErrNotConfigured
	}
	return &Aliyun{
		cfg:    cfg,
		client: &http.Client{Timeout: 6 * time.Second},
		now:    time.Now,
	}, nil
}

// Send 发送登录验证码。
//
// 参数是刻意写死的：6 位、5 分钟、60 秒间隔、新码覆盖旧码。
// 不读默认值是因为阿里云默认是 4 位——4 位数字只有 1 万种，配合不限次核验，
// 穷举成本低到不可接受。
func (a *Aliyun) Send(ctx context.Context, phone string) error {
	national, err := nationalNumber(phone)
	if err != nil {
		return fmt.Errorf("%w: 号码格式不正确", ErrUnavailable)
	}
	params := map[string]string{
		"Action":           actionSend,
		"CountryCode":      "86",
		"PhoneNumber":      national,
		"SignName":         a.cfg.SignName,
		"TemplateCode":     a.cfg.TemplateCode,
		"TemplateParam":    `{"code":"##code##","min":"5"}`,
		"CodeLength":       "6",
		"ValidTime":        "300",
		"DuplicatePolicy":  "1",
		"Interval":         "60",
		"CodeType":         "1",
		"ReturnVerifyCode": "false",
	}
	if a.cfg.SchemeName != "" {
		params["SchemeName"] = a.cfg.SchemeName
	}
	resp, err := a.call(ctx, params)
	if err != nil {
		return err
	}
	if !resp.Success || resp.Code != "OK" {
		return fmt.Errorf("%w: %s %s", ErrUnavailable, resp.Code, resp.Message)
	}
	return nil
}

// Check 核验验证码。
//
// 注意：接口 Success=true 只代表"调用成功"，验证码对不对只看 Model.VerifyResult。
// 这个区别写错一次，登录就会变成"输入任意验证码都能过"。
func (a *Aliyun) Check(ctx context.Context, phone, code string) (bool, error) {
	national, err := nationalNumber(phone)
	if err != nil {
		return false, fmt.Errorf("%w: 号码格式不正确", ErrUnavailable)
	}
	code = strings.TrimSpace(code)
	if code == "" {
		return false, nil
	}
	params := map[string]string{
		"Action":         actionCheck,
		"CountryCode":    "86",
		"PhoneNumber":    national,
		"VerifyCode":     code,
		"CaseAuthPolicy": "1",
	}
	if a.cfg.SchemeName != "" {
		params["SchemeName"] = a.cfg.SchemeName
	}
	resp, err := a.call(ctx, params)
	if err != nil {
		return false, err
	}
	if !resp.Success || resp.Code != "OK" {
		return false, fmt.Errorf("%w: %s %s", ErrUnavailable, resp.Code, resp.Message)
	}
	return resp.Model.VerifyResult == "PASS", nil
}

type aliyunResp struct {
	Code    string `json:"Code"`
	Message string `json:"Message"`
	Success bool   `json:"Success"`
	Model   struct {
		VerifyResult string `json:"VerifyResult"`
	} `json:"Model"`
}

// call 发起一次 RPC 请求（GET + HMAC-SHA1 签名）。
func (a *Aliyun) call(ctx context.Context, action map[string]string) (aliyunResp, error) {
	params := map[string]string{
		"Format":           "JSON",
		"Version":          apiVersion,
		"AccessKeyId":      a.cfg.AccessKeyID,
		"SignatureMethod":  "HMAC-SHA1",
		"SignatureVersion": "1.0",
		"SignatureNonce":   nonce(),
		"Timestamp":        a.now().UTC().Format("2006-01-02T15:04:05Z"),
	}
	for k, v := range action {
		params[k] = v
	}
	params["Signature"] = sign(params, a.cfg.AccessKeySecret)

	// 查询串必须与签名用同一套编码（percentEncode），
	// 不能图省事用 url.Values.Encode()：它把空格编成 '+'，签名就会对不上。
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, percentEncode(k)+"="+percentEncode(params[k]))
	}
	endpoint := strings.TrimRight(a.cfg.Endpoint, "/") + "/?" + strings.Join(parts, "&")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return aliyunResp{}, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return aliyunResp{}, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return aliyunResp{}, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	if resp.StatusCode >= 500 {
		return aliyunResp{}, fmt.Errorf("%w: HTTP %d", ErrUnavailable, resp.StatusCode)
	}
	var out aliyunResp
	if err := json.Unmarshal(body, &out); err != nil {
		return aliyunResp{}, fmt.Errorf("%w: 响应解析失败", ErrUnavailable)
	}
	return out, nil
}

// sign 按阿里云 RPC 签名规则计算 Signature。
func sign(params map[string]string, secret string) string {
	keys := make([]string, 0, len(params))
	for k := range params {
		if k == "Signature" {
			continue
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var canonical strings.Builder
	for i, k := range keys {
		if i > 0 {
			canonical.WriteByte('&')
		}
		canonical.WriteString(percentEncode(k))
		canonical.WriteByte('=')
		canonical.WriteString(percentEncode(params[k]))
	}
	toSign := "GET&%2F&" + percentEncode(canonical.String())
	mac := hmac.New(sha1.New, []byte(secret+"&"))
	mac.Write([]byte(toSign))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

// percentEncode 是阿里云要求的 RFC 3986 编码：
// url.QueryEscape 把空格编成 '+'、把 '~' 编成 %7E，这两处必须纠正，
// 否则签名对不上，报错只会说 "SignatureDoesNotMatch"，很难查。
func percentEncode(s string) string {
	r := strings.NewReplacer("+", "%20", "*", "%2A", "%7E", "~")
	return r.Replace(url.QueryEscape(s))
}

func nonce() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// 随机源失败极罕见；退化成时间戳也只会让重放窗口变大，
		// 但签名仍然有效，不会把登录彻底堵死。
		return strconv.FormatInt(time.Now().UnixNano(), 10)
	}
	return hex.EncodeToString(b)
}

// nationalNumber 把 E.164 的 +86 号码转成接口需要的 11 位。
func nationalNumber(e164 string) (string, error) {
	s := strings.TrimSpace(e164)
	if strings.HasPrefix(s, "+86") {
		s = s[3:]
	}
	if len(s) != 11 || s[0] != '1' {
		return "", fmt.Errorf("号码格式不正确")
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return "", fmt.Errorf("号码格式不正确")
		}
	}
	return s, nil
}
