package sms

// 阿里云「短信认证服务」（dypnsapi 2017-05-25）。
//
// 刻意不引官方 SDK：这一层只用两个 Action，签名算法是公开且稳定的 RPC 风格，
// 手写 80 行比拖一个依赖树更容易审计——尤其是"到底调的是哪个产品"这件事，
// 在代码里写死 Action 名称比藏在 SDK 方法后面更不容易搞错。

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

	"docvault/internal/integrations"
)

type aliyun struct {
	cfg    aliyunConfig
	client *http.Client
	now    func() time.Time
}

type aliyunConfig struct {
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
	// TestPhone 仅用于自检。
	TestPhone string
}

const (
	actionSend   = "SendSmsVerifyCode"
	actionCheck  = "CheckSmsVerifyCode"
	aliyunAPIVer = "2017-05-25"
)

func newAliyun(cfg, sec map[string]string) (Provider, error) {
	c := aliyunConfig{
		AccessKeyID:     strings.TrimSpace(cfg["accessKeyId"]),
		AccessKeySecret: sec["accessKeySecret"],
		SignName:        strings.TrimSpace(cfg["signName"]),
		TemplateCode:    strings.TrimSpace(cfg["templateCode"]),
		SchemeName:      strings.TrimSpace(cfg["schemeName"]),
		Endpoint:        strings.TrimSpace(cfg["endpoint"]),
		TestPhone:       strings.TrimSpace(cfg["testPhone"]),
	}
	if c.Endpoint == "" {
		c.Endpoint = "https://dypnsapi.aliyuncs.com"
	}
	if c.AccessKeyID == "" || c.AccessKeySecret == "" || c.SignName == "" || c.TemplateCode == "" {
		return nil, fmt.Errorf("%w: 阿里云需要 AccessKey、签名与模板", integrations.ErrNotConfigured)
	}
	return &aliyun{cfg: c, client: &http.Client{Timeout: 6 * time.Second}, now: time.Now}, nil
}

// NewAliyun 用平台环境变量构造通道（SaaS 的默认通道，兼容旧配置）。
//
// 租户自带通道走 integration_config，不经过这里。
func NewAliyun(accessKeyID, accessKeySecret, signName, templateCode, schemeName string) (Provider, error) {
	return newAliyun(
		map[string]string{
			"accessKeyId":  accessKeyID,
			"signName":     signName,
			"templateCode": templateCode,
			"schemeName":   schemeName,
		},
		map[string]string{"accessKeySecret": accessKeySecret},
	)
}

func (a *aliyun) Code() string { return "aliyun" }
func (a *aliyun) Mode() Mode   { return Managed }

// Send 发送登录验证码。
//
// 参数是刻意写死的：6 位、5 分钟、60 秒间隔、新码覆盖旧码。
// 不读默认值是因为阿里云默认是 4 位——4 位数字只有 1 万种，配合不限次核验，
// 穷举成本低到不可接受。code 参数在 managed 模式下由厂商生成，这里忽略。
func (a *aliyun) Send(ctx context.Context, phone, _ string) error {
	national, err := nationalNumber(phone)
	if err != nil {
		return integrations.Classify(integrations.CodeAuthFailed, "号码格式不正确", err)
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
		return classifyAliyun(resp.Code, resp.Message)
	}
	return nil
}

// Verify 核验验证码。
//
// 注意：接口 Success=true 只代表"调用成功"，验证码对不对只看 Model.VerifyResult。
// 这个区别写错一次，登录就会变成"输入任意验证码都能过"。
func (a *aliyun) Verify(ctx context.Context, phone, code string) (bool, error) {
	national, err := nationalNumber(phone)
	if err != nil {
		return false, integrations.Classify(integrations.CodeAuthFailed, "号码格式不正确", err)
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
		return false, classifyAliyun(resp.Code, resp.Message)
	}
	return resp.Model.VerifyResult == "PASS", nil
}

// Test 只核验、不发送（核验接口免费）。
//
// 用一个必然错误的码去核验：能拿到 "FAIL" 就说明鉴权、签名、模板都对；
// 鉴权错会直接返回错误码。这样自检不花钱。
func (a *aliyun) Test(ctx context.Context) error {
	if a.cfg.TestPhone == "" {
		return integrations.Classify(integrations.CodeNotConfigured,
			"请先填写「自检号码」再测试（阿里云自检只核验，不发送）", nil)
	}
	if _, err := a.Verify(ctx, a.cfg.TestPhone, "000000"); err != nil {
		return err
	}
	return nil
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
func (a *aliyun) call(ctx context.Context, action map[string]string) (aliyunResp, error) {
	params := map[string]string{
		"Format":           "JSON",
		"Version":          aliyunAPIVer,
		"AccessKeyId":      a.cfg.AccessKeyID,
		"SignatureMethod":  "HMAC-SHA1",
		"SignatureVersion": "1.0",
		"SignatureNonce":   nonce(),
		"Timestamp":        a.now().UTC().Format("2006-01-02T15:04:05Z"),
	}
	for k, v := range action {
		params[k] = v
	}
	params["Signature"] = signRPC(params, a.cfg.AccessKeySecret)

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
		return aliyunResp{}, integrations.Classify(integrations.CodeNetwork, "请求构造失败", err)
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return aliyunResp{}, integrations.Classify(integrations.CodeNetwork, "无法连接阿里云接口", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return aliyunResp{}, integrations.Classify(integrations.CodeNetwork, "读取响应失败", err)
	}
	if resp.StatusCode >= 500 {
		return aliyunResp{}, integrations.Classify(integrations.CodeQuota,
			fmt.Sprintf("阿里云返回 HTTP %d", resp.StatusCode), nil)
	}
	var out aliyunResp
	if err := json.Unmarshal(body, &out); err != nil {
		return aliyunResp{}, integrations.Classify(integrations.CodeUnknown, "阿里云响应解析失败", err)
	}
	return out, nil
}

// signRPC 按阿里云 RPC 签名规则计算 Signature。
func signRPC(params map[string]string, secret string) string {
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

// classifyAliyun 把阿里云错误码收敛成前端可解释的分类。
func classifyAliyun(code, msg string) error {
	l := strings.ToLower(code + " " + msg)
	switch {
	case strings.Contains(l, "accesskey"), strings.Contains(l, "signaturedoesnotmatch"),
		strings.Contains(l, "forbidden"), strings.Contains(l, "unauthorized"):
		return integrations.Classify(integrations.CodeAuthFailed, "AccessKey 无效或无权限", nil)
	case strings.Contains(l, "template"):
		return integrations.Classify(integrations.CodeTemplateMissing, "模板不存在或未审核通过", nil)
	case strings.Contains(l, "sign"):
		return integrations.Classify(integrations.CodeSignMissing, "签名未报备或与模板不匹配", nil)
	case strings.Contains(l, "amount"), strings.Contains(l, "balance"), strings.Contains(l, "limit"):
		return integrations.Classify(integrations.CodeQuota, "账户余额不足或被限流", nil)
	default:
		return integrations.Classify(integrations.CodeUnknown,
			fmt.Sprintf("阿里云返回 %s：%s", code, msg), nil)
	}
}
