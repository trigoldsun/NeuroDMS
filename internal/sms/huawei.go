package sms

// 华为云「消息&短信」（MSGSMS）。
//
// 官方资料：https://support.huaweicloud.cn/api-msgsms/sms_05_0001.html
//   - POST {endpoint}/sms/batchSendSms/v1
//   - 鉴权二选一：SDK-HMAC-SHA256 或 X-WSSE（这里用 WSSE，不依赖 SDK）
//   - **Content-Type 固定 application/x-www-form-urlencoded**（官方表 2），
//     参数必须以 urlencode 形式放在 body 里：
//     from=通道号&to=+8613...&templateId=...&templateParas=["123456"]&signature=...
//   - to 是**逗号分隔的字符串**（不是数组）；templateParas 是 **JSON 数组的字符串**
//   - 模板变量形如 ${1}，成功判据 code == "000000"（result[].status 同值）
//
// 注意一个易错点：华为云另有「群发不同内容」接口 /sms/batchSendDiffSms/v1，
// 那个才是 JSON + smsContent[]。把 JSON 发到 batchSendSms 会被判参数错误，
// 而报错只写 "参数不合法"，看不出是编码方式的问题（本次复核修正）。
//
// 该通道没有核验接口，验证码由本服务生成（Mode=Local）。

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"docvault/internal/integrations"
)

type huawei struct {
	cfg    huaweiConfig
	client *http.Client
	now    func() time.Time
}

type huaweiConfig struct {
	AppKey    string
	AppSecret string
	Sender    string // 通道号
	Signature string
	Template  string
	Endpoint  string
	TestPhone string
}

func newHuawei(cfg, sec map[string]string) (Provider, error) {
	c := huaweiConfig{
		AppKey:    strings.TrimSpace(cfg["appKey"]),
		AppSecret: sec["appSecret"],
		Sender:    strings.TrimSpace(cfg["sender"]),
		Signature: strings.TrimSpace(cfg["signature"]),
		Template:  strings.TrimSpace(cfg["templateId"]),
		Endpoint:  strings.TrimSpace(strings.TrimRight(cfg["endpoint"], "/")),
		TestPhone: strings.TrimSpace(cfg["testPhone"]),
	}
	if c.AppKey == "" || c.AppSecret == "" || c.Sender == "" || c.Signature == "" || c.Template == "" || c.Endpoint == "" {
		return nil, fmt.Errorf("%w: 华为云需要 APP_Key/APP_Secret、通道号、签名、模板与服务地址", integrations.ErrNotConfigured)
	}
	return &huawei{cfg: c, client: &http.Client{Timeout: 8 * time.Second}, now: time.Now}, nil
}

func (h *huawei) Code() string { return "huawei" }
func (h *huawei) Mode() Mode   { return Local }

func (h *huawei) Send(ctx context.Context, phone, code string) error {
	// templateParas 是「JSON 数组的字符串」，不是数组本身：
	// 写成 ["123456"] 这七个字符，而不是 JSON 的数组值。
	paras, _ := json.Marshal([]string{code})
	form := url.Values{}
	form.Set("from", h.cfg.Sender)
	form.Set("to", phone)
	form.Set("templateId", h.cfg.Template)
	form.Set("templateParas", string(paras))
	if h.cfg.Signature != "" {
		form.Set("signature", h.cfg.Signature)
	}
	// Encode() 会做 urlencode：号码里的 "+" 变成 %2B，
	// 不编码的话服务端会把 + 当成空格。
	body := []byte(form.Encode())

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		h.cfg.Endpoint+"/sms/batchSendSms/v1", bytes.NewReader(body))
	if err != nil {
		return integrations.Classify(integrations.CodeNetwork, "请求构造失败", err)
	}
	nonce, _ := randomHex(16)
	created := h.now().UTC().Format("2006-01-02T15:04:05Z")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", `WSSE realm="SDP",profile="UsernameToken",type="Appkey"`)
	req.Header.Set("X-WSSE", fmt.Sprintf(
		`UsernameToken Username="%s",PasswordDigest="%s",Nonce="%s",Created="%s"`,
		h.cfg.AppKey, wsseDigest(nonce, created, h.cfg.AppSecret), nonce, created))

	resp, err := h.client.Do(req)
	if err != nil {
		return integrations.Classify(integrations.CodeNetwork, "无法连接华为云接口", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return integrations.Classify(integrations.CodeNetwork, "读取响应失败", err)
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return integrations.Classify(integrations.CodeAuthFailed, "APP_Key/APP_Secret 无效", nil)
	}
	if resp.StatusCode >= 500 {
		return integrations.Classify(integrations.CodeQuota,
			fmt.Sprintf("华为云返回 HTTP %d", resp.StatusCode), nil)
	}
	var out struct {
		Code        string `json:"code"`
		Description string `json:"description"`
		Result      []struct {
			Status string `json:"status"`
			Origin string `json:"originTo"`
		} `json:"result"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return integrations.Classify(integrations.CodeUnknown, "华为云响应解析失败", err)
	}
	// 成功只认 000000。空 code 说明响应形状与预期不符——
	// 这种时候报"已发送"会让用户干等一条永远不来的短信。
	if out.Code != "000000" {
		if out.Code == "" {
			return integrations.Classify(integrations.CodeUnknown,
				"华为云未返回状态码，无法确认是否发出", nil)
		}
		return classifyHuawei(out.Code, out.Description)
	}
	// 批量接口逐号返回状态：顶层 000000 但单号失败是可能的。
	for _, r := range out.Result {
		if r.Status != "" && r.Status != "000000" {
			return classifyHuawei(r.Status, out.Description)
		}
	}
	return nil
}

func (h *huawei) Verify(context.Context, string, string) (bool, error) {
	return false, ErrNotSupported
}

// Test 真发一条（该通道没有免费核验接口）。
func (h *huawei) Test(ctx context.Context) error {
	if h.cfg.TestPhone == "" {
		return integrations.Classify(integrations.CodeNotConfigured, "请先填写「自检号码」再测试", nil)
	}
	return h.Send(ctx, h.cfg.TestPhone, "000000")
}

// wsseDigest = Base64(SHA256(nonce + created + appSecret))。
//
// 注意是**原始哈希字节**再 base64，不是先转十六进制——写成 hex 会一直 401，
// 而报错只说鉴权失败。
func wsseDigest(nonce, created, secret string) string {
	sum := sha256.Sum256([]byte(nonce + created + secret))
	return base64.StdEncoding.EncodeToString(sum[:])
}

func classifyHuawei(code, msg string) error {
	l := strings.ToLower(code + " " + msg)
	switch {
	case strings.Contains(l, "auth"), strings.Contains(l, "e000001"), strings.Contains(l, "token"):
		return integrations.Classify(integrations.CodeAuthFailed, "鉴权失败，请检查 APP_Key/APP_Secret", nil)
	case strings.Contains(l, "template"):
		return integrations.Classify(integrations.CodeTemplateMissing, "模板不存在或变量个数不符", nil)
	case strings.Contains(l, "sign"):
		return integrations.Classify(integrations.CodeSignMissing, "签名未报备或与模板类型不一致", nil)
	case strings.Contains(l, "quota"), strings.Contains(l, "limit"), strings.Contains(l, "balance"):
		return integrations.Classify(integrations.CodeQuota, "套餐余量不足或被限流", nil)
	default:
		return integrations.Classify(integrations.CodeUnknown, fmt.Sprintf("华为云返回 %s：%s", code, msg), nil)
	}
}
