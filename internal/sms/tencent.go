package sms

// 腾讯云短信（SendSms，Version 2021-01-11）。
//
// 官方资料：https://cloud.tencent.com/document/product/382/55981
//   - 域名 sms.tencentcloudapi.com，POST + JSON
//   - 必填 PhoneNumberSet / SmsSdkAppId / SignName / TemplateId / TemplateParamSet
//   - 签名 TC3-HMAC-SHA256（Authorization 头）
//   - 模板变量形如 {1}，成功判据 SendStatusSet[].Code == "Ok"
//
// 该通道**没有核验接口**，验证码由本服务生成（Mode=Local）。

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"docvault/internal/integrations"
)

type tencent struct {
	cfg    tencentConfig
	client *http.Client
	now    func() time.Time
}

type tencentConfig struct {
	SecretID   string
	SecretKey  string
	SdkAppID   string
	SignName   string
	TemplateID string
	Region     string
	Endpoint   string
	TestPhone  string
}

func newTencent(cfg, sec map[string]string) (Provider, error) {
	c := tencentConfig{
		SecretID:   strings.TrimSpace(cfg["secretId"]),
		SecretKey:  sec["secretKey"],
		SdkAppID:   strings.TrimSpace(cfg["sdkAppId"]),
		SignName:   strings.TrimSpace(cfg["signName"]),
		TemplateID: strings.TrimSpace(cfg["templateId"]),
		Region:     strings.TrimSpace(cfg["region"]),
		Endpoint:   strings.TrimSpace(cfg["endpoint"]),
		TestPhone:  strings.TrimSpace(cfg["testPhone"]),
	}
	if c.Endpoint == "" {
		c.Endpoint = "https://sms.tencentcloudapi.com"
	}
	if c.Region == "" {
		c.Region = "ap-guangzhou"
	}
	if c.SecretID == "" || c.SecretKey == "" || c.SdkAppID == "" || c.SignName == "" || c.TemplateID == "" {
		return nil, fmt.Errorf("%w: 腾讯云需要 SecretId/SecretKey、SdkAppId、签名与模板", integrations.ErrNotConfigured)
	}
	return &tencent{cfg: c, client: &http.Client{Timeout: 8 * time.Second}, now: time.Now}, nil
}

func (t *tencent) Code() string { return "tencent" }
func (t *tencent) Mode() Mode   { return Local }

func (t *tencent) Send(ctx context.Context, phone, code string) error {
	if !strings.HasPrefix(phone, "+") {
		return integrations.Classify(integrations.CodeAuthFailed, "号码需为 E.164（+86…）", nil)
	}
	payload := map[string]any{
		"PhoneNumberSet":   []string{phone},
		"SmsSdkAppId":      t.cfg.SdkAppID,
		"SignName":         t.cfg.SignName,
		"TemplateId":       t.cfg.TemplateID,
		"TemplateParamSet": []string{code},
	}
	body, _ := json.Marshal(payload)
	resp, err := t.do(ctx, body, t.now().Unix())
	if err != nil {
		return err
	}
	if resp.Response.Error != nil && resp.Response.Error.Code != "" {
		return classifyTencent(resp.Response.Error.Code, resp.Response.Error.Message)
	}
	if len(resp.Response.SendStatusSet) == 0 {
		return integrations.Classify(integrations.CodeUnknown, "腾讯云未返回发送结果", nil)
	}
	st := resp.Response.SendStatusSet[0]
	if st.Code != "Ok" {
		return classifyTencent(st.Code, st.Message)
	}
	return nil
}

func (t *tencent) Verify(context.Context, string, string) (bool, error) {
	return false, ErrNotSupported
}

// Test 真发一条：腾讯云没有免费核验接口，只能以"发出去了"为判据。
func (t *tencent) Test(ctx context.Context) error {
	if t.cfg.TestPhone == "" {
		return integrations.Classify(integrations.CodeNotConfigured, "请先填写「自检号码」再测试", nil)
	}
	return t.Send(ctx, t.cfg.TestPhone, "000000")
}

type tencentResp struct {
	Response struct {
		Error *struct {
			Code    string `json:"Code"`
			Message string `json:"Message"`
		} `json:"Error"`
		SendStatusSet []struct {
			Code        string `json:"Code"`
			Message     string `json:"Message"`
			PhoneNumber string `json:"PhoneNumber"`
		} `json:"SendStatusSet"`
		RequestId string `json:"RequestId"`
	} `json:"Response"`
}

func (t *tencent) do(ctx context.Context, body []byte, ts int64) (tencentResp, error) {
	u, err := url.Parse(t.cfg.Endpoint)
	if err != nil {
		return tencentResp{}, integrations.Classify(integrations.CodeNetwork, "服务地址不合法", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, t.cfg.Endpoint, bytes.NewReader(body))
	if err != nil {
		return tencentResp{}, integrations.Classify(integrations.CodeNetwork, "请求构造失败", err)
	}
	req.Header.Set("Content-Type", "application/json; charset=utf-8")
	req.Header.Set("X-TC-Action", "SendSms")
	req.Header.Set("X-TC-Version", "2021-01-11")
	req.Header.Set("X-TC-Timestamp", fmt.Sprintf("%d", ts))
	req.Header.Set("X-TC-Region", t.cfg.Region)
	req.Header.Set("Authorization", tc3Authorization(t.cfg.SecretID, t.cfg.SecretKey, u.Host, body, ts))

	resp, err := t.client.Do(req)
	if err != nil {
		return tencentResp{}, integrations.Classify(integrations.CodeNetwork, "无法连接腾讯云接口", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return tencentResp{}, integrations.Classify(integrations.CodeNetwork, "读取响应失败", err)
	}
	if resp.StatusCode >= 500 {
		return tencentResp{}, integrations.Classify(integrations.CodeQuota,
			fmt.Sprintf("腾讯云返回 HTTP %d", resp.StatusCode), nil)
	}
	var out tencentResp
	if err := json.Unmarshal(raw, &out); err != nil {
		return tencentResp{}, integrations.Classify(integrations.CodeUnknown, "腾讯云响应解析失败", err)
	}
	return out, nil
}

// tc3Authorization 计算 TC3-HMAC-SHA256 的 Authorization 头。
//
// 拆成独立函数是为了可测：签名错一个字节只会得到 SignatureFailure，
// 从错误信息里看不出是日期、头域顺序还是 body 哈希的问题。
func tc3Authorization(secretID, secretKey, host string, body []byte, ts int64) string {
	const (
		service = "sms"
		action  = "tc3_request"
		ct      = "application/json; charset=utf-8"
	)
	date := time.Unix(ts, 0).UTC().Format("2006-01-02")

	payloadHash := sha256Hex(body)
	canonicalHeaders := "content-type:" + ct + "\nhost:" + host + "\n"
	signedHeaders := "content-type;host"
	canonicalRequest := "POST\n/\n\n" + canonicalHeaders + "\n" + signedHeaders + "\n" + payloadHash

	scope := date + "/" + service + "/" + action
	stringToSign := "TC3-HMAC-SHA256\n" + fmt.Sprintf("%d", ts) + "\n" + scope + "\n" + sha256Hex([]byte(canonicalRequest))

	kDate := hmacSHA256([]byte("TC3"+secretKey), date)
	kService := hmacSHA256(kDate, service)
	kSigning := hmacSHA256(kService, action)
	sig := hex.EncodeToString(hmacSHA256(kSigning, stringToSign))

	return "TC3-HMAC-SHA256 Credential=" + secretID + "/" + scope +
		", SignedHeaders=" + signedHeaders + ", Signature=" + sig
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func hmacSHA256(key []byte, msg string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(msg))
	return m.Sum(nil)
}

func classifyTencent(code, msg string) error {
	l := strings.ToLower(code + " " + msg)
	switch {
	case strings.Contains(l, "authfailure"), strings.Contains(l, "secretid"),
		strings.Contains(l, "unauthorized"), strings.Contains(l, "signaturefailure"):
		return integrations.Classify(integrations.CodeAuthFailed, "SecretId/SecretKey 无效或签名不匹配", nil)
	case strings.Contains(l, "template"):
		return integrations.Classify(integrations.CodeTemplateMissing, "模板不存在、变量个数不符或未审核", nil)
	case strings.Contains(l, "sign"):
		return integrations.Classify(integrations.CodeSignMissing, "签名未审核通过或与模板不匹配", nil)
	case strings.Contains(l, "insufficientbalance"), strings.Contains(l, "limitexceeded"),
		strings.Contains(l, "resourceunavailable"):
		return integrations.Classify(integrations.CodeQuota, "套餐余额不足或被限流", nil)
	default:
		return integrations.Classify(integrations.CodeUnknown, fmt.Sprintf("腾讯云返回 %s：%s", code, msg), nil)
	}
}
