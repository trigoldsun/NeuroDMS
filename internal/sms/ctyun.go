package sms

// 天翼云短信（云通信 · SendSms）。
//
// 官方资料：
//   - 服务地址 https://sms-global.ctapi.ctyun.cn/sms/api/v1（可用 v2 / ctcloud/maas/v1）
//   - 请求体 JSON：action=SendSms、signName、phoneNumber（11 位）、templateCode、templateParam
//   - 鉴权 EOP 签名：eop-date + eop-Authorization（AK + Headers + Signature）+ ctyun-eop-request-id
//
// EOP 的签名串**不是** AWS SigV4 的形状（本次复核改正）：
//
//	sigture = 排序后的头（每条 "name:value\n"）+ "\n" + query + "\n" + hex(sha256(body))
//	ktime   = HMAC(key=sk,   data=eop-date)
//	kAk     = HMAC(key=ktime, data=ak)
//	kdate   = HMAC(key=kAk,  data=eop-date 的年月日)
//	sign    = base64(HMAC(key=kdate, data=sigture))
//
// 四步里任何一步的 key/data 反了都只报"鉴权失败"，从错误里看不出是哪一步。

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
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

type ctyun struct {
	cfg    ctyunConfig
	client *http.Client
	now    func() time.Time
}

type ctyunConfig struct {
	AccessKey    string
	SecretKey    string
	SignName     string
	TemplateCode string
	ParamKey     string
	Endpoint     string
	TestPhone    string
}

func newCtyun(cfg, sec map[string]string) (Provider, error) {
	c := ctyunConfig{
		AccessKey:    strings.TrimSpace(cfg["accessKey"]),
		SecretKey:    sec["secretKey"],
		SignName:     strings.TrimSpace(cfg["signName"]),
		TemplateCode: strings.TrimSpace(cfg["templateCode"]),
		ParamKey:     strings.TrimSpace(cfg["templateParamKey"]),
		Endpoint:     strings.TrimSpace(cfg["endpoint"]),
		TestPhone:    strings.TrimSpace(cfg["testPhone"]),
	}
	if c.Endpoint == "" {
		c.Endpoint = "https://sms-global.ctapi.ctyun.cn/sms/api/v1"
	}
	if c.ParamKey == "" {
		c.ParamKey = "code"
	}
	if c.AccessKey == "" || c.SecretKey == "" || c.SignName == "" || c.TemplateCode == "" {
		return nil, fmt.Errorf("%w: 天翼云需要 AccessKey/SecretKey、签名与模板", integrations.ErrNotConfigured)
	}
	return &ctyun{cfg: c, client: &http.Client{Timeout: 8 * time.Second}, now: time.Now}, nil
}

func (c *ctyun) Code() string { return "ctyun" }
func (c *ctyun) Mode() Mode   { return Local }

func (c *ctyun) Send(ctx context.Context, phone, code string) error {
	national, err := nationalNumber(phone)
	if err != nil {
		return integrations.Classify(integrations.CodeAuthFailed, "号码格式不正确", err)
	}
	param, _ := json.Marshal(map[string]string{c.cfg.ParamKey: code})
	body, _ := json.Marshal(map[string]any{
		"action":        "SendSms",
		"signName":      c.cfg.SignName,
		"phoneNumber":   national,
		"templateCode":  c.cfg.TemplateCode,
		"templateParam": string(param),
	})

	u, perr := url.Parse(c.cfg.Endpoint)
	if perr != nil {
		return integrations.Classify(integrations.CodeNetwork, "服务地址不合法", perr)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.Endpoint, bytes.NewReader(body))
	if err != nil {
		return integrations.Classify(integrations.CodeNetwork, "请求构造失败", err)
	}
	date := c.now().UTC().Format("20060102T150405Z")
	reqID, _ := randomUUID()
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("eop-date", date)
	req.Header.Set("ctyun-eop-request-id", reqID)
	// 签名里的 query 必须与真实 URL 的 query 一致；本接口不带 query，传空串。
	req.Header.Set("eop-Authorization",
		eopAuthorization(c.cfg.AccessKey, c.cfg.SecretKey, date, reqID, u.RawQuery, body))

	resp, err := c.client.Do(req)
	if err != nil {
		return integrations.Classify(integrations.CodeNetwork, "无法连接天翼云接口", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return integrations.Classify(integrations.CodeNetwork, "读取响应失败", err)
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		return integrations.Classify(integrations.CodeAuthFailed, "AK/SK 无效或 EOP 签名不匹配", nil)
	}
	if resp.StatusCode >= 500 {
		return integrations.Classify(integrations.CodeQuota,
			fmt.Sprintf("天翼云返回 HTTP %d", resp.StatusCode), nil)
	}
	var out struct {
		Code    any    `json:"code"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return integrations.Classify(integrations.CodeUnknown, "天翼云响应解析失败", err)
	}
	codeText := fmt.Sprintf("%v", out.Code)
	switch strings.ToUpper(codeText) {
	case "OK", "0", "000000":
		return nil
	case "", "<NIL>":
		// 没有 code 说明响应形状不对（可能是网关错误页）。报"已发送"
		// 会让用户干等一条不会来的短信，这里必须保守。
		return integrations.Classify(integrations.CodeUnknown,
			"天翼云未返回状态码，无法确认是否发出", nil)
	}
	return classifyCtyun(codeText, out.Message)
}

func (c *ctyun) Verify(context.Context, string, string) (bool, error) {
	return false, ErrNotSupported
}

func (c *ctyun) Test(ctx context.Context) error {
	if c.cfg.TestPhone == "" {
		return integrations.Classify(integrations.CodeNotConfigured, "请先填写「自检号码」再测试", nil)
	}
	return c.Send(ctx, c.cfg.TestPhone, "000000")
}

// eopAuthorization 计算 EOP 签名头（算法见文件头注释）。
//
// 三个容易写错的地方：
//  1. 头块里每条以 "\n" 结尾，拼完再加一个 "\n" 才接 query —— 于是
//     空 query 时会出现连续两个 "\n"（官方示例里就是三个 \n 连排，别删）；
//  2. 派生密钥的顺序是 sk → (key=ktime, data=ak) → (key=kAk, data=年月日)；
//  3. 最后一步是 base64 的**原始** HMAC 结果，不是十六进制。
func eopAuthorization(ak, sk, date, requestID, query string, body []byte) string {
	const signedHeaders = "ctyun-eop-request-id;eop-date"
	sigture := eopSigture(requestID, date, query, body)

	ktime := hmacSHA256([]byte(sk), date)
	kAk := hmacSHA256(ktime, ak)
	day := date
	if len(day) >= 8 {
		day = day[:8] // yyyymmdd
	}
	kdate := hmacSHA256(kAk, day)

	sig := base64.StdEncoding.EncodeToString(hmacSHA256(kdate, sigture))
	return ak + " Headers=" + signedHeaders + " Signature=" + sig
}

// eopSigture 拼"代签字符串"。
//
// 单独抽出来是为了能被测试钉住：这里少一个 "\n"、或者把 query 与 body
// 的顺序调换，签名都会错，而服务端只会回"鉴权失败"。
func eopSigture(requestID, date, query string, body []byte) string {
	// 头按名字母序：ctyun-eop-request-id < eop-date
	headerBlock := "ctyun-eop-request-id:" + requestID + "\n" + "eop-date:" + date + "\n"
	return headerBlock + "\n" + query + "\n" + sha256Hex(body)
}

func classifyCtyun(code, msg string) error {
	l := strings.ToLower(code + " " + msg)
	switch {
	case strings.Contains(l, "auth"), strings.Contains(l, "signature"), strings.Contains(l, "403"):
		return integrations.Classify(integrations.CodeAuthFailed, "AK/SK 无效或签名不匹配", nil)
	case strings.Contains(l, "template"):
		return integrations.Classify(integrations.CodeTemplateMissing, "模板不存在或未审核", nil)
	case strings.Contains(l, "sign"):
		return integrations.Classify(integrations.CodeSignMissing, "签名未报备或与模板不匹配", nil)
	case strings.Contains(l, "limit"), strings.Contains(l, "balance"), strings.Contains(l, "quota"):
		return integrations.Classify(integrations.CodeQuota, "余量不足或被限流", nil)
	default:
		return integrations.Classify(integrations.CodeUnknown, fmt.Sprintf("天翼云返回 %s：%s", code, msg), nil)
	}
}

// randomHex 生成 n 字节的十六进制随机串（WSSE 的 Nonce 等）。
func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// randomUUID 生成 32 位十六进制请求号（EOP 要求请求流水号）。
func randomUUID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
