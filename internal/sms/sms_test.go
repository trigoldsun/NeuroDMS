package sms

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// 腾讯云：请求形状与 TC3 签名头。
//
// 签名算法错一个字节只会得到 SignatureFailure，从错误里看不出原因，
// 所以这里钉住"头域齐全 + 签名随 body 变化 + 成功判据是 SendStatusSet[0].Code"。
func TestTencentSendRequestShape(t *testing.T) {
	var gotBody map[string]any
	var gotAuth, gotAction, gotVersion string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &gotBody)
		gotAuth = r.Header.Get("Authorization")
		gotAction = r.Header.Get("X-TC-Action")
		gotVersion = r.Header.Get("X-TC-Version")
		_, _ = w.Write([]byte(`{"Response":{"SendStatusSet":[{"Code":"Ok","Message":"send success"}]}}`))
	}))
	defer srv.Close()

	p, err := newTencent(map[string]string{
		"secretId": "AKIDtest", "sdkAppId": "1400006666", "signName": "测试签名",
		"templateId": "1234", "region": "ap-guangzhou", "endpoint": srv.URL,
	}, map[string]string{"secretKey": "secret"})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Send(context.Background(), "+8613800138000", "654321"); err != nil {
		t.Fatalf("发送失败: %v", err)
	}
	if gotAction != "SendSms" || gotVersion != "2021-01-11" {
		t.Fatalf("Action/Version 不对: %s %s", gotAction, gotVersion)
	}
	if !strings.HasPrefix(gotAuth, "TC3-HMAC-SHA256 Credential=AKIDtest/") {
		t.Fatalf("Authorization 前缀不对: %s", gotAuth)
	}
	if !strings.Contains(gotAuth, "SignedHeaders=content-type;host") {
		t.Fatalf("SignedHeaders 不对: %s", gotAuth)
	}
	if gotBody["SmsSdkAppId"] != "1400006666" || gotBody["TemplateId"] != "1234" {
		t.Fatalf("body 缺字段: %v", gotBody)
	}
	params, _ := gotBody["TemplateParamSet"].([]any)
	if len(params) != 1 || params[0] != "654321" {
		t.Fatalf("模板参数不对: %v", gotBody["TemplateParamSet"])
	}
}

// 同一个 body/时间戳必须得到同一个签名；body 变一个字节就必须不同。
func TestTC3SignatureIsDeterministic(t *testing.T) {
	a := tc3Authorization("id", "key", "sms.tencentcloudapi.com", []byte(`{"a":1}`), 1700000000)
	b := tc3Authorization("id", "key", "sms.tencentcloudapi.com", []byte(`{"a":1}`), 1700000000)
	c := tc3Authorization("id", "key", "sms.tencentcloudapi.com", []byte(`{"a":2}`), 1700000000)
	if a != b {
		t.Fatal("相同输入应得到相同签名")
	}
	if a == c {
		t.Fatal("body 变化后签名必须变化")
	}
}

// 华为云：WSSE 摘要必须是 Base64(原始 SHA256)，不是十六进制。
func TestHuaweiWSSEDigest(t *testing.T) {
	got := wsseDigest("abc", "2026-01-01T00:00:00Z", "secret")
	sum := sha256.Sum256([]byte("abc" + "2026-01-01T00:00:00Z" + "secret"))
	want := base64.StdEncoding.EncodeToString(sum[:])
	if got != want {
		t.Fatalf("WSSE 摘要不对\n got=%s\nwant=%s", got, want)
	}
	if strings.ContainsAny(got, "0123456789abcdef") && len(got) == 64 {
		t.Fatal("看起来像十六进制，应为 Base64 原始哈希")
	}
}

// 华为云请求形状：from / smsContent[0] 的四个字段。
func TestHuaweiSendRequestShape(t *testing.T) {
	// 官方要求 Content-Type 固定 application/x-www-form-urlencoded，
	// 参数必须 urlencode 放在 body 里（不是 JSON）。
	var ct, raw string
	var wsse string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/sms/batchSendSms/v1" {
			t.Errorf("路径不对: %s", r.URL.Path)
		}
		ct = r.Header.Get("Content-Type")
		b, _ := io.ReadAll(r.Body)
		raw = string(b)
		wsse = r.Header.Get("X-WSSE")
		_, _ = w.Write([]byte(`{"code":"000000","description":"Success","result":[{"status":"000000","originTo":"+8613800138000"}]}`))
	}))
	defer srv.Close()

	p, err := newHuawei(map[string]string{
		"appKey": "ak", "sender": "csms123", "signature": "签名",
		"templateId": "tpl", "endpoint": srv.URL,
	}, map[string]string{"appSecret": "sk"})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Send(context.Background(), "+8613800138000", "112233"); err != nil {
		t.Fatalf("发送失败: %v", err)
	}
	if ct != "application/x-www-form-urlencoded" {
		t.Fatalf("Content-Type 必须为表单编码，实际 %q", ct)
	}
	if !strings.HasPrefix(wsse, `UsernameToken Username="ak"`) {
		t.Fatalf("X-WSSE 不对: %s", wsse)
	}
	form, perr := url.ParseQuery(raw)
	if perr != nil {
		t.Fatalf("body 不是合法表单: %q", raw)
	}
	if form.Get("from") != "csms123" || form.Get("templateId") != "tpl" || form.Get("signature") != "签名" {
		t.Fatalf("表单字段不对: %q", raw)
	}
	// "+" 必须被编码成 %2B，否则服务端会把号码当成 "+ 8613..."。
	if form.Get("to") != "+8613800138000" {
		t.Fatalf("to 应为 E.164: %q（原始 body: %s）", form.Get("to"), raw)
	}
	if !strings.Contains(raw, "to=%2B86") {
		t.Fatalf("号码里的 + 必须 urlencode: %s", raw)
	}
	// templateParas 是 JSON 数组的**字符串**
	if got := form.Get("templateParas"); got != `["112233"]` {
		t.Fatalf("templateParas 应为 JSON 字符串: %q", got)
	}
}

// 顶层 000000 但单号失败，必须当失败处理。
func TestHuaweiPerNumberFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"code":"000000","result":[{"status":"E200028","originTo":"+8613800138000"}]}`))
	}))
	defer srv.Close()
	p, err := newHuawei(map[string]string{
		"appKey": "ak", "sender": "csms123", "signature": "s",
		"templateId": "tpl", "endpoint": srv.URL,
	}, map[string]string{"appSecret": "sk"})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Send(context.Background(), "+8613800138000", "112233"); err == nil {
		t.Fatal("单号失败必须报错，不能因为顶层 000000 就放过")
	}
}

// 响应里没有 code（网关错误页之类）时不能报成功。
func TestHuaweiMissingCodeIsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"unexpected":"shape"}`))
	}))
	defer srv.Close()
	p, _ := newHuawei(map[string]string{
		"appKey": "ak", "sender": "csms123", "signature": "s",
		"templateId": "tpl", "endpoint": srv.URL,
	}, map[string]string{"appSecret": "sk"})
	if err := p.Send(context.Background(), "+8613800138000", "112233"); err == nil {
		t.Fatal("没有状态码时应报错，而不是假定已发送")
	}
}

// 天翼云：EOP 头三个字段齐全，body 里 templateParam 是"字符串化的 JSON"。
func TestCtyunSendRequestShape(t *testing.T) {
	var body map[string]any
	var eopDate, eopAuth, reqID string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &body)
		eopDate, eopAuth, reqID = r.Header.Get("eop-date"), r.Header.Get("eop-Authorization"), r.Header.Get("ctyun-eop-request-id")
		_, _ = w.Write([]byte(`{"code":"OK","message":"success"}`))
	}))
	defer srv.Close()

	p, err := newCtyun(map[string]string{
		"accessKey": "ak", "signName": "签名", "templateCode": "SMS_1",
		"templateParamKey": "code", "endpoint": srv.URL + "/sms/api/v1",
	}, map[string]string{"secretKey": "sk"})
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Send(context.Background(), "+8613800138000", "445566"); err != nil {
		t.Fatalf("发送失败: %v", err)
	}
	if eopDate == "" || reqID == "" || !strings.Contains(eopAuth, "Headers=ctyun-eop-request-id;eop-date") {
		t.Fatalf("EOP 头不完整: date=%q id=%q auth=%q", eopDate, reqID, eopAuth)
	}
	// eop-date 必须是 yyyymmddTHHMMSSZ
	if len(eopDate) != 16 || eopDate[8] != 'T' || eopDate[15] != 'Z' {
		t.Fatalf("eop-date 格式应为 yyyymmddTHHMMSSZ: %q", eopDate)
	}
	if body["phoneNumber"] != "13800138000" {
		t.Fatalf("phoneNumber 应为 11 位: %v", body["phoneNumber"])
	}
	tp, _ := body["templateParam"].(string)
	if !strings.Contains(tp, "445566") {
		t.Fatalf("templateParam 应含验证码: %q", tp)
	}
}

// EOP 签名的确定性：同样的四元组必须得到同一个签名，
// 任意一个输入变一位都必须不同（key/data 顺序写反了就用这条兜住）。
func TestEOPSignatureIsDeterministic(t *testing.T) {
	date := "20220525T160752Z"
	id := "27cfe4dc-e640-45f6-92ca-492ca73e8680"
	body := []byte(`{"action":"SendSms"}`)
	a := eopAuthorization("ak", "sk", date, id, "", body)
	if a != eopAuthorization("ak", "sk", date, id, "", body) {
		t.Fatal("同样输入应得到同样签名")
	}
	for _, other := range []string{
		eopAuthorization("ak2", "sk", date, id, "", body),
		eopAuthorization("ak", "sk2", date, id, "", body),
		eopAuthorization("ak", "sk", "20220525T160753Z", id, "", body),
		eopAuthorization("ak", "sk", date, id+"x", "", body),
		eopAuthorization("ak", "sk", date, id, "a=1", body),
		eopAuthorization("ak", "sk", date, id, "", []byte(`{"action":"SendSms" }`)),
	} {
		if other == a {
			t.Fatal("任一输入变化都必须改变签名")
		}
	}
	// 头格式：ak + 空格 + Headers= + 空格 + Signature=
	if !strings.HasPrefix(a, "ak Headers=ctyun-eop-request-id;eop-date Signature=") {
		t.Fatalf("Authorization 格式不对: %s", a)
	}
}

// 签名串里空 query 会连续出现两个换行，这是官方示例的形状，不能"顺手"去掉。
func TestEOPSigtureShape(t *testing.T) {
	got := eopSigture("id-1", "20220525T160752Z", "", []byte("body"))
	want := "ctyun-eop-request-id:id-1\neop-date:20220525T160752Z\n\n\n" + sha256Hex([]byte("body"))
	if got != want {
		t.Fatalf("sigture 拼接不对:\n got=%q\nwant=%q", got, want)
	}
}

// 天翼云返回空 code（网关错误页）时不能报成功。
func TestCtyunMissingCodeIsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"message":"bad gateway"}`))
	}))
	defer srv.Close()
	p, _ := newCtyun(map[string]string{
		"accessKey": "ak", "signName": "s", "templateCode": "SMS_1", "endpoint": srv.URL,
	}, map[string]string{"secretKey": "sk"})
	if err := p.Send(context.Background(), "+8613800138000", "445566"); err == nil {
		t.Fatal("没有状态码时应报错")
	}
}

// 未知 provider 必须报错，不能静默当成"没有"。
func TestBuildProviderUnknown(t *testing.T) {
	if _, err := buildProvider("nope", nil, nil); err == nil {
		t.Fatal("未知 provider 应报错")
	}
}

// 本地验证码必须是 6 位纯数字（含前导零）。
func TestRandomCodeShape(t *testing.T) {
	for i := 0; i < 200; i++ {
		c, err := randomCode(6)
		if err != nil {
			t.Fatal(err)
		}
		if len(c) != 6 {
			t.Fatalf("长度应为 6: %q", c)
		}
		for _, r := range c {
			if r < '0' || r > '9' {
				t.Fatalf("应为纯数字: %q", c)
			}
		}
	}
}
