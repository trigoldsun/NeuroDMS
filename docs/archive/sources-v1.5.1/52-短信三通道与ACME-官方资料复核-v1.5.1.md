# 短信三通道与 ACME 官方资料复核 v1.0

| 项 | 内容 |
|---|---|
| 版本 | V1.5.1（与产品版本一致） |
| 沿革 | 首版 v1.0.0；自 V1.5.1 起随产品发版 |
| 日期 | 2026-11-14 |
| 性质 | 官方技术资料**逐项复核**报告（不是设计稿） |
| 目的 | 在拿到客户凭据前，先把"照着官方文档能不能跑通"这件事验证干净 |
| 结论 | 腾讯云：**原实现正确**；华为云、天翼云：**各有一处实错，已修正**；ACME：**流程正确，补了限流保护** |

---

## 1. 方法

不是"再看一遍代码"，而是**逐字段对照厂商文档**：

1. 抓官方接口页的**参数表**（名称、类型、是否必填）与**示例**（请求/响应原文）；
2. 抓官方**鉴权/签名**专页的算法步骤（含示例中间值）；
3. 用自己的实现生成同样的输入，逐字节比对签名串形状；
4. 与文档不一致的地方 → 改代码 → 加回归测试（钉住"形状"而不只是"不报错"）。

复核依据（均为厂商官方站点，2026-11-14 访问）：

| 厂商 | 页面 |
|---|---|
| 腾讯云 | `cloud.tencent.com/document/product/382/55981`（SendSms）、`/document/api/213/30654`（签名方法 v3） |
| 华为云 | `support.huaweicloud.cn/api-msgsms/sms_05_0001.html`（发送短信）、国际站同页 + Batch 接口页 |
| 天翼云 | `ctyun.cn/document/10007767/10022662`（EOP 认证鉴权）、云通信短信 API 操作手册（PDF）、`eop.ctyun.cn`（云通信-短信 sid=74） |
| ACME | `letsencrypt.org/docs/challenge-types/`、`letsencrypt.org/docs/rate-limits/` |

---

## 2. 腾讯云：原实现正确

| 检查点 | 官方要求 | 原实现 | 结论 |
|---|---|---|---|
| 域名/方法 | `sms.tencentcloudapi.com`，POST JSON，路径 `/` | 一致 | ✅ |
| 版本 | `2021-01-11` | `X-TC-Version: 2021-01-11` | ✅ |
| 必填体字段 | `PhoneNumberSet`、`SmsSdkAppId`、`TemplateId`（`SignName` 国内必填） | 五个都有 | ✅ |
| 号码格式 | E.164 `+86…`，单次 ≤200 个 | 强制 `+` 前缀，单个 | ✅ |
| 模板变量 | `TemplateParamSet` 个数必须与模板变量数一致；验证码类只能 0–6 位纯数字 | 传 1 个 6 位码 | ✅ |
| CanonicalRequest | `Method \n URI \n Query \n CanonicalHeaders \n SignedHeaders \n Hash(payload)`，头每条 `k:v\\n` 且小写、字典序 | 完全一致的拼法 | ✅ |
| 签哪些头 | **至少** `host` + `content-type`；`x-tc-action` 为推荐项 | 签 `content-type;host` | ✅（合规，未加推荐项） |
| 日期 | 必须是 **UTC** 日期（东八区凌晨易错） | `time.Unix(ts,0).UTC().Format("2006-01-02")` | ✅ |
| 密钥派生 | `kDate=HMAC("TC3"+SK, date)` → `kService=HMAC(kDate,service)` → `kSigning=HMAC(kService,"tc3_request")` | 一致（key/data 顺序正确） | ✅ |
| Authorization | `TC3-HMAC-SHA256 Credential=ID/scope, SignedHeaders=…, Signature=…`（逗号+空格） | 一致 | ✅ |
| 成功判据 | `SendStatusSet[].Code == "Ok"`（HTTP 200 也可能是单条失败） | 逐条检查 | ✅ |

**唯一改进**：模板变量个数必须与模板一致这条，原来只写在文档里，现在写进了通道说明（配错时最容易犯的错）。

---

## 3. 华为云：**编码方式错了，已修正**

| 检查点 | 官方要求 | 原实现 | 结论 |
|---|---|---|---|
| Content-Type | **固定 `application/x-www-form-urlencoded`**（官方"表 2 请求 Headers"） | `application/json;charset=UTF-8` | ❌ **错** |
| 请求体 | 表单参数：`from`、`to`、`templateId`、`templateParas`、`signature`，**参数需 urlencode** | JSON `{"from":…,"smsContent":[…]}` | ❌ **错** |
| `to` | **逗号分隔的字符串**（不是数组），≤500 个，每个 ≤21 字符 | 数组 | ❌ 错 |
| `templateParas` | **JSON 数组格式的字符串**，如 `'["3","…"]'` | 数组值 | ❌ 错 |
| `from` | 通道号：国内取签名关联的 `csms…`，国际取应用分配 | 一致 | ✅ |
| 鉴权头 | `Authorization: WSSE realm="SDP",profile="UsernameToken",type="Appkey"` | 一致 | ✅ |
| X-WSSE | `UsernameToken Username="app_key",PasswordDigest="…",Nonce="…",Created="…"` | 一致 | ✅ |
| PasswordDigest | `Base64(SHA256(Nonce + Created + Secret))`，**原始哈希再 base64**（不是 hex） | `base64(sha256(...))` | ✅ |
| Created | UTC，`2006-01-02T15:04:05Z` | 一致 | ✅ |
| 成功判据 | `code == "000000"`；`result[].status` 逐号返回 | 只看顶层 code，且**空 code 当成功** | ⚠️ 已收紧 |

**为什么会错**：华为云有两个「批量」接口——`/sms/batchSendSms/v1`（同内容，表单）与
`/sms/batchSendDiffSms/v1`（不同内容，JSON + `smsContent[]`）。我当时按后者写了前者。
真实环境下的表现会是：HTTP 200 + `code` 非 000000 / 参数不合法，而错误信息里看不出是编码问题。

**修正**（`internal/sms/huawei.go`）：

- 改为 `url.Values` 表单编码，`Content-Type` 固定表单；
- `to` 传字符串（E.164），由 `Encode()` 把 `+` 转成 `%2B`——不转的话服务端会把 `+` 当空格；
- `templateParas` 传 `["123456"]` 这个**字符串**；
- 成功只认 `000000`；空 code 报"无法确认是否发出"（宁可让用户重试，也不谎报成功）；
- 额外检查 `result[].status`：顶层 000000 但单号失败是可能的。

---

## 4. 天翼云：**EOP 签名算法写错了，已修正**

| 检查点 | 官方要求 | 原实现 | 结论 |
|---|---|---|---|
| 服务地址 | `https://sms-global.ctapi.ctyun.cn/sms/api/v1`（亦有 v2 / `ctcloud/maas/v1`） | 一致（可配） | ✅ |
| 公共头 | `Content-Type`、`eop-date`（`yyyymmddTHHMMSSZ`）、`eop-Authorization`、`ctyun-eop-request-id` | 四个都有 | ✅ |
| 请求体 | JSON：`action=SendSms`、`signName`、`phoneNumber`（11 位）、`templateCode`、`templateParam`（JSON **字符串**） | 一致 | ✅ |
| 成功判据 | `code == "OK"` | 把「空 code」也当成功 | ⚠️ 已收紧 |
| **代签字符串** | `排序头(每条 "name:value\\n") + "\\n" + query + "\\n" + hex(sha256(body))` | 写成了 AWS SigV4 形状（`POST\\n path\\n\\n headers…`） | ❌ **错** |
| **密钥派生** | `ktime=HMAC(sk, eop-date)` → `kAk=HMAC(ktime, ak)` → `kdate=HMAC(kAk, yyyymmdd)` | 直接 `HMAC(sk, "EOP\\ndate\\nhash")` | ❌ **错** |
| **签名** | `base64(HMAC(kdate, sigture))` | `base64(HMAC(sk, stringToSign))` | ❌ **错** |
| 头格式 | `ak Headers=ctyun-eop-request-id;eop-date Signature=…`（三段空格分隔） | 一致 | ✅ |

**错在哪**：我把 EOP 当成"和 AWS SigV4 同源"来写（连注释都这么写了）。两者只是**都叫签名**，
拼接规则、派生链、参与签名的主体完全不同。官方示例里那段连续三个 `\n`
（头块自身结尾 + query 前置 + query 为空）就是最容易被"顺手清理"掉的细节。

**修正**（`internal/sms/ctyun.go`）：

```go
sigture = "ctyun-eop-request-id:"+id+"\n" + "eop-date:"+date+"\n" + "\n" + query + "\n" + hex(sha256(body))
ktime   = HMAC(key=sk,    data=eop-date)
kAk     = HMAC(key=ktime, data=ak)
kdate   = HMAC(key=kAk,   data=yyyymmdd)
sign    = base64(HMAC(key=kdate, data=sigture))
```

新增两条测试钉住形状：`TestEOPSigtureShape`（拼串逐字节）、
`TestEOPSignatureIsDeterministic`（六个输入各变一位都必须改变签名——key/data 反了会被这条抓住）。

---

## 5. ACME：流程正确，补了限流保护

| 检查点 | 官方要求 | 实现 | 结论 |
|---|---|---|---|
| HTTP-01 路径 | `http://<域名>/.well-known/acme-challenge/<token>`，内容 = token + 账号密钥指纹 | 挑战服务器同路径、`text/plain` 返回 keyAuth | ✅ |
| HTTP-01 端口 | **只能 80**，不支持通配符；跟最多 10 次跳转 | 监听 `:80`（失败会显示在状态里） | ✅ |
| DNS-01 | TXT 记录名 `_acme-challenge.<域名>`；值 = base64url(SHA256(keyAuth)) | `BeginDNS01` 同名，值由 `acme.Client.DNS01ChallengeRecord` 生成 | ✅ |
| DNS-01 是否需自动化 | 官方建议"DNS 有 API 才适合自动" | 我们做**两阶段手动**：给记录 → 客户添加 → 完成。不索取客户的 DNS API 凭证 | ✅（有意取舍） |
| 账户配额 | **同一 IP 每 3 小时最多 10 个新账户** | 账户私钥持久化在 `acme_account`，只注册一次 | ✅ |
| 订单配额 | 每账号每 3 小时 300 个新订单 | 一次签发一单，续期 30 天前触发 | ✅ |
| **授权失败配额** | **同一 identifier 每账号每小时 5 次失败**，超了该域名 1 小时内连订单都下不了 | 原来没有保护，界面可连点 | ⚠️ **已补冷却** |
| 同一证书集配额 | 同 identifier 集合每 7 天 5 张；**同集合续期不计入** | 每域名单张证书，续期 identifier 不变 | ✅ |
| 测试环境 | 官方明确要求"开发/联调请用 staging" | 支持 `DOCVAULT_ACME_DIRECTORY`，界面标出"测试目录" | ✅ |

**新增保护**：`acmecert.Cooldown` + 接口层 60 秒冷却（`429 ACME_COOLDOWN`），
错误文案直接说明"每小时失败 5 次会被 CA 临时拒绝一小时，建议先用测试目录调通"。
这条不是锦上添花——没有它，实施在现场连点五次就会把该域名锁一小时，而界面上只会显示"校验未通过"。

**已知边界**（官方口径，写进手册）：

- HTTP-01 **不能**签通配符；通配符必须走 DNS-01（本系统走手工上传证书）；
- DNS-01 手动模式**不自动续期**（TXT 要人加），到期前需重新操作；
- 逆向代理/隧道部署时 80/443 不在本机 → 必须 `off`，证书由边缘托管。

---

## 6. 修正清单

| 文件 | 改动 | 测试 |
|---|---|---|
| `internal/sms/huawei.go` | 表单编码 + `to` 字符串 + `templateParas` JSON 字符串 + 逐号状态 + 空 code 报错 | `TestHuaweiSendRequestShape`（含 `%2B` 断言）、`TestHuaweiPerNumberFailure`、`TestHuaweiMissingCodeIsError` |
| `internal/sms/ctyun.go` | EOP 算法四步重写 + `query` 参与签名 + 空 code 报错 | `TestEOPSigtureShape`、`TestEOPSignatureIsDeterministic`、`TestCtyunMissingCodeIsError`、`TestCtyunSendRequestShape` |
| `internal/acmecert/acmecert.go` | `Cooldown` + 校验失败文案带配额后果 | 模式与状态单测（已有） |
| `internal/httpapi/handlers_domain.go` | 签发/完成入口 60 秒冷却 → 429 | 线上实测（见 §7） |
| `internal/sms/sms.go` | 三家通道说明补"变量个数必须 1""签名填内容""通道号类型" | — |

---

## 7. 验证

```
go test ./internal/sms/ -count=1     ok   （含新增 6 条）
go test ./internal/acmecert/ -count=1 ok
go test ./... -count=1               exit=0（空库，含迁移）
gofmt -l ./cmd ./internal            无输出
go vet ./...                         无输出
```

线上（SaaS）回归：`/v1/admin/domains` 返回 `acme.mode=off` 与"证书需由边缘托管"的说明；
`POST .../acme` 返回 `409 ACME_DISABLED`（不是 502，也不会被 Cloudflare 吞掉）。

---

## 8. 状态判定：开发基本完成，只差接入

| 通道 | 代码 | 单测 | 官方资料核对 | 真实发送 | 状态 |
|---|---|---|---|---|---|
| 阿里云（managed） | ✅ | ✅ | ✅ | ✅ 已实测（18616808870 收到并核验通过） | **已上线** |
| 腾讯云 | ✅ | ✅ 请求形状/TC3/响应判据 | ✅ 本次逐项核对通过 | ⏳ 缺 SecretId/SecretKey + SdkAppId | **开发完成，待接入** |
| 华为云 | ✅ 已修正 | ✅ 表单编码/逐号状态 | ✅ 本次核对并修正 | ⏳ 缺 APP_Key/APP_Secret + 通道号 | **开发完成，待接入** |
| 天翼云 | ✅ 已修正 | ✅ EOP 四步/拼串形状 | ✅ 本次核对并修正 | ⏳ 缺 AK/SK | **开发完成，待接入** |
| ACME | ✅ | ✅ 模式/CSR/状态/冷却 | ✅ 挑战与限流核对通过 | ⏳ 需一个"域名直连本机、80 可达"的环境 | **开发完成，待接入** |

### 客户/我方各需要提供什么

| 通道 | 需要的凭据 | 谁来准备 |
|---|---|---|
| 腾讯云 | SecretId、SecretKey、SmsSdkAppId、已审核签名（内容）、模板 ID | 客户（自带账号） |
| 华为云 | APP_Key、APP_Secret、通道号（`csms…`）、签名、模板 ID、服务地址 | 客户 |
| 天翼云 | AccessKey、SecretKey、签名、模板 CODE、变量名 | 客户 |
| ACME | 一个 A 记录指向本机的域名 + 开放 80（HTTP-01）或客户手工加 TXT（DNS-01） | 客户网络/域名管理员 |

### 首次接通必做的 5 步（缺一步都别宣布"接通了"）

1. 填非密字段 → 保存 → 填密钥 → 保存（密钥只写不读，页面上看不到回显是正常的）；
2. 点「**测试连接**」：腾讯/华为/天翼会**真发一条**到"自检号码"，确认手机能收到；
3. 到「系统设置 → 登录方式」打开短信登录；
4. 用**真实账号**走一遍"手机号 + 验证码"登录，确认核验通过（本地核验的三家要确认码存在本系统）；
5. 检查审计里有 `admin.integration.save` 与 `admin.integration.test`（本轮修过的坑：这类事件曾因 `object_id` 类型不匹配而静默丢失）。

> 一个已知的"看起来像 bug 但不是"的现象：**切换通道后，切换前发出的验证码无法核验**。
> 本地核验把码存在本系统里，但签发时用的是旧通道的模板；让用户重发一次即可。

---

## 9. 一句话总结

这一轮把"照文档写"变成了"照文档**验**"：腾讯云一次通过，华为云的编码方式与天翼云的签名算法各错一处，
都属于"不真发就永远发现不了、真发也只报一句参数/鉴权失败"的类型。现在三条通道的开发侧已闭环，
剩下的只是把客户凭据填进去点一次「测试连接」。
