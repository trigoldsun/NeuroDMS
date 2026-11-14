# 外部身份认证（SAML 2.0 / OIDC / OAuth 2.0）设计与迭代方案

| 项目 | 值 |
|---|---|
| 版本 | v1.1.0（设计定案，未实施） |
| 日期 | 2026-11-14 |
| 状态 | **已定案**：OIDC 优先；接入顺序 微信 → 苹果 → 谷歌 → 钉钉 → 飞书 → 企业微信；SSO 单列增值项；SCIM 放在 P2（见 §12） |
| 关联 | `docs/15-目录认证配置`、`docs/16-登录方式与域身份单点登录`、`docs/28-安全合规审计` |
| 影响范围 | `internal/auth`、`internal/directory`、`internal/httpapi/handlers_sso.go`、登录页、管理台 |

---

## 0. 一页结论

今天 NeuroDMS 的登录方式只有四种：**本地口令 + TOTP**、**LDAP/AD 直连认证**、
**目录同步（建号后仍用本地口令）**、**反向代理注入头断言**（`X-Remote-User`）。

这三条都解决不了现在客户提的三类需求：

1. 客户已有统一身份平台（Azure AD / AD FS / Okta / Keycloak / 宁盾 / 竹云 / Authing），
   要求"人员离职在 IdP 停用，业务系统立刻登不进"——反向代理方案做不到，因为
   代理只管"进门那一下"，管不了会话吊销；
2. 客户全员用钉钉 / 企业微信 / 飞书，要求"工作台点开就进去，别再输一次密码"；
3. 客户要做等保/密评，要求"认证协议标准化、可审计、不依赖自研头断言"。

**结论：三条都要，但不是一个东西。** 建议按下面的拆分实施，避免"上一个协议包打天下"：

| 需求 | 协议 | 角色 | 排期（已定） |
|---|---|---|---|
| 自建 IdP / 现代身份平台（Google、Apple、Keycloak、Authing 等） | **OIDC**（RP 端，Code + PKCE） | 现代标准，配置比 SAML 简单一个量级 | **P1（先做）** |
| 微信扫码（开放平台网站应用） | **OAuth 2.0** | C 端/个人身份，只给 openid，必须先绑定 | **P1** |
| 钉钉 / 飞书 / 企业微信 工作台免登、扫码 | **OAuth 2.0**（飞书优先 OIDC） | 国内办公协同入口 | P2（钉钉→飞书→企微） |
| 企业对 IdP 联合登录（AD FS / Azure AD / Okta / 国产 IAM） | **SAML 2.0**（SP 端） | 政企、金融、制造业的主力，投标门槛项 | P3 |
| 人员/部门自动同步、离职即停用 | **SCIM 2.0** | 与 SSO 配套 | **P5+（暂不做）** |

一句话：**OIDC 解决"标准接入"，OAuth 2.0 解决"国内平台的接入形态"，
SAML 解决"政企既有 IdP"，SCIM 解决"账号生命周期"（本期不做）。**
前三个缺一个，客户验收都会卡住；SCIM 可以先用目录同步顶，但离职空窗要写进验收说明。

---

## 1. 现状盘点

### 1.1 已具备

| 能力 | 实现位置 | 说明 |
|---|---|---|
| 本地口令 + 锁定策略 | `internal/auth/service.go` | 5 次失败锁 30 分钟 |
| TOTP / 邮件验证码双因子 | `internal/auth/otp.go`、`notify` | `mfa_required` 账号无通道即拒登（fail-closed） |
| LDAP / AD 认证 | `internal/directory` | 支持 StartTLS/ldaps、部门与组同步、增量同步 |
| 目录配置页 + 测试连接 | `handlers_ldap_admin.go` | 数据库配置优先，回退环境变量 |
| 头断言 SSO | `handlers_sso.go` | 受信代理网段 + 共享密钥 + 头白名单，fail-closed |
| 会话吊销 | `internal/auth/revocation.go` | 按账号 epoch 失效全部令牌 |
| 四层身份 | 账号类型 / 管理角色 / 权限档位 / 密级 | 与认证解耦，这是本次设计能成立的基础 |

### 1.2 缺口

| 缺口 | 后果 |
|---|---|
| 无标准协议 SP 端 | 客户 IdP 只能"反向代理塞头"，需要改动客户网络架构，很多客户的安全团队不接受 |
| 无 IdP 侧会话联动 | IdP 上禁用账号后，NeuroDMS 里的 refresh token 仍可用 30 天（除非管理员手动停用） |
| 无账号绑定模型 | 头断言 SSO 用"用户名相同即同一个人"，一旦 IdP 侧改名/重名就会串号 |
| 无多 IdP | 一个租户只能接一套目录（`directory_config` 主键是 tenant_id），集团客户多子公司场景不支持 |
| 无 SCIM | 人员变动要靠定时全量同步，离职后最长有一个同步周期的空窗 |

---

## 2. 三个协议分别是什么（够用版）

### 2.1 SAML 2.0

**是什么**：基于 XML 的联合认证协议。企业 IdP（AD FS、Okta、Azure AD、Keycloak）
签发一份**签名断言（Assertion）**，声明"这个用户是谁、属于哪个组织、有哪些属性"，
通过浏览器 POST 到我们的 ACS 端点。

**一次 SP 发起登录**：

```
用户 → GET /sso/start?tenant=acme
     → 302 到 IdP 的 SSO URL，带 SAMLRequest（压缩+base64+可选签名）、RelayState
IdP  → 用户认证（可能带 MFA）
     → 302/POST 回 /sso/acs，带 SAMLResponse（base64）
我们 → 校验签名、Audience、InResponseTo、时间窗 → 建会话 → 302 到目标页面
```

**它擅长**：政企/金融的既有 IdP 生态；属性断言（部门、工号、职级）随登录一起下发；
不需要 IdP 暴露 JSON API。

**它的坑**（这也是为什么必须写测试，而不能"跑通就行"）：

- **XML 签名包装攻击（XSW）**：攻击者在合法断言外套一层未签名的断言，让解析器
  读"外层"、验签"内层"。必须用成熟库 + 严格指定"只认 Response 或 Assertion 其中
  一个签名位置"，且校验 `Assertion.ID == Response. SignedInfo Reference URI`。
- **签名剥离**：库默认"有签名才验"，没签名就跳过。必须**强制要求签名**。
- **Audience / Destination / Recipient 不校验**：同一份断言可以被投递到另一个 SP。
- **时钟偏移**：`NotBefore` / `NotOnOrAfter` 常见 ±5 分钟容忍，超过就会被前移攻击。
- **IdP 发起（IdP-initiated）无法校验 `InResponseTo`**：等于放弃防重放，只能靠
  `Assertion.ID` 一次性标记 + 短有效期。**建议默认关闭，按客户白名单开启。**

### 2.2 OIDC（OpenID Connect 1.0）

**是什么**：架在 OAuth 2.0 授权码流程上的**认证层**。核心产物是 `id_token`——
一个 JWT，包含 `iss / aud / exp / sub / nonce`，由 IdP 签名。

**一次 RP 发起登录**：

```
GET /sso/oidc/start?tenant=acme
  → 生成 state + nonce + code_verifier，存服务端（或签名 Cookie）
  → 302 到 {authorization_endpoint}?response_type=code&client_id=...&
          redirect_uri=...&scope=openid profile email&state=...&nonce=...&
          code_challenge=...&code_challenge_method=S256
回调 /sso/oidc/callback?code=...&state=...
  → 校验 state（必须与发起时一致，一次性）
  → POST {token_endpoint}（client_secret_basic 或 private_key_jwt）换 id_token
  → 校验 JWT 签名（JWKS）、iss、aud、exp/iat、nonce，以及 azp（多受众时）
  → 若需要更多属性：带 access_token 调 {userinfo_endpoint}
```

**它擅长**：配置简单（填 issuer + client_id + secret 即可，其余靠 discovery 拉取）；
移动端/SPA/小程序友好；**国内 IM 平台正在向它靠拢**（飞书最标准）。

**它的坑**：

- **缺 PKCE**：公共客户端（SPA、桌面、小程序）必须用 `S256`，否则授权码可被截获；
- **缺 state 或 state 可预测**：CSRF 登录（把攻击者的账号绑到受害者会话上）；
- **不校验 nonce**：id_token 重放；
- **只验签名不验 claims**：`aud` 不校验等于任何接入方的 token 都能登进来；
- **JWKS 缓存与轮换**：IdP 换密钥后要能自动刷新，否则整站登不进；
- **`email` 不可作为唯一标识**：可改、可空、可不唯一。必须用 `sub`（+ issuer）绑定。

### 2.3 OAuth 2.0

**是什么**：**授权**协议，不是认证协议。它只回答"这个客户端能否代表用户访问某资源"。

**为什么还需要它**：钉钉、企业微信的免登本质上就是 OAuth 2.0 授权码流程
（企微 `snsapi_base` 拿 `UserId`，钉钉 `/contact/users/me` 拿 `unionId`），
它们不提供标准 OIDC discovery，也没有 `id_token`。所以：

- **飞书**：优先走 OIDC（有 discovery、标准 claims），拿不到再降级 OAuth；
- **企业微信 / 钉钉**：走 OAuth 2.0 + 各自的 userinfo 接口，**必须额外校验
  `corp_id`/`agent_id`**（否则别人的企业应用能把你的人登进来）；
- **微信开放平台（C 端扫码）**：只有 OAuth 2.0（`snsapi_login`），且只能拿到
  `openid/unionid`，需要"先绑定后登录"。

**关键纪律**：OAuth 2.0 拿到的不是"身份断言"，是"平台背书的一段信息"。
必须把它映射到**已绑定**的本地账号，不能凭手机号/昵称自动建号
（否则任何人改个昵称就能冒充）。

---

### 2.4 各提供商的接入要点（按已定顺序）

顺序是**接入顺序**，不是客户重要性。技术上要分两类看待：

- **苹果、谷歌是标准 OIDC**：与通用 OIDC 能力同一批做，边际成本最低；
- **微信、钉钉、飞书、企业微信是各自的 OAuth 2.0 变体**（飞书最接近标准 OIDC），
  每家都要单独的适配器与联调环境。

| 提供商 | 协议 | 必须知道的坑 |
|---|---|---|
| 微信（开放平台网站应用扫码） | OAuth 2.0 `snsapi_login` | **只返回 openid/unionid，没有邮箱也没有手机号** → 必须先绑定已有账号，绝不能自动建号；授权回调域要在开放平台登记；`unionid` 需主体绑定开放平台后才稳定（多应用识别同一人） |
| 苹果 Sign in with Apple | OIDC | `client_secret` **不是固定串**，要用 `.p8` 私钥现签 ES256 JWT（有效期 ≤6 个月，需定时轮换）；必须 `response_mode=form_post`；姓名/邮箱**只在首次授权时返回一次**，之后只有 `sub`；用户可选「隐藏邮箱」得到 `@privaterelay.appleid.com` |
| 谷歌 | OIDC（标准 discovery） | 可用 `hd` 限定企业域名；邮箱可被改，绑定键仍然只能是 `sub` |
| 钉钉 | OAuth 2.0 | 扫码登录与工作台免登是两条链路（后者在容器内用 jsapi 授权码）；需 corpId + 应用 agentId |
| 飞书 | OIDC（优先）/ OAuth 2.0 | 标准 discovery + claims，接入成本最低；`open_id` 是应用内唯一，跨应用要用 `union_id` |
| 企业微信 | OAuth 2.0 | 工作台免登 `snsapi_base` 只给 `UserId`；**服务端换 token 的出口 IP 必须加进可信 IP**，否则报 60020（这是最常见的上线卡点）；自建应用只能读可见范围内的成员 |

**一条贯穿全部提供商的规则**：账号绑定键永远是 `(provider, subject)`。
微信的 openid、苹果的 sub、谷歌的 sub 都不是邮箱——**邮箱可以改、可以空、可以不唯一**，
用它做绑定键，早晚会出现"两个人进同一个账号"。

---

## 3. 目标架构

### 3.1 认证源注册表（多 IdP）

一个租户可注册多个认证源（集团多子公司、灰度切换、SAML 与 OIDC 并存）：

```
identity_provider
  id, tenant_id, kind(saml|oidc|oauth|ldap|header), slug, display_name,
  enabled, is_default,
  -- SAML
  idp_entity_id, idp_sso_url, idp_slo_url, idp_cert_pem(s), sp_entity_id,
  nameid_format, want_assertions_signed, allow_idp_initiated,
  -- OIDC / OAuth
  issuer, client_id, client_secret_enc, scopes, authorization_endpoint,
  token_endpoint, userinfo_endpoint, jwks_uri, token_auth_method,
  -- 通用
  attribute_map jsonb,   -- {username, email, displayName, dept, employeeNo, groups}
  jit_provisioning bool, default_role, default_classification,
  allowed_email_domains text[]
```

**登录页的发现顺序**（必须可预测，否则用户会看到"有时跳 IdP、有时要口令"）：

1. 用户从 `/{tenantSlug}` 入口进 → 用该租户 `is_default` 的认证源；
2. `identity_hint`（邮箱域名）匹配 `allowed_email_domains` → 用对应认证源；
3. 都没有 → 本地口令。

### 3.2 外部身份绑定表

```
external_identity
  tenant_id, provider_id, subject,        -- subject = SAML NameID / OIDC sub / 企微 UserId
  user_id, linked_at, last_login_at, raw_claims jsonb,
  PRIMARY KEY (tenant_id, provider_id, subject)
```

**三条规则**：

1. **只有 `(provider_id, subject)` 是身份**。邮箱、手机号、用户名只是属性，
   可用于"首次自动关联"的提示，但必须管理员确认或用户已登录后主动绑定；
2. **一个本地账号可以绑多个外部身份**（同一个人既在 Azure AD 又在飞书）；
3. **解绑即失效**：删除绑定后，该 subject 再登录只能走 JIT（若开启）或拒绝。

### 3.3 账号供给（JIT）与权限映射

JIT 只做"建号"，**绝不做"提权"**：

| 属性 | 来源 | 规则 |
|---|---|---|
| 用户名 | `attribute_map.username` | 冲突时加后缀，不允许覆盖已有账号 |
| 显示名 / 邮箱 | 断言 / claims | 直接写入，可被下次登录更新 |
| 部门 | `attribute_map.dept` | 只匹配已存在的部门路径，匹配不上则留空并记审计 |
| 管理角色 | **不从 IdP 取** | 只能由租户 sysadmin 授予。IdP 里的 "admin" 组不等于 NeuroDMS 的 sysadmin |
| 权限档位 | `default_role`（如 viewer） | JIT 建号一律最低档 |
| 密级 | `default_classification`（默认 0） | 高密级必须人工定，不能让 IdP 属性决定 |
| 账号状态 | 每次登录校验 | IdP 侧禁用不会自动同步，需 SCIM 或下次登录拒绝 |

**这条"不取角色"是刻意的**：把 IdP 组映射成管理角色，等于把提权能力交给客户 IdP 
管理员，而 IdP 管理员往往不在我们的审计范围内。

### 3.4 会话与吊销

沿用现有 JWT + epoch 机制，但增加两个触发点：

- **SLO（单点登出）**：SAML 的 `LogoutRequest` / OIDC 的 `end_session_endpoint` 
  回调到 `/sso/logout` → 按 `external_identity` 找到 user → `revocation` 提升 epoch；
- **登录时校验**：每次 SSO 登录写 `last_login_at` + `session_id`，管理员可在
  成员页看到"这个账号从哪个 IdP 登录"，并一键吊销。

### 3.5 与密级/审计的关系（不得放松）

- SSO 登录成功**不改变**密级门：断言里的"职级"不能当密级用；
- 审计事件新增 `auth.sso.login` / `auth.sso.fail` / `auth.sso.link` / `auth.sso.unlink`，
  记录 `provider_id`、`subject`（脱敏）、`result`、`reason`；
- 断言原文**不入库**（只存 `raw_claims` 里的白名单字段），避免把 IdP 的敏感属性
  复制进我们的备份。

---

## 4. 关键安全设计（逐条可测）

| # | 要求 | 验收方式 |
|---|---|---|
| S1 | SAML 必须验签，且只认一个签名位置（Response 或 Assertion） | 构造"外层无签名/内层有签名"的 XSW 样本，必须拒绝 |
| S2 | 校验 `Audience == sp_entity_id`、`Destination == acs_url`、`Recipient` | 篡改三者的样本必须拒绝 |
| S3 | 校验 `InResponseTo`（SP 发起时），并一次性消费 | 重放同一 Response 第二次必须拒绝 |
| S4 | 时间窗 ±5 分钟，`NotOnOrAfter` 不得超过 10 分钟 | 过期断言必须拒绝 |
| S5 | IdP 发起默认关闭，开启时按 `Assertion.ID` 做一次性去重 | 重复投递必须拒绝 |
| S6 | OIDC 强制 PKCE(S256) + state + nonce，三者一次性 | 去掉任一参数必须拒绝 |
| S7 | id_token 必须校 `iss/aud/exp/iat/nonce/azp`，JWKS 支持轮换 | 换 issuer、换 audience 的 token 必须拒绝 |
| S8 | 账号绑定只认 `(provider, subject)`，不以邮箱/手机号自动建号 | 用同邮箱不同 subject 登录，不得进入同一账号 |
| S9 | IdP 元数据/证书更新必须走"先校验再替换"，保留旧证书双活窗口 | 轮换期间登录不中断 |
| S10 | 所有失败路径 fail-closed：配置缺失、JWKS 拉取失败、证书过期 → 拒绝登录并说明原因 | 断网/删配置后必须登不进，且审计有记录 |
| S11 | 防账号枚举：不存在的 subject 与停用账号返回同一提示 | 两种情况的响应体与耗时一致 |
| S12 | SSO 登录不产生管理员权限 | JIT 建号后角色为空、档位最低 |

---

## 5. 数据模型与迁移

```sql
-- 0052_identity_provider.sql（草案）
CREATE TABLE identity_provider (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id uuid NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
    kind text NOT NULL CHECK (kind IN ('saml','oidc','oauth')),
    slug text NOT NULL CHECK (slug ~ '^[a-z0-9][a-z0-9-]{1,31}$'),
    display_name text NOT NULL,
    enabled boolean NOT NULL DEFAULT false,
    is_default boolean NOT NULL DEFAULT false,
    -- SAML
    idp_entity_id text NOT NULL DEFAULT '',
    idp_sso_url text NOT NULL DEFAULT '',
    idp_slo_url text NOT NULL DEFAULT '',
    idp_cert_pem text NOT NULL DEFAULT '',        -- 允许多张（轮换期）
    sp_entity_id text NOT NULL DEFAULT '',
    nameid_format text NOT NULL DEFAULT '',
    want_assertions_signed boolean NOT NULL DEFAULT true,
    allow_idp_initiated boolean NOT NULL DEFAULT false,
    -- OIDC / OAuth
    issuer text NOT NULL DEFAULT '',
    client_id text NOT NULL DEFAULT '',
    client_secret_enc bytea,
    scopes text NOT NULL DEFAULT 'openid profile email',
    authorization_endpoint text NOT NULL DEFAULT '',
    token_endpoint text NOT NULL DEFAULT '',
    userinfo_endpoint text NOT NULL DEFAULT '',
    jwks_uri text NOT NULL DEFAULT '',
    token_auth_method text NOT NULL DEFAULT 'client_secret_basic',
    -- 通用
    attribute_map jsonb NOT NULL DEFAULT '{}'::jsonb,
    jit_provisioning boolean NOT NULL DEFAULT false,
    default_role text NOT NULL DEFAULT 'viewer',
    default_classification smallint NOT NULL DEFAULT 0,
    allowed_email_domains text[] NOT NULL DEFAULT '{}',
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    updated_by uuid,
    UNIQUE (tenant_id, slug)
);
-- RLS 同其它租户表

CREATE TABLE external_identity (
    tenant_id uuid NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
    provider_id uuid NOT NULL REFERENCES identity_provider(id) ON DELETE CASCADE,
    subject text NOT NULL,
    user_id uuid NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,
    linked_at timestamptz NOT NULL DEFAULT now(),
    last_login_at timestamptz,
    raw_claims jsonb NOT NULL DEFAULT '{}'::jsonb,
    PRIMARY KEY (tenant_id, provider_id, subject)
);
```

**为什么单独建表而不是塞进 `directory_config`**：一个租户要接多个 IdP，
`directory_config` 的主键是 `tenant_id`，扩成多行会牵动现有同步逻辑；
新表还能顺带承载"钉钉/企微"这类非 LDAP 的源。

**SP 签名密钥**：SAML 需要 SP 自己的私钥（给 AuthnRequest 签名、解密加密断言）。
复用现有 `secretbox` 落库，密钥来源与证书私钥同一个 `DOCVAULT_SECRET_KEY`。
不引入证书时也可以"不签 AuthnRequest"（多数 IdP 接受），作为降级路径。

---

## 6. 接口与页面

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/v1/auth/providers?tenant={slug}` | 登录页用：返回该租户可用的认证源（不含任何密钥） |
| GET | `/api/sso/{tenant}/{provider}/start` | SP 发起：生成请求、302 到 IdP |
| POST | `/api/sso/{tenant}/{provider}/acs` | SAML 断言接收 |
| GET | `/api/sso/{tenant}/{provider}/callback` | OIDC/OAuth 回调 |
| GET | `/api/sso/{tenant}/{provider}/metadata` | 输出 SP 元数据 XML（客户 IdP 侧导入） |
| GET/POST | `/api/sso/logout` | SLO 回调 |
| GET/PUT | `/v1/admin/identity-providers` | 管理台列表/保存（sysadmin） |
| POST | `/v1/admin/identity-providers/{id}/test` | 元数据/发现文档连通性与证书校验 |
| DELETE | `/v1/admin/identity-providers/{id}` | 删除（有绑定时需二次确认） |
| GET/DELETE | `/v1/admin/users/{id}/identities` | 查看/解绑某人的外部身份 |

**管理台页面**：`管理台 → 目录认证` 下新增「单点登录（SAML / OIDC）」区块，
与现有 LDAP 配置并列；每个认证源一张卡片（状态、上次登录、测试按钮）。

**登录页**：租户入口 `/{slug}` 先拉 `/v1/auth/providers`，有默认 SSO 的租户
直接显示"使用企业账号登录"为主按钮，本地口令收进"其他登录方式"。

---

## 7. 分阶段迭代计划（按已定决策重排）

工期是**单人或双人并行**的估算，不含客户侧配合与联调排队时间。

### P0 · 技术验证（3～4 人日）

- 本地起一个 OIDC IdP（Keycloak）与一个最小 OAuth2 服务，跑通
  code + PKCE、state/nonce、回调、绑定、登出；
- 产出"畸形令牌/回调"样本集（换 issuer、换 aud、重放 code、缺 nonce、state 不匹配）；
- 定库：`coreos/go-oidc` + `golang.org/x/oauth2`（SAML 到 P3 再引 `crewjam/saml`）。
- **验收**：S1～S12 中与 OIDC/OAuth 相关的 6 条用例全部按预期拒绝。

### P1 · OIDC 核心 + 微信 + 苹果 + 谷歌（15～20 人日）

按已定顺序，这一批同时覆盖三种形态：标准 OIDC、苹果的"动态 client_secret"、微信的"无邮箱 OAuth"。

- 迁移：`identity_provider` / `external_identity`；
- 通用 OIDC RP：discovery、JWKS 缓存与轮换、id_token 校验（iss/aud/exp/nonce/azp）；
- 通用 OAuth2 适配器：授权码换取、userinfo、字段映射（微信/钉钉/企微共用）；
- 三个提供商适配器：微信扫码、苹果（ES256 client_secret 生成与轮换）、谷歌；
- **账号绑定**：绑定页、解绑、冲突处理（同一 subject 已绑他人 / 同一人被两个 subject 绑定）；
- JIT：`default_role=viewer`、管理角色一律为空、密级 0（见 §3.3）；
- 登录页分流 + 管理台配置页 + 「测试连接」；
- 审计事件 `auth.sso.login / fail / link / unlink`。
- **验收**：三家真实环境各跑通一次登录 → 绑定 → 登出；未绑定用户不得自动获得任何对象权限；
  同一邮箱两个 subject 不得进入同一账号。

### P2 · 钉钉 → 飞书 → 企业微信 + SCIM（14～18 人日）

同一套 OAuth2 适配器，按顺序逐个接，每接一家就交付一次（不攒到最后）。

- 钉钉扫码 + 工作台免登（容器内 jsapi）；
- 飞书优先走 OIDC（有标准 discovery），拿不到再降级 OAuth；
- 企业微信工作台免登（`snsapi_base` → `UserId`），并把出口 IP 加可信 IP 写进实施手册；
- 一租户多认证源、默认源切换、按邮箱域名分流；
- **SCIM 2.0**：`/scim/v2/Users`、`/scim/v2/Groups`（Bearer token、增量 `startIndex/count`），
  与现有目录同步并存（谁配置谁生效），离职即时停用。
- **验收**：四家（含 P1 的微信）在同一租户内可共存，登录页按域名正确分流；
  IdP 侧停用/删除用户后，**下一分钟**该账号会话失效。

### P3 · SAML 2.0（企业 IdP）（12～16 人日）

为什么放在这里：已确定的顺序里没有传统企业 IdP，但政企/金融客户只认 SAML。
**不建议再往后拖**——它是投标门槛项，且越晚做，`identity_provider` 表要改的地方越多。

- SP 端：AuthnRequest、ACS、SP metadata、SLO；
- 断言校验：强制签名、单签名位置、Audience/Destination/InResponseTo、时间窗（§4 S1～S5）；
- IdP 发起登录默认关闭，按租户白名单开启；
- 证书双活轮换（新旧并存 30 天）。

### P4 · 企业级打磨（8～12 人日）

- 元数据自动刷新、断言加密（`EncryptedAssertion`）；
- 会话管理页：按 IdP 维度看登录、批量吊销；SLO 全链路；
- 平台侧 IdP 模板（Azure AD / 谷歌 / 苹果 / 微信 / 钉钉 / 飞书 / 企微 / Keycloak）；
- 私有化离线交付：手工粘贴元数据与 JWKS，不依赖外网 discovery。

### P5 · 暂不做

SCIM 已并入 P2，本节清空。后续候选：SAML 断言加密、终端代理（用于采集主机名/
域账号，见 docs/31 §7.8 的边界说明）、多租户 IdP 模板市场。

**总计约 52～70 人日**（不含客户侧配合与合规文档）。

---

## 8. 测试策略

| 类型 | 内容 |
|---|---|
| 单元 | 断言/令牌校验函数：篡改 issuer、audience、时间、nonce、签名位置 |
| 集成 | 测试内起一个最小 IdP（SAML：预置密钥自签断言；OIDC：httptest 暴露 discovery + JWKS） |
| 安全回归 | 上面 12 条（S1～S12）作为**固定用例**，每次改动必跑 |
| 兼容性 | 三家真实 IdP + 两家国内 IM 的沙箱环境（客户常提供测试企业） |
| 故障注入 | JWKS 拉取失败、IdP 证书过期、时钟偏移 6 分钟、网络中断 |
| 权限 | SSO 登录后的角色/档位/密级必须与"本地登录同一账号"完全一致 |

---

## 9. 运维与交付

- **元数据**：客户 IdP 侧导入我们的 `/metadata`；我们把客户的元数据 XML
  存库（`idp_metadata_xml`），支持 URL 拉取但**以库里副本为准**（避免 IdP 变更
  导致登录突然中断，变更走"测试→确认→替换"）。
- **证书轮换**：`idp_cert_pem` 支持多张，新旧并存期间都能验签，30 天后清理。
- **私有化**：不依赖外网，discovery 结果可手工粘贴（issuer/三个 endpoint/jwks）。
- **档位**：SSO 归入"专业版及以上"（与目录认证一致），在保存入口拦截而不是只藏页面。
- **可观测**：`/v1/ops/status` 增加每个认证源的"最近成功登录时间"与"证书到期日"。

---

## 10. 与现有代码的改动面

| 文件/包 | 改动 |
|---|---|
| `internal/auth/service.go` | 抽出 `AuthenticateExternal(ctx, tenantID, providerID, subject, attrs)`，复用会话签发 |
| `internal/auth/revocation.go` | 增加 `RevokeByIdentity(provider, subject)` |
| 新包 `internal/idp` | `saml.go` / `oidc.go` / `oauth.go` / `store.go` / `mapper.go` |
| `internal/httpapi/handlers_sso.go` | 现有"头断言"保留（部分客户只用它就够），新增协议路由 |
| `web/src/pages/Login.tsx` | 认证源分流、SSO 按钮、失败提示 |
| `web/src/pages/DirectorySettings.tsx` 或新页 | 认证源卡片 |
| `migrations/0052+` | 两张新表 + RLS + 授权 |

**不改**：authz 权限内核、密级体系、审批流程。认证只负责"这个人是谁"，
"这个人能干什么"仍由现有四层身份决定——这是本次设计最重要的边界。

---

## 11. 风险

| 风险 | 影响 | 缓解 |
|---|---|---|
| 客户 IdP 配置质量差（证书错、时钟漂移、属性名不一致） | 实施周期不可控 | 提供"测试连接"与明确的错误码；养一份各家 IdP 的配置手册 |
| XML 解析漏洞 | 认证绕过 | 只用成熟库 + 固定 12 条安全用例；禁止自研 XML 解析 |
| 账号绑定冲突（同一邮箱两个 subject） | 串号 / 数据泄露 | 只认 subject；冲突时拒绝并提示管理员处理 |
| IdP 侧离职不同步 | 前员工仍可登录 | P2 必须交付 SCIM 或"每次登录校验 IdP 状态" |
| 多 IdP 后登录页变复杂 | 用户困惑 | 默认源 + 邮箱域名分流 + 单一入口 |
| 私有化环境无外网 | discovery/JWKS 拉不到 | 支持手工粘贴元数据与 JWKS |

---

## 12. 决策记录（2026-11-14 已定）

| # | 问题 | 决定 | 对方案的影响 |
|---|---|---|---|
| 1 | 先 SAML 还是 OIDC | **先 OIDC** | P1 做通用 OIDC；SAML 推迟到 P3，但仍必须做（政企门槛项） |
| 2 | JIT 建号是否给默认档位 | **按推荐**：JIT 建号、`default_role=viewer`、**管理角色一律为空**、密级 0 | 新人登录即"可进系统但看不到任何未授权内容"；管理员仍需显式授权 |
| 3 | SSO 后是否保留本地口令 | **按推荐**：保留，但 SSO 用户**默认禁用本地口令登录**，按租户开关打开（break-glass） | 需要一条"平台管理员可强制恢复本地登录"的应急路径，写进运维手册 |
| 4 | 国内 IM 的范围与顺序 | **微信 → 苹果 → 谷歌 → 钉钉 → 飞书 → 企业微信** | 微信进 P1（OAuth2 适配器先落地），钉钉/飞书/企微进 P2 按序交付 |
| 5 | 档位归属 | **单列增值项**（不并入专业版） | 需要新增一个能力位与报价项；运营台按租户开通，未开通时登录页不显示 |
| 6 | SCIM 是否在 P2 | **改主意：放进 P2** | P2 = 钉钉/飞书/企微 + SCIM；离职即时停用成为可承诺项，不再留空窗 |

### 关于第 5 条"档位"是什么意思

本产品的"档位"就是**版本/套餐**（基础版 / 专业版 / 商业版），存在 `tenant.edition`，
决定哪些功能可用；运营台可以给单个租户临时覆盖。目录认证（LDAP/AD）现在就属于
"专业版及以上"，基础版只能看配置页、保存会被拒。

**建议 SSO 与目录认证同档（专业版及以上）**，理由：

1. SSO 的实施成本主要在客户侧（IdP 登记、证书、属性映射、联调），不是点一下就能用；
   放基础版会让低客单价客户占用大量支持资源；
2. 它是政企采购的常见门槛项，放在专业版能自然形成升级理由；
3. 与现有"认证类能力同档"的规则一致，运营和报价都好解释。

如果希望单列增值项（加钱开），也可以——技术上只是 `edition` 里多一个能力位，
不影响本方案的任何设计。

### 仍未确定的一件事

**是否现在就启动 P1。** 上面 6 条已定，P1 的范围与验收标准也已明确；
一旦确认，我会先做 P0（3～4 人日）再进 P1。

---

## 13. 与二期电子签名方案的关系

`docs/phase2/38-电子签名与数据完整性` 里的"签名人身份可信"依赖认证强度。
SSO 落地后，签名事件可以记录 `provider` 与 `subject`，把"谁签的"从
"本地账号"升级为"经企业 IdP 认证的主体"，这对 21 CFR Part 11 / eIDAS 的
"签名人身份可归属"是加分项。两期不冲突，但**签名方案不应等待 SSO**：
P1 完成后可作为签名审计的一个属性补入。
