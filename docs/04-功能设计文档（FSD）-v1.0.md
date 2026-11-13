# 功能设计文档（FSD）v1.0

- 产品：DocVault ｜ 版本：v1.0 ｜ 日期：2026-11-08 ｜ 状态：**待评审**
- 上游：02-PRD、03-SAD ｜ 定位：可直接驱动编码实现的规格（表 → 接口 → 算法 → 时序 → 用例）

---

## 1. 通用约定

### 1.1 标识与命名

| 项 | 规范 |
|---|---|
| 主键 | `uuid` v7（时间有序，减少 B-tree 分裂），DB 默认 `gen_random_uuid()` 仅用于非热点表；热点表由应用生成 v7 |
| 时间 | 全部 `timestamptz`，**存储 UTC**，展示按用户时区；禁止 `timestamp without time zone` |
| 软删除 | `deleted_at timestamptz NULL`；查询默认 `deleted_at IS NULL`；唯一约束用部分索引 `WHERE deleted_at IS NULL` |
| 命名 | 表名单数蛇形（`app_user`），字段蛇形；Go 结构体驼峰；JSON 传输驼峰 |
| 枚举 | DB 用 `text + CHECK`（不用 PG enum，避免 ALTER TYPE 受限）；Go 用常量 + `Valid()` |
| 金额/大小 | 字节用 `bigint`；金额用 `numeric(18,4)`（为将来计费预留） |

### 1.2 统一响应信封

```json
{ "code": "OK", "message": "success", "requestId": "01J...", "data": {} }
```

| HTTP | code 示例 | 语义 |
|---|---|---|
| 200 | `OK` | 成功 |
| 400 | `INVALID_ARGUMENT` | 参数错误（附 `fields`） |
| 401 | `UNAUTHENTICATED` / `SESSION_EXPIRED` | 未登录/会话失效 |
| 403 | `PERMISSION_DENIED` / `CEILING_EXCEEDED` / `CLASSIFICATION_DENIED` / `MFA_REQUIRED` | 有身份无权限/超过封顶/密级不足/需二次验证 |
| 404 | `NOT_FOUND` | 不存在**或无权访问**（默认不区分） |
| 409 | `CONFLICT` / `VERSION_CONFLICT` / `ALREADY_EXISTS` | 并发冲突 |
| 410 | `SHARE_UNAVAILABLE` | 分享不存在/过期/用尽/撤销（统一） |
| 422 | `POLICY_VIOLATION` | 违反策略（如分享有效期超上限） |
| 429 | `RATE_LIMITED` | 限流（附 `retryAfter`） |
| 500 | `INTERNAL` | 服务端错误（不返回堆栈，仅 requestId） |

**纪律**：错误码稳定不随版本变；不允许客户端靠 message 文案判断。

### 1.3 幂等

- 所有 `POST` 写接口支持 `Idempotency-Key` 头；服务端存 `(key, tenant, route)` → 首次响应快照（TTL 24h）。
- 内部任务与通知使用业务幂等键（见 §8.2）。

### 1.4 分页

- 列表用**游标分页**（`cursor` = base64(`created_at|id`)），默认 50，最大 200。
- 必须提供稳定排序键（`ORDER BY created_at DESC, id DESC`），禁止仅按非唯一列排序。

---

## 2. 数据模型

### 2.1 租户与身份

```sql
CREATE TABLE tenant (
  id uuid PRIMARY KEY,
  slug text NOT NULL UNIQUE,            -- 子域名/路径白标标识
  name text NOT NULL,
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('active','suspended','deleted')),
  plan_code text NOT NULL DEFAULT 'standard',
  brand jsonb NOT NULL DEFAULT '{}',    -- logo/背景/文案/主色
  settings jsonb NOT NULL DEFAULT '{}', -- 租户级配置覆盖
  created_at timestamptz NOT NULL DEFAULT now(),
  deleted_at timestamptz
);

CREATE TABLE app_user (
  id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL REFERENCES tenant(id),
  principal_type text NOT NULL CHECK (principal_type IN ('internal','external','system')),
  source text NOT NULL CHECK (source IN ('local','ldap','oidc','invite')),
  username text NOT NULL,               -- 内部唯一（本地）或 sAMAccountName
  email citext,
  email_verified_at timestamptz,
  phone text,
  phone_verified_at timestamptz,
  display_name text NOT NULL,
  password_hash text,                   -- Argon2id；LDAP 用户为 NULL
  dept_id uuid,
  title text,
  classification smallint NOT NULL DEFAULT 0,   -- 用户密级
  ceiling smallint NOT NULL DEFAULT 10,         -- 可授出最高档位（见 §3.5）
  mfa_required boolean NOT NULL DEFAULT false,
  status text NOT NULL DEFAULT 'active' CHECK (status IN ('invited','active','suspended','deleted')),
  session_epoch int NOT NULL DEFAULT 1,         -- 自增即可踢下线
  last_login_at timestamptz,
  expires_at timestamptz,               -- 外部用户有效期
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  deleted_at timestamptz
);
CREATE UNIQUE INDEX uq_user_tenant_username ON app_user(tenant_id, lower(username)) WHERE deleted_at IS NULL;
CREATE UNIQUE INDEX uq_user_tenant_email    ON app_user(tenant_id, email)            WHERE deleted_at IS NULL AND email IS NOT NULL;
CREATE INDEX ix_user_dept ON app_user(tenant_id, dept_id) WHERE deleted_at IS NULL;

CREATE TABLE dept (
  id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL,
  parent_id uuid REFERENCES dept(id),
  path ltree NOT NULL,                  -- 组织树路径，支持子树查询
  name text NOT NULL,
  ldap_dn text,                         -- 与目录同步的锚点
  sort int NOT NULL DEFAULT 0,
  deleted_at timestamptz
);
CREATE INDEX ix_dept_path ON dept USING gist(path);

CREATE TABLE user_group (
  id uuid PRIMARY KEY, tenant_id uuid NOT NULL,
  name text NOT NULL, kind text NOT NULL CHECK (kind IN ('static','dynamic','ldap')),
  rule jsonb,                           -- 动态组成员规则
  ldap_dn text, deleted_at timestamptz
);
CREATE TABLE group_member (
  group_id uuid NOT NULL, user_id uuid NOT NULL, tenant_id uuid NOT NULL,
  source text NOT NULL DEFAULT 'manual', -- manual | ldap | rule
  PRIMARY KEY (group_id, user_id)
);

CREATE TABLE role (
  id uuid PRIMARY KEY, tenant_id uuid NOT NULL,
  code text NOT NULL, name text NOT NULL,
  is_system boolean NOT NULL DEFAULT false,   -- 系统内置（三权分立角色）
  data_scope text NOT NULL DEFAULT 'self' CHECK (data_scope IN ('self','dept','dept_sub','custom','all')),
  scope_dept_ids uuid[],
  perms text[] NOT NULL DEFAULT '{}',          -- 菜单/按钮/接口权限码
  UNIQUE (tenant_id, code)
);
```

### 2.2 目录与内容

```sql
CREATE TABLE space (
  id uuid PRIMARY KEY, tenant_id uuid NOT NULL,
  kind text NOT NULL CHECK (kind IN ('personal','dept','project','knowledge','archive')),
  name text NOT NULL, owner_id uuid NOT NULL, dept_id uuid,
  quota_bytes bigint, used_bytes bigint NOT NULL DEFAULT 0,
  default_preset text NOT NULL DEFAULT 'viewer', -- 默认权限档位
  classification smallint NOT NULL DEFAULT 0,    -- 空间密级下限（子对象不得低于）
  inherit_broken boolean NOT NULL DEFAULT false, -- 空间根不继承租户
  deleted_at timestamptz
);

CREATE TABLE node (
  id uuid PRIMARY KEY, tenant_id uuid NOT NULL, space_id uuid NOT NULL,
  parent_id uuid REFERENCES node(id),
  path ltree NOT NULL,                  -- 含自身 id 的路径，用于继承查询
  kind text NOT NULL CHECK (kind IN ('folder','file')),
  name text NOT NULL,
  size_bytes bigint NOT NULL DEFAULT 0,
  mime text,
  ext text,
  current_version_id uuid,
  effective_version_id uuid,            -- "生效版"（可不同于最新版）
  classification smallint NOT NULL DEFAULT 0,
  owner_id uuid NOT NULL,
  inherit_broken boolean NOT NULL DEFAULT false,
  locked boolean NOT NULL DEFAULT FALSE,
  scan_status text NOT NULL DEFAULT 'pending' CHECK (scan_status IN ('pending','clean','infected','skipped')),
  media_status text CHECK (media_status IN ('none','pending','processing','ready','failed')),
  deleted_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ix_node_path     ON node USING gist(path);
CREATE INDEX ix_node_parent   ON node(tenant_id, parent_id) WHERE deleted_at IS NULL;
CREATE UNIQUE INDEX uq_node_sibling ON node(space_id, parent_id, lower(name)) WHERE deleted_at IS NULL AND kind='folder';

CREATE TABLE version (
  id uuid PRIMARY KEY, tenant_id uuid NOT NULL, node_id uuid NOT NULL,
  version_no int NOT NULL,
  blob_id uuid NOT NULL,
  size_bytes bigint NOT NULL,
  sha256 bytea NOT NULL,
  state text NOT NULL DEFAULT 'draft' CHECK (state IN ('draft','reviewing','effective','superseded','void')),
  created_by uuid NOT NULL,
  note text,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (node_id, version_no)          -- 并发安全的根基
);

CREATE TABLE blob (
  id uuid PRIMARY KEY,                  -- 内容寻址：sha256 前 16 字节
  tenant_id uuid NOT NULL,
  size_bytes bigint NOT NULL,
  sha256 bytea NOT NULL,
  storage_backend text NOT NULL,        -- local|s3|oss
  storage_key text NOT NULL,
  wrapped_dek bytea NOT NULL,           -- 信封加密
  ref_count int NOT NULL DEFAULT 0,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, sha256, size_bytes)
);
```

### 2.3 权限

```sql
CREATE TABLE ace (
  id uuid PRIMARY KEY, tenant_id uuid NOT NULL,
  object_type text NOT NULL CHECK (object_type IN ('space','node')),
  object_id uuid NOT NULL,
  subject_type text NOT NULL CHECK (subject_type IN ('user','dept','role','group','external','anonymous')),
  subject_id uuid,                       -- anonymous 为 NULL
  allow_bits bigint NOT NULL DEFAULT 0,  -- 15 位
  deny_bits  bigint NOT NULL DEFAULT 0,
  conditions jsonb NOT NULL DEFAULT '[]',-- 条件表达式数组
  preset text,                           -- 授权时使用的档位（可追溯）
  expires_at timestamptz,                -- 临时授权
  granted_by uuid NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX uq_ace ON ace(tenant_id, object_type, object_id, subject_type, COALESCE(subject_id,'00000000-0000-0000-0000-000000000000'::uuid));
CREATE INDEX ix_ace_object ON ace(tenant_id, object_id) WHERE allow_bits <> 0 OR deny_bits <> 0;
CREATE INDEX ix_ace_subject ON ace(tenant_id, subject_type, subject_id);
```

**条件表达式结构**（`conditions` 为数组，AND 组合；数组内元素为 `{key, op, value}`）

```json
[
  {"key":"time_window","op":"in","value":{"tz":"Asia/Shanghai","days":[1,2,3,4,5],"from":"09:00","to":"18:00"}},
  {"key":"ip_cidr","op":"in","value":["10.0.0.0/8","203.0.113.0/24"]},
  {"key":"device_trust","op":"eq","value":true},
  {"key":"mfa_satisfied","op":"eq","value":true},
  {"key":"download_quota","op":"lte","value":{"per_day":20}},
  {"key":"share_expiry_max","op":"lte","value":{"days":30}},
  {"key":"approval_state","op":"eq","value":"approved"},
  {"key":"watermark_required","op":"eq","value":true}
]
```

**未知条件键 → 判定为不满足（fail-closed）**，不允许忽略。

### 2.4 分享

```sql
CREATE TABLE share (
  id uuid PRIMARY KEY, tenant_id uuid NOT NULL,
  object_type text NOT NULL CHECK (object_type IN ('node','space','version')),
  object_id uuid NOT NULL,
  creator_id uuid NOT NULL,
  kind text NOT NULL CHECK (kind IN ('internal','link','request')),
  token_hash bytea,                     -- 仅 link：sha256(token)
  token_hint text,                      -- 前 6 位，便于用户识别（不可用于访问）
  password_hash text,                   -- 可选
  max_uses int,                         -- 1 = 一次性
  used_count int NOT NULL DEFAULT 0,
  first_used_at timestamptz,
  expires_at timestamptz,
  expire_mode text CHECK (expire_mode IN ('absolute','relative','after_first_open')),
  relative_hours int,
  allow_download boolean NOT NULL DEFAULT false,
  allow_upload boolean NOT NULL DEFAULT false,
  watermark boolean NOT NULL DEFAULT true,
  require_verify boolean NOT NULL DEFAULT false,   -- 需邮箱/短信验证码
  verify_channel text CHECK (verify_channel IN ('email','sms')),
  access_scope text NOT NULL DEFAULT 'public' CHECK (access_scope IN ('public','whitelist')),
  approval_id uuid,
  policy_snapshot jsonb NOT NULL,       -- 创建时的策略快照（不随策略变更追溯）
  revoked_at timestamptz, revoked_by uuid,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX uq_share_token ON share(token_hash) WHERE token_hash IS NOT NULL;
CREATE INDEX ix_share_object ON share(tenant_id, object_type, object_id);

CREATE TABLE share_recipient (
  share_id uuid NOT NULL, email citext, phone text,
  verified_at timestamptz,
  PRIMARY KEY (share_id, COALESCE(email, phone))
);

CREATE TABLE share_ticket (
  id uuid PRIMARY KEY,
  share_id uuid NOT NULL,
  recipient text,
  perms jsonb NOT NULL,                 -- 快照权限位
  ip_prefix inet,
  expires_at timestamptz NOT NULL,      -- 签发时 now()+5min
  consumed_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ix_ticket_expiry ON share_ticket(expires_at);

CREATE TABLE share_visit (
  id uuid PRIMARY KEY, tenant_id uuid NOT NULL, share_id uuid NOT NULL,
  action text NOT NULL,                 -- open|ticket|preview|download|upload|denied
  result text NOT NULL,                 -- ok|denied|expired|quota|bad_password|bad_code
  ip inet, ua text, device_fp text, country text,
  node_id uuid, bytes bigint,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ix_visit_share_time ON share_visit(share_id, created_at DESC);
```

### 2.5 通知与验证码

```sql
CREATE TABLE verification_code (
  id uuid PRIMARY KEY, tenant_id uuid NOT NULL,
  target text NOT NULL,                 -- email/phone
  purpose text NOT NULL CHECK (purpose IN ('login','bind','reset','share_access')),
  code_hash bytea NOT NULL,             -- sha256(code + pepper)
  attempts int NOT NULL DEFAULT 0,
  consumed_at timestamptz,
  expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ix_vcode_lookup ON verification_code(tenant_id, target, purpose, created_at DESC);

CREATE TABLE outbox (
  id uuid PRIMARY KEY, tenant_id uuid NOT NULL,
  channel text NOT NULL CHECK (channel IN ('email','sms','inapp','webhook')),
  template_code text NOT NULL,
  recipient text NOT NULL,
  vars jsonb NOT NULL DEFAULT '{}',
  idempotency_key text NOT NULL,
  status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','sending','sent','failed','dead')),
  attempts int NOT NULL DEFAULT 0,
  last_error text,
  next_retry_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, idempotency_key)
);
```

### 2.6 审计

见 SAD §9.5。补充约束：

```sql
CREATE TABLE audit_event (
  id uuid PRIMARY KEY, tenant_id uuid NOT NULL,
  seq bigint NOT NULL,
  actor_id uuid, actor_type text NOT NULL, actor_name text,   -- 冗余展示名，事实源是 actor_id
  action text NOT NULL, object_type text, object_id uuid,
  result text NOT NULL, detail jsonb NOT NULL DEFAULT '{}',
  ip inet, ua text, request_id text,
  prev_hash bytea, hash bytea NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, seq)
) PARTITION BY RANGE (created_at);

-- 只追加
CREATE RULE audit_no_update AS ON UPDATE TO audit_event DO INSTEAD NOTHING;
CREATE RULE audit_no_delete AS ON DELETE TO audit_event DO INSTEAD NOTHING;
```

> 注意：`DO INSTEAD NOTHING` 会让"误删"静默失效（更安全），但也会掩盖程序 bug。因此**同时**在应用角色上撤销 `UPDATE/DELETE` 权限，形成双保险；测试环境用触发器 `RAISE EXCEPTION` 以便暴露误用。

---

## 3. 权限模型规格

### 3.1 原子权限位（15）

| # | 位 | 名称 | 文件语义 | 文件夹语义 |
|---|---|---|---|---|
| 0 | `display` | 可见 | 对象及其属性可见、可收藏 | 可打开并列出子项 |
| 1 | `preview` | 预览 | 可查看内容与历史版本 | 对文件夹无效（继承到子项） |
| 2 | `download` | 下载 | 可下载原文件与历史版本 | 可缓存整个文件夹（打包） |
| 3 | `print` | 打印 | 可网页打印/导出 PDF | 对子项继承 |
| 4 | `copy` | 复制 | 可复制文本/另存、可"复制到" | 可复制子树到有权限的位置 |
| 5 | `edit` | 编辑 | 可编辑内容、可覆盖同名 | 可修改文件夹属性 |
| 6 | `create` | 新建 | 无效 | 可在其下新建/上传 |
| 7 | `rename` | 重命名 | 可改名 | 可改名 |
| 8 | `move` | 移动 | 可移动（需目标 `create`） | 可移动子树 |
| 9 | `delete` | 删除 | 可删除到回收站 | 可删除子树 |
| 10 | `share_internal` | 内部分享 | 可向内部主体分享 | 同 |
| 11 | `share_external` | 外部分享 | 可创建对外链接 | 同 |
| 12 | `manage_version` | 版本管理 | 可设生效版、回滚、清理版本 | 对子树生效 |
| 13 | `manage_acl` | 权限管理 | 可增删 ACE（受 ceiling 约束） | 同 |
| 14 | `owner` | 所有者 | 全部 + 可移交所有权 | 同 |

### 3.2 蕴含关系（DAG，服务端自动补齐）

```
display ◄── preview ◄── download ──► print
                  ▲        └────────► copy
                  │
                 edit ◄── manage_version
                   │
                (无强制)
create / rename / move / delete   为结构操作，独立
share_internal ◄── share_external
share_internal ◄── manage_acl ◄── owner
owner ⇒ 全部 15 位
```

**归一化规则**（写入与判定两侧都执行）：
- 授出 `download` → 自动补 `preview`、`print`、`copy`、`display`。
- 授出 `edit` → 自动补 `preview`、`display`。
- 授出 `owner` → 自动补全部。
- 若某位被 deny，其**被蕴含的下位**不自动 deny（deny 只作用于显式声明的位），但若下位无 allow，则结果仍不可用——由"未设置=拒绝"保证。

### 3.3 权限档位预设（6 档）

| 档位 | 包含位 | 典型主体 |
|---|---|---|
| `viewer` 查看者 | display, preview | 跨部门只读 |
| `commenter` 评论者 | + （评论能力，非权限位）| 评审人 |
| `contributor` 贡献者 | + download, print, create | 外部供应商上传 |
| `editor` 编辑者 | + copy, edit, rename | 项目成员 |
| `manager` 管理者 | + move, delete, share_internal, manage_version | 项目负责人 |
| `owner` 所有者 | + share_external, manage_acl, owner | 空间所有者 |

**界面纪律**：默认只暴露 6 档；"自定义"折叠在高级选项里，且必须显示"实际生效的 15 位"。

### 3.4 封顶（Ceiling）

| 档位 | ceiling 值 | 含义 |
|---|---|---|
| viewer | 1 | 最多授出 viewer |
| contributor | 3 | 最多授出 contributor |
| editor | 4 | 最多授出 editor |
| manager | 5 | 最多授出 manager |
| owner | 6 | 可授出 owner |

**语义边界（v1.0 修正）**：ceiling 只约束「能授出多高的档位」，**不约束本人依据 ACL 能做什么**。
判定函数 `authz.Authorize` 不看 ceiling；只在授权路径 `ace.Grant → authz.Grantable` 中生效。

> 修正原因：早期实现把 ceiling 同时用于动作判定，导致用户 `ceiling=4`（编辑者）的空间所有者
> 连 `manage_acl` 都过不了、无法给同事授权；而"交接所有权"是正常业务动作，不是越权。
> 该问题由集成测试暴露（`TestGrantViewerThenAccess` 全量 404）后修正。

`app_user.ceiling` **默认 6（owner）**，由安全管理员按账号下调（如外部合作方压到 3）。
防提权真正的两道闸是：①必须先对该对象有 `manage_acl`；②目标档位 ≤ 自身 ceiling。

授权时：`requested_level ≤ granter.ceiling`，否则 `403 CEILING_EXCEEDED` 并写审计（含试图授出的目标）。

### 3.5 密级（MAC）

- 取值：`0=公开, 1=内部, 2=秘密, 3=机密`（可自定义名称与级数，但级数上限 6）。
- 系统密级 `system_class`：**只升不降**（降级需 `dvctl downgrade-classification` 离线操作 + 双人确认 + 审计）。
- 用户密级 `user_class` ≤ `system_class`；文件密级 `node_class` ≤ `user_class`（上传时）。
- 判定：`user_class < node_class` → `403 CLASSIFICATION_DENIED`，**即使 ACL 全开**。
- 空间密级下限：空间可设 `min_class`，其下新对象自动继承不低于该值。

### 3.6 判定伪代码

```go
func Authorize(ctx, sub Subject, obj Object, act Action) (Decision, error) {
    // 1 租户
    if obj.TenantID != sub.TenantID { return deny("TENANT_MISMATCH"), nil }
    // 2 主体有效
    if !sub.Active || sub.SessionEpoch != ctx.Epoch { return deny("SESSION_INVALID"), nil }
    // 3 对象存在（调用方已保证，仍复核）
    if obj.DeletedAt != nil { return deny("NOT_FOUND"), nil }
    // 4 密级门（MAC）
    if sub.Class < obj.Class { return deny("CLASSIFICATION"), nil }
    // 5/6 取 ACE：本对象显式 + 祖先继承（最近显式优先）
    aces, err := loadAces(ctx, sub, obj)     // 含 space 根与 node 链
    if err != nil { return Decision{}, err } // 调用方必须转 deny（P1）
    if hitDeny(aces, act) { return deny("EXPLICIT_DENY"), nil }
    allow := collectAllow(aces)              // 就近显式覆盖：深度最大的显式 ACE 决定该位
    if !allow.Has(act) { return deny("NO_ALLOW"), nil }
    // 7 条件求值
    if !evalConditions(ctx, allow.Conditions(act), sub, obj) { return deny("CONDITION"), nil }
    // 8 封顶
    if act > sub.Ceiling { return deny("CEILING"), nil }
    // 9 归一化
    return allowNormalized(allow), nil
}

// 调用范式（禁止写成 if err != nil { /* 放行 */ }）
d, err := authz.Authorize(...)
if err != nil || !d.Allowed {
    audit.Deny(...)          // 拒绝也要审计
    return notFoundOrForbidden(d)
}
```

### 3.7 权限解释接口（排障与客服的刚需）

`GET /v1/authz/explain?objectId=&userId=&action=` 返回：

```json
{
  "allowed": false,
  "action": "download",
  "deniedBy": "EXPLICIT_DENY",
  "chain": [
    {"source":"space:project-x","subject":"role:viewer","allow":["display","preview"],"deny":[]},
    {"source":"node:contract.pdf","subject":"group:legal","allow":[],"deny":["download"],"aceId":"..."}
  ],
  "classification": {"user":1,"object":2,"denied":true}
}
```

---

## 4. API 契约（摘要，完整以 OpenAPI 3.1 为准）

### 4.1 认证

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/v1/auth/login` | `{method:"local"\|"ldap", username, password, captcha}` → 会话或 MFA 挑战 |
| POST | `/v1/auth/ldap/login` | 域登录（不回退本地） |
| POST | `/v1/auth/mfa/verify` | TOTP 或验证码 |
| POST | `/v1/auth/refresh` | 旋转刷新令牌 |
| POST | `/v1/auth/logout` | 会话失效 |
| GET | `/v1/auth/sessions` | 我的设备列表 |
| DELETE | `/v1/auth/sessions/{id}` | 踢下线 |
| POST | `/v1/auth/password/change` | 改密（校验旧密码，踢其他会话） |
| POST | `/v1/auth/password/reset/request` | 发送重置令牌 |
| POST | `/v1/auth/password/reset/confirm` | 消费令牌 |

### 4.2 外部用户与验证码

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/v1/ext/signup` | 邀请令牌换账号（设密码） |
| POST | `/v1/ext/login` | 口令 → 返回 `verify_required` + `ticket` |
| POST | `/v1/ext/verify/send` | `{ticket, channel}` → 发送验证码（限频） |
| POST | `/v1/ext/verify/confirm` | `{ticket, code}` → 签发会话 |
| GET | `/v1/ext/me` | 我的资料/有效期/可访问空间 |
| PATCH | `/v1/ext/me` | 改密/换绑（需双凭证） |

### 4.3 目录与文档

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/v1/spaces` | 我可见的空间 |
| GET | `/v1/nodes?spaceId=&parentId=&cursor=` | 列目录（**`parentId` 缺省=根，不返回全量子树**） |
| POST | `/v1/nodes` | 新建文件夹 |
| GET | `/v1/nodes/{id}` | 详情（含我的权限位） |
| PATCH | `/v1/nodes/{id}` | 改名/属性 |
| POST | `/v1/nodes/{id}/move` | 移动 |
| DELETE | `/v1/nodes/{id}` | 删除到回收站 |
| GET | `/v1/nodes/{id}/versions` | 版本列表 |
| POST | `/v1/nodes/{id}/versions/{vid}/restore` | 回滚 |
| POST | `/v1/nodes/{id}/versions/{vid}/effective` | 设为生效版（需 manage_version） |
| POST | `/v1/uploads` | 初始化（返回已存在分片、是否秒传） |
| PUT | `/v1/uploads/{id}/parts/{n}` | 上传分片 |
| POST | `/v1/uploads/{id}/complete` | 完成（幂等） |
| GET | `/v1/nodes/{id}/content` | 下载（`Range` 支持；校验 download 位） |
| GET | `/v1/nodes/{id}/preview` | 预览（返回渲染副本 URL/流） |
| POST | `/v1/nodes/{id}/editor` | 获取编辑器配置（JWT） |
| POST | `/v1/editor/callback` | 编辑器回调（验签，**非 CSRF 豁免裸端点**） |

### 4.4 权限与分享

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/v1/acl?objectType=&objectId=` | 列出 ACE（含继承来源标记） |
| POST | `/v1/acl` | 新增/更新 ACE（ceiling 校验） |
| DELETE | `/v1/acl/{id}` | 删除 ACE |
| POST | `/v1/acl/break-inherit` | 打断继承 |
| POST | `/v1/acl/restore-inherit` | 恢复继承 |
| GET | `/v1/acl/report` | 权限报告（导出 CSV/XLSX） |
| GET | `/v1/authz/explain` | 权限解释 |
| POST | `/v1/shares` | 创建分享（内部/链接/请求） |
| GET | `/v1/shares` | 分享列表（可筛状态/对象/创建人） |
| POST | `/v1/shares/{id}/revoke` | 撤销 |
| GET | `/v1/shares/{id}/visits` | 访问记录 |

### 4.5 分享访问（对外，免登录）

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/s/{token}` | 分享首页（密码/验证码/直接预览） |
| POST | `/s/{token}/password` | 提交密码 |
| POST | `/s/{token}/verify/send` | 发送验证码到白名单 |
| POST | `/s/{token}/verify/confirm` | 校验 → 换票据 |
| GET | `/s/{token}/view` | 预览页（需票据） |
| GET | `/s/{token}/raw/{ticket}` | 字节流（Range） |
| POST | `/s/{token}/upload` | 上传请求（若允许） |

### 4.6 通知、审计、管理

| 方法 | 路径 | 说明 |
|---|---|---|
| GET/POST | `/v1/admin/mail-channels` | SMTP / Graph 配置 |
| POST | `/v1/admin/mail-channels/{id}/test` | 连通性自检 |
| GET/POST | `/v1/admin/sms-channels` | 短信通道 |
| GET/POST | `/v1/admin/ldap` | 目录配置/测试连接 |
| POST | `/v1/admin/ldap/sync` | 手动触发（可断点续跑） |
| GET | `/v1/admin/ldap/runs` | 同步记录 |
| GET | `/v1/audit/events` | 审计检索 |
| POST | `/v1/audit/export` | 导出证据包（异步） |
| GET | `/v1/admin/settings` | 系统设置（分组） |
| PUT | `/v1/admin/settings` | 修改（校验+审计+可回滚） |
| GET | `/v1/admin/health` | 依赖状态 |
| GET | `/v1/admin/usage` | 用量与配额 |
| POST | `/v1/admin/license` | 导入许可 |

---

## 5. 状态机

### 5.1 分享（share）

```
        created ──(需审批)──► pending_approval ──approved──┐
           │                       │ rejected            │
           │                       ▼                     ▼
           └──(无需审批)────────► active ◄───────────────┘
                                    │
              ┌─────────────────────┼─────────────────────┐
        到期/用尽               手动撤销               对象被删除
              ▼                     ▼                     ▼
          expired               revoked              invalidated
```

**不可逆**：`revoked/expired/invalidated` 不可复活（需新建分享），避免"撤销后又被恢复"的安全争议。

### 5.2 版本（version）

```
draft ──submit──► reviewing ──approve──► effective ──new effective──► superseded
  │                    │                                                  │
  │                    └──reject──► draft                                 │
  └──void──────────────────────────────────────────────────────────► void
```

规则：同一 node 同时只能有 **1 个** `effective`；新版本生效时旧版本自动 `superseded`；`void` 不可恢复。

### 5.3 上传（upload）

```
initiated ──parts──► uploading ──complete──► completing ──verify──► done
     │                   │                        │
     │                   └──cancel──► aborted    └──fail──► failed（可重试）
     └──expire(24h)──► aborted
```

### 5.4 外部用户

```
invited ──accept──► active ──expire/suspend──► suspended
   │                  │                            │
   └──expire(72h)──► expired                  reactivate──► active
                        │
                    delete ──► deleted（身份脱敏，访问记录保留）
```

### 5.5 任务（job）

```
pending ──claim──► running ──ok──► done
   ▲                  │
   │                  ├──retryable──► pending（退避）
   │                  ├──permanent──► dead
   └──stale(30min)────┘
```

---

## 6. 关键算法

### 6.1 就近显式优先的继承解析

```
输入：node.path（ltree，含祖先 id）
1. 取 space 根 ACE（space.id）
2. 取 path 上所有节点的"显式 ACE"（inherit_broken=true 的节点为该子树的新根）
3. 按深度升序排序 → 逐位应用：
   - 若该位在更深层有显式设置 → 覆盖
   - deny 一旦命中即短路（deny 永久优先，不被更深层 allow 覆盖）
4. 合并主体匹配（user/dept 子树/role/group/external/anonymous）
5. 输出位图 + 依据链
```

**性能**：单次查询用一条 SQL 完成（`ltree` + `IN` 主体集合），避免 N+1；结果进缓存（key 含 `subject_version`）。

### 6.2 一次性链接的消费与票据签发

```go
func RedeemShare(ctx, token string, req RedeemReq) (ticket string, err error) {
    h := sha256.Sum256([]byte(token))
    tx := db.Begin()
    // 原子消费：单条语句，不用 SELECT-then-UPDATE
    row := tx.QueryRow(`
        UPDATE share SET used_count = used_count + 1,
                         first_used_at = COALESCE(first_used_at, now())
         WHERE token_hash = $1
           AND revoked_at IS NULL
           AND (expires_at IS NULL OR expires_at > now())
           AND (max_uses IS NULL OR used_count < max_uses)
        RETURNING id, allow_download, watermark, policy_snapshot, object_id`, h)
    // 影响 0 行 → 统一 410
    // 令牌生成（256bit），存 hash；票据 5 分钟
    // 审计 share_visit(action=ticket, result=ok)
    tx.Commit()
    return ticket, nil
}
```

**并发门禁**：`max_uses=1` + 100 并发 → `SELECT count(*) FROM share_visit WHERE share_id=$1 AND action='ticket' AND result='ok'` 必须 = 1。

### 6.3 Office 编辑回调（安全六步）

```
1. 验签：仅接受配置的算法（HS256/RS256），签名为空或算法不符 → 401
2. 重放防护：载荷里的 url 必须与 body.url 完全一致；request_id 存 10 分钟去重表
3. URL 白名单：scheme ∈ {http,https}，host 必须等于配置的 docserver host（含端口）
4. 限长：io.LimitReader(resp.Body, maxFileSize+1MB)；超限中止
5. 对象授权：docID → 解析 tenant/node，校验 sub(编辑器 JWT 内 userID) 有 edit 位
6. 落库：乐观锁（version_no），冲突返回 409 并由前端提示"另存为新版本"
```

### 6.4 HLS 播放签名

```
请求 /v1/nodes/{id}/play → 校验 preview 位 → 返回 master.m3u8 给 player
master.m3u8 内各 variant URL 带 ?t=<ticket>&exp=<ts>&sig=<hmac>
分片请求同样校验 sig；sig = HMAC(secret, path|exp|ip_prefix|user_id)
密钥请求 /v1/media/key/{kid}?t=... → 校验后返回 16 字节 AES key（不缓存到磁盘）
```

- TTL：播放列表 10 分钟，分片 10 分钟（较长视频由 player 自动刷新 master）。
- 防下载：`Content-Disposition: inline`；原始文件端点单独鉴权（默认关闭）。
- 断点续播：前端 localStorage 记录 `nodeId → position`，登录后同步到服务端。

### 6.5 LDAP/AD 同步

```
阶段 1 连接与绑定：LDAPS(636)/StartTLS(389)；bind DN 认证
阶段 2 组织树：搜索 (objectClass=organizationalUnit) → 按 DN 生成 dept 树（幂等 upsert by ldap_dn）
阶段 3 用户全量：分页（AD 用 1000/页 + ranged retrieval）→ upsert by (tenant, ldap_dn)
阶段 4 组：AD 用 tokenGroups 展开（处理嵌套）；通用 LDAP 用递归 member 查询
阶段 5 差异处置：
   - 新增 → 创建（status=active，来源 ldap）
   - 属性变化 → 更新（不改本地覆盖字段：手机号若已本地验证则保留）
   - 消失 → 停用 + 触发离职处置策略
阶段 6 水位：保存 max(uSNChanged) / max(whenChanged) + 同步时间
阶段 7 报告：新增/更新/停用/失败条数 + 耗时 + 错误明细
```

**纪律**：
- 单次同步超 30 分钟自动中止并告警（R5）。
- 同步过程不阻塞登录（域登录走实时 bind，不依赖同步结果）。
- 差异率 > 5% 时**暂停自动停用**，转为待人工确认（防止"目录被误清空导致全员停用"）。

### 6.6 审计链写入

```go
func Append(tx, ev Event) error {
    // 串行化：租户级 advisory lock，避免链头竞争
    tx.Exec(`SELECT pg_advisory_xact_lock(hashtext($1))`, ev.TenantID)
    var prev []byte; var seq int64
    tx.QueryRow(`SELECT hash, seq FROM audit_event WHERE tenant_id=$1 ORDER BY seq DESC LIMIT 1`).
        Scan(&prev, &seq)          // sql.ErrNoRows → 创世
    ev.Seq = seq + 1
    ev.PrevHash = prev
    body := canonicalJSON(ev)      // 键排序、时间微秒截断、浮点禁用
    ev.Hash = sha256(prev || body)
    return tx.Insert(ev)           // 失败向上返回 → 业务回滚
}
```

**日结**：`daily_root(tenant, date, first_seq, last_seq, merkle_root, prev_root, signature)`；离线校验工具用同一 canonical 规则重算。

---

## 7. 前端设计

### 7.1 路由（每个菜单独立 URL，刷新不丢位置）

| 路由 | 页面 | URL 承载状态 |
|---|---|---|
| `/` | 工作台（待办/最近/分享） | — |
| `/files` | 我的文件（个人空间根） | `?tab=&sort=` |
| `/spaces/:spaceId/nodes/:nodeId?` | 空间浏览（面包屑/点进） | 路径参数 + `?view=list\|grid&sort=&q=` |
| `/files/:nodeId` | 文件详情（预览/版本/权限/审计） | `?tab=preview\|versions\|acl\|activity` |
| `/shared-with-me` | 与我共享 | `?page=&sort=` |
| `/shares` | 我的分享 | `?status=&objectId=&q=` |
| `/trash` | 回收站 | `?spaceId=` |
| `/search` | 搜索 | `?q=&type=&from=&to=&space=&tag=` |
| `/approvals` | 审批中心 | `?status=` |
| `/admin/*` | 管理控制台（分组） | 子路由如 `/admin/users`、`/admin/ldap`、`/admin/mail`、`/admin/policy`、`/admin/audit` |
| `/s/:token` | 分享访问页（独立布局，白标） | — |
| `/403` `/404` `/500` | 兜底页 | — |

**纪律**
1. 所有筛选/分页/排序/选项卡同步到查询参数（含非法值回落）。
2. 登录后回跳 `redirect`（校验同源，防开放重定向）。
3. 前进/后退可用；表单提交后 `replace` 而非 `push`（防重复提交）。
4. 详情页必须有资源 ID 在 URL。
5. 404/403/500 兜底，不白屏。

### 7.2 页面状态四态

每个数据区块必须实现：`loading`（骨架屏）、`empty`（区分"无数据"与"筛选无结果"，带下一步动作）、`error`（可读文案 + 重试）、`partial`（批量操作逐条结果）。

### 7.3 关键交互

| 场景 | 要求 |
|---|---|
| 上传 | 进度、速率、剩余时间、可取消、失败重试（断点）；拖拽到目录行即落该目录 |
| 批量操作 | 选中态在 URL（`?sel=`）或 store 且返回时保留；上限 500；结果面板逐条 |
| 权限矩阵 | 勾选即时预览"影响面"；保存前后显示 diff |
| 分享创建 | 一屏配完（对象/有效期/密码/次数/权限/水印/验证）；生成后一键复制**绝对 URL** |
| 预览 | 全屏、缩放、翻页快捷键、水印叠加；Office 预览失败降级为下载 |
| 编辑器 | iframe 绝对像素高度；`minHeight:0` + flex；退出前提示未保存 |
| 外部分享页 | 移动端优先；不显示系统导航；品牌 Logo 由租户配置 |
| 表格 | 列宽可调、排序持久、超长文本省略 + tooltip |

### 7.4 视觉与可访问性

- 设计令牌统一（间距/圆角/字号/色板），禁止页面级硬编码像素。
- 对比度 ≥ 4.5:1；状态双通道（色 + 图标/文字）。
- 键盘可达；`aria-label`；弹窗焦点锁定与 `Esc` 关闭。
- 深色模式、200% 缩放、长文案（中/英）不破版。

---

## 8. 通知规格

### 8.1 模板清单（一期 18 个）

| code | 场景 | 通道 | 变量 |
|---|---|---|---|
| `share.created` | 分享创建（给收件人） | email/sms | 分享人、对象名、链接、有效期、密码（分开发送） |
| `share.verify_code` | 分享访问验证码 | email/sms | code、ttl |
| `share.accessed` | 分享被访问（给创建人） | email/inapp | 访问者、时间、IP |
| `share.expiring` | 到期前 1 天 | email/inapp | 到期时间 |
| `share.revoked` | 已撤销 | inapp | — |
| `user.invite` | 外部用户邀请 | email/sms | 邀请链接、有效期 |
| `user.verify_code` | 登录验证码 | email/sms | code、ttl |
| `pwd.reset` | 重置密码 | email/sms | 链接、ttl |
| `approval.todo` | 审批待办 | email/inapp | 对象、申请人、链接 |
| `approval.result` | 审批结果 | email/inapp | 结果、意见 |
| `upload.completed` | 大文件/打包下载完成 | inapp | 下载链接（24h） |
| `media.ready` / `media.failed` | 转码完成/失败 | inapp | 对象、原因 |
| `ldap.sync_failed` | 目录同步失败 | email/inapp | 错误摘要 |
| `security.login_anomaly` | 异常登录 | email/inapp | 地点、设备 |
| `acl.changed` | 权限变更（给被授权人/所有者） | email/inapp | 变更摘要 |
| `quota.warning` | 存储 85%/95% | email/inapp | 用量 |
| `license.expiring` | 许可 30 天内到期 | email/inapp | 到期日 |

### 8.2 幂等与重试

- `idempotency_key = sha256(template_code|object_id|recipient|day_bucket)`。
- 重试：1m → 5m → 15m → 1h → 4h，5 次后 `dead` + 告警。
- 验证码类**不重试**（重发由用户触发），但受频率限制。

---

## 9. 系统设置项（节选，完整 ≥ 90 项）

| 分组 | 键 | 默认 | 说明 |
|---|---|---|---|
| 安全 | `auth.password.min_length` | 12 | 密码最小长度 |
| 安全 | `auth.login.max_fail` | 5 | 失败锁定阈值 |
| 安全 | `auth.session.access_ttl` | 15m | 访问令牌 TTL |
| 安全 | `auth.session.refresh_ttl` | 30d | 刷新令牌 TTL |
| 安全 | `auth.trust_proxy_cidrs` | `[]` | **空=不信任 XFF** |
| 安全 | `auth.mfa.enforce_roles` | `[]` | 强制 MFA 的角色 |
| 分享 | `share.max_expiry_days` | 30 | 最长有效期 |
| 分享 | `share.password.min_length` | 8 | 分享密码强度 |
| 分享 | `share.allow_anonymous` | true | 是否允许免登录链接 |
| 分享 | `share.watermark.default` | true | 默认加水印 |
| 分享 | `share.require_approval.class_gte` | 2 | 密级≥2 需审批 |
| 外部用户 | `ext.verify.channel` | `email` | email/sms/both |
| 外部用户 | `ext.verify.code_ttl` | 5m | 验证码有效期 |
| 外部用户 | `ext.verify.max_attempts` | 5 | 校验次数上限 |
| 外部用户 | `ext.trusted_device_days` | 30 | 可信设备豁免期 |
| 外部用户 | `ext.default_expiry_days` | 90 | 账号默认有效期 |
| 上传 | `upload.max_file_size` | 10GB | 单文件上限 |
| 上传 | `upload.part_size` | 8MB | 分片大小 |
| 上传 | `upload.allowed_ext` | 白名单 | 允许扩展名 |
| 预览 | `preview.cache_ttl_days` | 30 | 渲染副本保留 |
| 媒体 | `media.transcode.concurrency` | cores/2 | 并发转码 |
| 媒体 | `media.max_duration_hours` | 4 | 单文件时长上限 |
| 媒体 | `media.keep_original` | true | 转码后保留原片 |
| 存储 | `storage.recycle_retention_days` | 30 | 回收站保留 |
| 存储 | `storage.version_retention` | 50 | 版本数上限 |
| 审计 | `audit.retention_days` | 180 | 审计保留 |
| 审计 | `audit.fail_closed` | true | 审计失败即拒绝（**不建议关闭**） |
| 通知 | `notify.email.channel` | `smtp` | `smtp`/`graph` |
| 通知 | `notify.fallback_channel` | `smtp` | 主通道失败备用 |
| 许可 | `license.enforce` | true | 超限行为 |

**纪律**：所有设置项必须①有默认值 ②有范围校验 ③变更进审计（旧值/新值）④可回滚 ⑤前端可见可改（除"仅离线"项如系统密级降级）。

---

## 10. 越权与安全用例（验收门禁，≥ 60 条，节选 24）

| # | 用例 | 预期 |
|---|---|---|
| AC-01 | 用户 A 直接请求 B 的 node ID | 404 |
| AC-02 | A 用自己 token 请求他租户对象 | 404 |
| AC-03 | 只读用户调用 PATCH /nodes/{id} | 403 |
| AC-04 | editor 授出 owner 档位 | 403 CEILING_EXCEEDED + 审计 |
| AC-05 | 部门子目录 deny download，经理仍能下载 | 403（deny 优先） |
| AC-06 | 用户密级 1 访问密级 2 文件（ACL 全开） | 403 CLASSIFICATION_DENIED |
| AC-07 | 系统密级尝试降级 | 403/仅离线工具可执行 |
| AC-08 | 分享撤销后立即访问 | 410 |
| AC-09 | 一次性链接第 2 次访问 | 410 |
| AC-10 | 一次性链接 100 并发 | 成功 1 次，其余 410 |
| AC-11 | 分享 token 猜解（枚举 hint） | 不可用；限流生效 |
| AC-12 | 非白名单邮箱访问白名单分享 | 403 且审计 |
| AC-13 | 外部用户访问未授权空间 | 404 |
| AC-14 | 外部用户注销后旧会话 | 401 |
| AC-15 | 伪造 XFF 绕过 ip_cidr 条件 | 拒绝（未配置可信代理） |
| AC-16 | Office 回调伪造 JWT | 401 |
| AC-17 | Office 回调 url 指向内网 | 400（白名单外） |
| AC-18 | Office 回调 docID 为他租户 | 403 |
| AC-19 | 上传 .php 改名为 .jpg（双扩展名） | 拒绝 |
| AC-20 | SVG 含 script 预览 | 净化后渲染，无脚本执行 |
| AC-21 | 搜索命中无权对象 | 不出现在结果中 |
| AC-22 | 批量下载含 1 个无权对象 | 整体 403（不部分放行） |
| AC-23 | 审计表 UPDATE/DELETE | 无效/报错 |
| AC-24 | 新增表未加 RLS 后启动 | 启动失败并列出表名 |

---

## 11. 迁移与排障工具（`dvctl`）

| 命令 | 用途 |
|---|---|
| `dvctl migrate` | 执行迁移（仅 server/部署时） |
| `dvctl doctor` | 全量自检（配置/迁移/RLS/依赖/字体/许可） |
| `dvctl reset-password --user` | 应急重置（强审计 + 需二次确认） |
| `dvctl verify-audit --from --to` | 校验审计链 |
| `dvctl export-evidence --tenant --range` | 导出证据包 |
| `dvctl backup / restore` | 备份与恢复（含演练模式） |
| `dvctl reindex-preview` | 重建预览缓存（换字体/转换器后） |
| `dvctl classification-downgrade` | 系统密级降级（双人确认 + 离线） |

---

## 12. 交付物清单

| # | 交付物 | 说明 |
|---|---|---|
| 1 | `docker-compose.yml` + `.env.example` | 单机一键部署 |
| 2 | `install.sh` | 生成密钥/初始化/健康检查/打印初始口令 |
| 3 | Helm Chart | SaaS 部署 |
| 4 | 迁移脚本 | 版本化、可重放 |
| 5 | OpenAPI 3.1 | 与实现契约比对 |
| 6 | SBOM + 许可清单 | 法务交付 |
| 7 | 等保三级自查表 | 逐条对应实现 |
| 8 | 运维手册 | 备份/恢复/扩容/排障/日志 |
| 9 | 种子数据脚本 | demo 租户 + 可复现演示 |
| 10 | E2E 与越权用例集 | 可 CI 执行 |

---

## 13. 变更记录

| 版本 | 日期 | 变更 |
|---|---|---|
| v1.0 | 2026-11-08 | 首版。确定 15 位权限 + 6 档位 + 条件表达式；分享两段式票据与原子消费；Office 回调六步；HLS 签名播放；LDAP 七阶段同步；审计链写入范式 |
