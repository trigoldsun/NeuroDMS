# 系统架构设计（SAD）v1.0

- 产品：DocVault ｜ 版本：v1.0 ｜ 日期：2026-11-08 ｜ 状态：**待评审**
- 上游：01-BRD、02-PRD ｜ 下游：04-FSD
- 本文回答四个问题：**长什么样（视图）、为什么这样选（决策）、哪里会坏（风险）、怎么长（扩展）**

---

## 1. 架构原则

### 1.1 六条不可让渡的原则

| # | 原则 | 具体含义 | 违反后果 |
|---|---|---|---|
| P1 | **fail-closed** | 权限、审计、隔离任何一环出错，一律拒绝而非放行 | 一次降级放行 = 一次数据泄露 |
| P2 | **判定与数据同源** | 权限判定在数据库同一事务内完成，不依赖应用层缓存作为唯一依据 | 缓存过期窗口 = 越权窗口 |
| P3 | **双层隔离** | 应用层强制 `tenant_id` + 数据库 RLS，两道都过才放行 | 单层漏一处即跨租户 |
| P4 | **字节流只认票据** | 文件流不认长期凭证，只认短 TTL 票据 | 链接泄漏 = 长期可访问 |
| P5 | **不可变事实** | 审计、版本、访问记录只追加不修改 | 举证能力归零 |
| P6 | **单机可跑，集群可扩** | 同一镜像、同一迁移集；形态由配置决定，不由代码分支决定 | 私有化与 SaaS 分叉 = 双倍维护 |

### 1.2 从上一版继承的硬纪律（负面清单转化）

| 来源缺陷 | 架构级对策 | 落点 |
|---|---|---|
| C1 Office 回调无验签 → SSRF + 任意写入 | 编辑器回调必经 `callbackguard`（验签 + URL 白名单 + 限长 + 对象授权），且**不注册为 CSRF 豁免的裸端点** | §6.4 |
| C2 无条件信任 XFF | 单一 `clientip` 组件；默认只用 RemoteAddr；仅当 `trust_proxy_cidrs` 明确配置才解析 XFF | §11.2 |
| C3 权限查询失败降级放行 | `authorize()` 返回 `(decision, error)`，error 非空即 deny；全链路禁止 `if err != nil { return nil }` | §5.3 |
| C4 多进程各自建表导致迁移链断裂 | **迁移单一所有者**：只有 `docvault-server` 执行迁移；worker 只做启动断言，禁止 DDL | §9.2 |
| C5 SIGTERM 使任务卡死 | 任务使用独立 ctx；`Fail/Done` 用 `context.WithoutCancel`；`locked_at` 超时回收 | §9.3 |
| M8 一次性令牌 SELECT-then-UPDATE 可重放 | 原子消费 SQL + 两段式票据 | §7.4 |
| M9 版本号 max+1 并发 500 | 版本号由 `UNIQUE(doc_id, version_no)` + 重试，或序列生成 | FSD §7.3 |

### 1.3 被否决的架构选择

| 被否决 | 理由 |
|---|---|
| 微服务拆分（10+ 服务） | 私有化单机交付必须简单；网络调用会把"权限判定 20ms"变成 200ms；一期用模块化单体 + 独立 worker |
| 自研 Web Office | 工程量以年计，格式兼容永远追不上；工程资源应投在权限与分享 |
| 把权限放 Redis 做主判断 | 违背 P2；Redis 只做**缓存**，且必须能被旁路验证 |
| 每个对象存一张权限矩阵 | 不可维护、不可审计；界面矩阵与存储规范化分离 |
| 用 `tenant_id` 过滤器代替 RLS | 一处忘写 WHERE 即跨租户；RLS 是第二道保险 |
| 文件直读本地磁盘目录 | 无法水平扩展、无法接对象存储、无法做去重与生命周期 |
| 分享链接直接返回文件 URL | 违背 P4；必须走票据 |

---

## 2. 系统上下文（C4-L1）

```
        ┌──────────┐   ┌──────────┐   ┌──────────┐   ┌──────────┐
        │ 内部员工 │   │ 外部客户 │   │ 管理员   │   │ 集成系统 │
        └────┬─────┘   └────┬─────┘   └────┬─────┘   └────┬─────┘
             │              │              │              │
             └──────────────┴──────┬───────┴──────────────┘
                                   ▼
                        ┌─────────────────────┐
                        │      DocVault       │
                        └──┬────┬────┬────┬───┘
                           │    │    │    │
        ┌──────────────────┘    │    │    └───────────────────┐
        ▼                       ▼    ▼                        ▼
┌───────────────┐   ┌────────────────────┐   ┌──────────────────────┐
│ 企业目录      │   │ 邮件/短信          │   │ 对象存储             │
│ AD / LDAP     │   │ SMTP / Graph API   │   │ 本地FS/MinIO/S3/OSS  │
│ (认证+组织)   │   │ 阿里云/腾讯云 SMS   │   │ (内容+转码产物)      │
└───────────────┘   └────────────────────┘   └──────────────────────┘
        │
        ▼
┌───────────────┐   ┌────────────────────┐
│ ONLYOFFICE    │   │ 可观测性           │
│ Docs（编辑）  │   │ Prometheus/Loki    │
└───────────────┘   └────────────────────┘
```

**外部依赖清单与失败影响**

| 依赖 | 必需性 | 不可用时的影响 | 降级策略 |
|---|---|---|---|
| PostgreSQL | 必需 | 全站不可用 | 无（主库） |
| 对象存储 | 必需 | 无法上传/下载/预览 | 无（本地 FS 为兜底后端） |
| Redis | 可选 | 缓存失效、限流失效 | 降级为进程内缓存 + DB 限流（性能下降，功能可用） |
| ONLYOFFICE | 可选 | 无法在线编辑 | 自动降级为预览 |
| SMTP/Graph | 可选 | 无法发邮件 | 站内通知兜底；队列重试；死信告警 |
| SMS | 可选 | 外部用户无法收短信码 | 自动切邮件验证码（若策略允许） |
| LDAP/AD | 可选 | 域用户无法登录 | 应急管理员本地登录 + P1 告警 |

**关键设计**：所有可选依赖都必须有"降级路径"，且降级状态在界面上可见（不允许"静默坏掉"）。

---

## 3. 容器视图（C4-L2）

### 3.1 容器清单（单机形态：8 个）

| # | 容器 | 职责 | 必需 | 资源（8C16G 参考） |
|---|---|---|:--:|---|
| 1 | `docvault-gateway` | 反向代理、TLS 终止、静态资源、安全响应头 | 是 | 0.5C / 256M |
| 2 | `docvault-server` | API + 认证 + 权限 + 业务 + 内嵌前端 + 迁移所有者 | 是 | 4C / 4G |
| 3 | `docvault-worker` | 预览转换、音视频转码、邮件/短信发送、LDAP 同步、审计日结、清理 | 是 | 2C / 2G（转码另计） |
| 4 | `docvault-postgres` | 元数据、权限、审计 | 是 | 2C / 4G |
| 5 | `docvault-redis` | 缓存、限流、队列（轻量）、会话黑名单 | 否 | 0.5C / 512M |
| 6 | `docvault-minio` | 对象存储（也可外挂 S3/OSS） | 否 | 1C / 1G |
| 7 | `docvault-onlyoffice` | 在线编辑 | 否 | 2C / 4G |
| 8 | `docvault-convert` | LibreOffice + ffmpeg + 字体（转换执行器，被 worker 调起） | 否 | 按需 |

> 设计说明：`worker` 与 `convert` 分离，是为了让"重 CPU 且不可信输入"的转换进程与"可访问数据库与密钥"的进程隔离。worker 只传文件句柄/临时路径，convert 无 DB 凭据、无对象存储密钥，仅挂载一个临时卷。

### 3.2 为什么不把 worker 拆成微服务

- 私有化交付要求"最少容器、最少端口、最少运维动作"。
- worker 的负载是**批处理型**，横向扩展靠"多副本 + 队列抢占"，不需要独立服务网格。
- 拆分收益（独立发布）在单产品阶段不存在，成本（分布式事务、链路追踪、配置同步）立刻产生。

**何时才拆**：单租户文档数 > 500 万 或 转码并发 > 8 路 时，把 `transcode` 独立为可弹性伸缩的独立部署单元（不改代码，只改编排）。

### 3.3 请求链路（同步主链路）

```
浏览器
  │ HTTPS
  ▼
gateway ──► 安全头 / 限流(粗) / 静态资源
  │
  ▼
server ──► requestid → recover → accesslog → authn(会话/APIKey) 
        ──► tenantctx(设置 tenant_id, SET LOCAL app.tenant_id)
        ──► csrf → ratelimit(细) → handler
                                │
                                ├─► authorize(对象级)   ← 权限引擎（同事务）
                                ├─► biz logic
                                ├─► audit.Append()      ← 同事务，失败即回滚
                                └─► response(统一信封)
```

**时序纪律**：`authorize` 必须在任何数据读取**之前**或**与之同事务**；不允许"先查出来再判断能不能返回"（这正是 M2 的成因）。

### 3.4 异步链路

```
server ──INSERT job_queue──► (提交即返回)
                                 │
                            worker.Claim (FOR UPDATE SKIP LOCKED)
                                 │
                    ┌────────────┼────────────┬─────────────┐
                    ▼            ▼            ▼             ▼
                 preview      transcode     notify      ldap_sync
                 (LO→PDF)     (ffmpeg→HLS)  (SMTP/Graph) (bind+diff)
                    │            │            │             │
                    └────────────┴─────┬──────┴─────────────┘
                                       ▼
                              job_attempt 记录 / 退避重试 / 死信
```

---

## 4. 技术选型

### 4.1 版本基线（已核实项标 ✔，其余须在编码前按官方下载页锁定）

| 层 | 选型 | 版本 | 核实 |
|---|---|---|:--:|
| 后端语言 | Go | **1.27.3**（2026-10-19 发布） | ✔ go.dev/doc/devel/release |
| HTTP 框架 | chi v5（标准库 `net/http` 生态） | 最新稳定 | — |
| 数据库驱动 | pgx v5（原生协议、批量、COPY） | 最新稳定 | — |
| 数据库 | PostgreSQL | **18.6**（当前 minor，19 仍为 beta，不采用） | ✔ postgresql.org/support/versioning |
| 缓存/限流 | Redis（或 Valkey 兼容） | 最新稳定 | — |
| 对象存储 | MinIO（S3 兼容）/ S3 / OSS / 本地 FS | 最新稳定 | — |
| 在线编辑 | ONLYOFFICE Docs | **10.0**（2026-10 发布，JWT 默认启用） | ✔ onlyoffice.com |
| 文档转换 | LibreOffice（headless） | 最新稳定 | — |
| 音视频 | ffmpeg / ffprobe | 最新稳定 | — |
| 前端框架 | React + TypeScript | React 19 / TS 7.x | — |
| 构建 | Vite | 最新稳定 | — |
| UI 组件 | Ant Design | 最新稳定（v5/v6 以官方为准） | — |
| 播放器 | hls.js | 最新稳定 | — |
| PDF | PDF.js | 最新稳定 | — |
| 反向代理 | Nginx | 最新稳定 | — |
| 可观测 | OpenTelemetry + Prometheus + Grafana + Loki | 最新稳定 | — |
| 编排 | Docker Compose（单机）/ Helm（SaaS） | 最新稳定 | — |

**版本纪律**：所有版本写入 `docs/versions.lock.md` 并附"官方下载页 URL + 核实日期"；禁止使用 beta/RC/已 EOL 版本。CI 增加"依赖 EOL 检查"。

### 4.2 选型理由（只写有争议的）

| 决策 | 备选 | 为什么选它 |
|---|---|---|
| Go 而非 Python | FastAPI | 文件流式传输、零拷贝 sendfile、低内存、单二进制内嵌前端——私有化交付与高并发下载是核心场景 |
| chi 而非 Gin/Echo | Gin/Echo | 只依赖标准库 `net/http`，中间件链显式、无隐式绑定；长期维护风险最低；性能差异在本场景不显著 |
| pgx 而非 database/sql | lib/pq | 原生协议 + `COPY` + 批量 + 类型支持完整；`pq.Array` 类问题不再出现 |
| PostgreSQL 而非 MySQL | MySQL | RLS（多租户第二道保险）、JSONB、ltree（目录树）、分区、`gen_random_uuid`、全文检索可扩展 |
| 模块化单体 | 微服务 | 见 §3.2 |
| MinIO 而非直接 FS | 直接 FS | 内容寻址 + 生命周期 + 版本 + 可替换为云对象存储；本地 FS 仍作为最轻量后端支持（单机小客户） |
| ONLYOFFICE 而非 Collabora | Collabora | 中文/复杂表格渲染更稳，社区文档与连接器更成熟；两者都通过 `EditorProvider` 可替换 |
| React 而非 Vue | Vue | 与后端契约生成的类型工具链（openapi-typescript）配合更顺；团队可替换，架构上不构成约束 |

### 4.3 关键第三方约束

| 组件 | 许可 | 约束 |
|---|---|---|
| ONLYOFFICE Docs CE | AGPLv3 | 私有化：独立进程 + HTTP 调用（聚合），可接受（仍需法务确认）；**SaaS 对外销售必须购商业授权**，否则关闭编辑 |
| PostgreSQL | PostgreSQL License | 无约束 |
| MinIO | AGPLv3 | 作为独立服务进程使用；若嵌入分发需评估 |
| LibreOffice | MPL 2.0 | 独立进程调用，无约束 |
| ffmpeg | LGPL/GPL（取决于编译选项） | **必须用 LGPL 构建**（不含 `--enable-gpl`），避免分发风险 |

> 出 SBOM（`syft`）+ 许可清单，作为交付物之一。R1 风险（许可成本）在此显式登记。

---

## 5. 权限引擎架构（核心）

### 5.1 判定输入（五维）

```
Decision = f(Subject, Object, Action, Classification, Conditions)

Subject      : {user_id, dept_paths[], role_ids[], group_ids[], is_external, is_anonymous, ceiling_level}
Object       : {node_id, space_id, path(ltree), owner_id, classification, inherit_broken, tags[]}
Action       : 15 个原子位之一（含蕴含归一化）
Classification: 用户密级 vs 文件密级 vs 系统密级（MAC 门，先于 ACL）
Conditions   : {time_window, ip_cidr, device_trust, mfa_satisfied, download_quota,
                approval_state, watermark_required, share_expiry_max}
```

### 5.2 判定顺序（固定，不可调换）

```
1. 租户校验        tenant_id 必须匹配，否则 404（不泄漏存在性）
2. 主体有效性      is_active / 会话有效 / 未锁定
3. 对象存在性      不存在或已删除 → 404
4. 密级强制门      user_class < file_class → DENY（MAC，ACL 不可覆盖）
5. 显式拒绝        任一匹配主体的 deny 位命中 → DENY（deny 优先，含继承链）
6. 允许集合        收集所有匹配 ACE 的 allow 位（就近显式 > 继承；同层取并集）
7. 条件求值        允许位上的条件全部满足才保留该位
8. 蕴涵归一化      download⇒preview⇒display 补齐，保证不自相矛盾
   （注：ceiling 不在判定链内，只作用于授权路径，见 FSD §3.4）
10. 结果 + 依据链  返回 {allowed[], denied_by, reason_chain[]}（用于解释与审计）
```

**为什么密级在 ACL 之前**：ACL 是"可以给"，密级是"不允许给"。顺序反了会出现"某管理员给自己授权就绕过密级"。

### 5.3 存储与性能

- **ACE 表规范化**：`ace(id, tenant_id, object_id, subject_type, subject_id, allow_bits bigint, deny_bits bigint, conditions jsonb, inherited_from, expires_at, granted_by, created_at)`。
- `allow_bits/deny_bits` 用 `bigint` 位图（15 位），一次读取即可判定，避免 N 行权限项。
- **目录树用 `ltree`**：`nodes.path`，权限继承查询 `WHERE path @> $1` 走 GiST 索引。
- **两级缓存**：
  - L1：进程内 LRU（key = subject_version + object_id + action），TTL 30s，**subject_version 在权限变更时自增**（保证即时失效）。
  - L2：Redis（可选），TTL 60s，同样以 subject_version 为键前缀。
- **缓存不是信任基础**：缓存未命中或异常 → 走数据库；数据库异常 → **DENY**（P1）。
- 目标性能：单对象判定 P95 ≤ 20ms（含缓存），冷路径 ≤ 60ms。

### 5.4 授权侧的防越权

| 风险 | 对策 |
|---|---|
| 低权限用户授出高权限 | ceiling 钳制：`granted_bits ⊆ requester.ceiling`，越界 403 + 审计 |
| 通过"分享"绕过 ACL | 分享创建时校验 `share_internal/share_external` 位 + 密级 + 策略；分享不能授出超过创建者自身能力的权限 |
| 通过"移动节点"继承到更高权限 | 移动需源 `delete` + 目标 `create`，且移动后重新评估（不允许"移动即继承"） |
| 通过"标签授权"提权 | 标签策略只做 allow 补充，**永不覆盖显式 deny**，且策略有独立的管理权限 |
| 匿名主体被滥用 | 匿名 ACE 只能由分享策略生成，禁止手工创建（PRD-ACL-18） |

### 5.5 权限健康度（可解释性产出）

定期（每日）计算：孤儿授权、超档位授权、90 天未访问的显式授权、对外暴露面（匿名/外部主体可访问的对象数）、密级冲突（高密级文件在低密级空间中）。输出报告 + 评分，作为交付物与续费话术。

---

## 6. 内容与存储架构

### 6.1 三层模型

```
节点（node）      逻辑对象：目录/文件，有名称、路径、权限、标签
  └─ 版本（version）  某次内容快照：version_no、size、hash、状态、创建人
       └─ 内容（blob）  内容寻址：blob_id = sha256(content)[:32]，全局唯一
```

**收益**：同一文件多版本、多副本、多租户重复上传都只存一份（去重）；版本只是指向 blob；回收站只是标记。

### 6.2 上传流水线

```
1. 客户端计算文件 sha256（分片前整体或分片级）
2. POST /v1/uploads        → 返回 upload_id + 已存在分片 + 是否可秒传
3. 秒传判定：blob 存在且 size 一致 → 直接建 version（必须服务端 stat 实际大小，不采信客户端）
4. PUT /v1/uploads/{id}/parts/{n}   分片直传（可直传对象存储，用预签名 URL）
5. POST /v1/uploads/{id}/complete   服务端校验分片完整性（hash 树）→ 合并 → 入队病毒扫描
6. 扫描通过 → 状态 active；不通过 → quarantined（隔离区，仅管理员可见）
7. 入队预览生成任务
```

**并发正确性**：`complete` 必须幂等（`upload_id` 唯一约束 + 状态机 `uploading→completing→done`），重复调用返回同一结果而非重复建版本（对应上一版 M9）。

### 6.3 加密与密钥

| 层 | 方案 |
|---|---|
| 传输 | TLS 1.2+（强制），HSTS |
| 静态（对象） | 信封加密：每对象随机 DEK（AES-256-GCM），DEK 用租户 KEK 包裹，KEK 存 KMS/本地密钥文件（可配外部 KMS） |
| 静态（DB） | 磁盘/表空间级加密（部署层）+ 敏感字段列级加密（手机号、API Key、SMTP 密码） |
| 密钥轮换 | KEK 支持多版本，轮换时只重包 DEK，不重写内容 |
| 水印 | 在服务端渲染副本上叠加（不修改原件），含查看人/时间/IP |

### 6.4 预览与编辑流水线

```
预览：blob → (缓存命中?) → 是：直接返回
                        → 否：worker 调 convert(LibreOffice headless) → PDF + 首页缩略图
                              → 存为 derived blob（key: hash+renderer_version）
                              → 返回
编辑：server 生成 JWT 配置 → 前端 iframe 加载 ONLYOFFICE
      → 编辑保存回调 → callbackguard（验签+白名单+限长+对象授权）→ 拉取新内容 → 建新版本
```

**`renderer_version` 入 key**：字体或转换器升级后可整体失效缓存，避免"旧样式永远被缓存"。

**字体**：`convert` 镜像内预装思源黑体/宋体、Liberation、Carlito/Caladea（与 Office 度量兼容），并做字体渲染自检（渲染一份含中文+表格的基准文件，比对像素差异阈值）——把"变形"变成可自动发现的缺陷。

#### 6.4.1 为什么预览与编辑用两个引擎（G1 追加说明）

结论：**是分工，不是重复；且可配置为单引擎。**

| 维度 | 预览链路（LibreOffice） | 编辑链路（ONLYOFFICE） |
|---|---|---|
| 频次 | 高频，约占文档访问 90% | 低频，仅"要改"时进入 |
| 资源模型 | 一次性转换 + 结果缓存（按 `hash+renderer_version` 复用） | 持续会话，占用并发连接 |
| 成本 | MPL-2.0，无按连接计费 | CE 为 AGPLv3；SaaS 需商业授权，按并发计费 |
| 不可信输入 | 承接全部畸形文件，容器**无网络、无凭据、只读根** | 必须持有 JWT 密钥、可回连 API 拉取与写回，暴露面更大 |
| 首屏 | PDF.js ≤1s（缓存命中） | 编辑器就绪约 6s 量级 |
| 故障影响 | 自身故障仅影响新文件预览 | 自身故障不影响预览，仅降级为只读 |

**关键商业含义**：正因为预览不依赖 ONLYOFFICE，BRD §6.2 的"SaaS 仅预览降级档"才成立——否则降级档也逃不掉 ONLYOFFICE 授权成本。

**可配置项**：
```yaml
preview:
  engine: libreoffice      # libreoffice | onlyoffice
editor:
  enabled: true            # false 时系统仅提供预览（SaaS 无商业授权时的合规形态）
  provider: onlyoffice
```

**代价（必须承认）**：镜像体积增加（LibreOffice + 字体约 1GB 量级）；两处都要装同一套字体，否则会出现"预览是宋体、编辑是黑体"的割裂；同一份 docx 在两条链路的渲染会有细微差异，因此格式回归测试必须同时覆盖预览与编辑器。

### 6.5 音视频流水线

```
上传 → ffprobe 探测（时长/分辨率/编码/音轨）
     → 决策：是否需要转码（源已是 H.264/AAC 且分辨率达标 → 可直接封装为 HLS，省算力）
     → ffmpeg 生成多码率 fMP4 分片 + AES-128 加密（key 由服务端保管）
     → 生成 master.m3u8
     → 存为 derived（不覆盖原件）
     → 任务完成通知
播放 → 校验票据 → 返回签名 master.m3u8 → 播放器按码率拉分片（分片 URL 签名，TTL 10min）
```

**资源护栏**：转码并发上限（默认 = CPU 核数/2）、单任务 CPU 权重、队列优先级（小文件/短视频优先）、单文件上限（4h/20GB）、失败 3 次进死信。

#### 6.5.1 体验优先的具体设计（G1 决策：以用户体验最佳为优先）

"体验优先"不等于"直出原片"——直出原片会让用户遇到不能拖拽、卡顿、清晰度不可控；也不等于"上传即阻塞转码"——那会让用户对着进度条等。因此三条设计同时成立：

| 用户感知 | 机制 | 代价 |
|---|---|---|
| 打开即见画面 | 上传完成立即用首帧生成封面（`ffmpeg -ss 0 -vframes 1`），播放页先展示封面 + 播放按钮，**不等转码完成** | 封面生成约 1–2s，可忽略 |
| 点了就能播 | 优先级队列：正在被访问的视频插队转码；未访问过的空闲时批量转 | 队列调度复杂度 |
| 弱网不卡、强网不糊 | 多码率自适应（360/720/1080），播放器按实时带宽切换 | 存储 ×1.5–2 |
| 拖动立即响应 | fMP4 分片 + `#EXT-X-INDEPENDENT-SEGMENTS`，每片 2s；关键帧对齐 | 分片数增多，元数据变大 |
| 源片已达标不等待 | 探测到 H.264/AAC 且分辨率 ≤ 目标档位 → **remux 直封装**（秒级，不重编码） | 需精确探测，误判会劣化画质 |
| 转码失败不空白 | 失败时自动降级为"原片流式播放（同容器可播时）"+ 明确提示 | 多一条降级分支 |

**判定顺序**（服务端）：`可直接播放？` → remux；`源分辨率达标但编码不兼容？` → 单档转码；`否则` → 全档转码。三者都生成同一 `master.m3u8` 结构，播放器无感知。

---

## 7. 分享与票据架构（差异化核心）

### 7.1 两段式凭证

```
链接 token（长期，仅存哈希）
    │  ① 换取（原子消费）
    ▼
分享票据 share_ticket（短 TTL ≤ 5min，JWT 或服务端随机串）
    │  ② 校验
    ▼
字节流（range 请求、预览渲染、HLS 分片）
```

| 凭证 | 存储 | TTL | 可重用 | 绑定 |
|---|---|---|---|---|
| `share.token` | `sha256` 哈希 | 至 `expires_at` | 是（受 `max_uses` 约束） | 无 |
| `share_ticket` | 服务端表 / 签名 JWT | ≤ 5 分钟 | 是（TTL 内） | share_id + 收件人 + IP 段 + 权限位 |

### 7.2 访问流程（含双重认证）

```
GET /s/{token}
  ├─ token 不存在/已撤销/已过期 → 统一失效页（404 语义，不区分原因）
  ├─ 需要密码？ → 密码页（错误 5 次锁定 30min）
  ├─ 需要验证码？ → 发送到白名单邮箱/手机 → 校验（单次消费）
  ├─ 原子消费（max_uses / expires 检查）
  ├─ 签发 ticket → 302 到 /s/{token}/view?t={ticket}
  └─ 审计：share.open（含 IP/UA/设备指纹）
```

**统一失效页**：不存在、已用尽、已过期、已撤销、密码错误超限 全部返回同一页面与同一 HTTP 状态（410），防止通过差异枚举链接状态。

### 7.3 一次性链接的并发保证

```sql
-- 单条语句完成"检查 + 消费"，行锁由数据库保证
UPDATE share
   SET used_count = used_count + 1,
       last_used_at = now()
 WHERE id = $1
   AND revoked_at IS NULL
   AND (expires_at IS NULL OR expires_at > now())
   AND (max_uses IS NULL OR used_count < max_uses)
RETURNING used_count, max_uses;
-- 影响行数 = 0 → 拒绝
```

压测门禁：`max_uses=1` + 100 并发 → 成功数必须恰为 1；日志中 `share.open` 恰好 1 条 `result=ok`。

### 7.4 防盗链与防爬

- 分享页 `X-Robots-Tag: noindex, nofollow`；`robots.txt` 全站 Disallow。
- 预览图片/PDF/视频分片均签名，URL 不可推导；不带 `Referer` 也可用（避免误伤），但票据与 IP 段绑定。
- 下载与大流量操作有配额与速率限制（按链接、按 IP、按租户）。
- 不返回真实文件 ID/路径；只用分享内相对 ID。

---

## 8. 身份与通知架构

### 8.1 身份（多源认证）

```
                    ┌────────────────────────────┐
                    │  AuthBroker（认证编排器）   │
                    └──┬───────┬────────┬────────┘
                       │       │        │
              ┌────────▼──┐ ┌──▼─────┐ ┌▼──────────┐
              │ local     │ │ ldap/ad│ │ oidc(预留) │
              │ Argon2id  │ │ bind   │ │            │
              └───────────┘ └──┬─────┘ └────────────┘
                               │
                        ┌──────▼───────────┐
                        │ DirectorySync    │  全量/增量/组嵌套/组织树
                        └──────────────────┘
```

**关键约束**
- 认证方式由用户显式选择（域登录 / 本地登录），**域失败不回退本地**（防降级）。
- 会话：Access Token（JWT，15min，仅含 user_id/tenant_id/session_id/epoch）+ Refresh Token（随机串，DB 存哈希，30 天，旋转使用）。`session_epoch` 自增即可使全部旧 token 失效（改密/停用/被踢）。
- 应急管理员：独立标记，不走目录，强审计 + 登录即告警 + 可配 IP 白名单。

### 8.2 通知（双通道）

```
业务事件 → outbox（同事务写入）→ notify job → MailChannel / SmsChannel
                                              ├─ smtp（STARTTLS/SSL）
                                              └─ exchange_online（Graph sendMail, OAuth2）
```

- **outbox 模式**：通知与业务同事务落库，避免"业务成功但通知丢失"或"通知发了业务回滚"。
- 幂等键：`event_type + object_id + recipient + 时间窗`，重复消费不重发。
- 通道健康：连续 3 次失败标记 unhealthy，自动切换备用通道并告警。
- Graph 权限：应用权限 `Mail.Send`（**只授 Send**，不授 `Mail.ReadWrite`），凭据存密钥库并支持轮换。

---

## 9. 数据架构

### 9.1 逻辑分区

| 域 | 主要表 | 量级预估（单租户 2 万用户/500 万对象） |
|---|---|---|
| 租户与身份 | tenant, user, external_user_meta, dept, group, group_member, role, role_perm, user_role, ldap_dir, ldap_sync_run | 百万级 |
| 内容 | space, node, version, blob, blob_ref, upload, upload_part, tag, node_tag | 千万级 |
| 权限 | ace, acl_audit, perm_preset, tag_policy | 千万级（ACE 是最大表） |
| 分享 | share, share_recipient, share_visit, share_ticket | 百万级 |
| 协作 | comment, approval, approval_step, task, request_upload | 百万级 |
| 审计 | audit_event（分区）, audit_daily_root, login_log | 亿级（按月分区） |
| 平台 | job, job_attempt, outbox, notify_log, setting, license, usage_meter | 千万级 |

### 9.2 多租户隔离

- 所有业务表带 `tenant_id NOT NULL`，并建 `(tenant_id, ...)` 复合索引。
- **RLS 策略**：`USING (tenant_id = current_setting('app.tenant_id')::uuid)`，每个请求由 `tenantctx` 中间件执行 `SET LOCAL app.tenant_id`。
- 应用角色与迁移角色分离：应用角色无 `BYPASSRLS`，迁移角色单独。
- **启动自检**：遍历 `information_schema.tables`，任何业务表缺 RLS 策略 → 拒绝启动（把他人的"忘记"变成系统的"不可能"）。
- 平台运营后台使用独立角色 + 显式 `BYPASSRLS`，且所有跨租户读取进平台审计。

### 9.3 迁移

- 工具：`golang-migrate`（或 `goose`），**单一所有者**：只有 server 在启动时执行（`migrate` 子命令）。
- 规则：只前进不修改历史脚本；破坏性变更走"三步走"（加新列→双写→删旧列，分三个版本）；每个迁移必须可在测试库从零重放。
- worker 启动只做**断言**（检查必需表/列存在），缺则 fail-fast，绝不建表（对应 C4）。

### 9.4 任务队列

```sql
-- 认领：跳过已锁行，多 worker 无冲突
UPDATE job SET status='running', locked_by=$1, locked_at=now(), attempt=attempt+1
 WHERE id = (SELECT id FROM job
              WHERE status='pending' AND run_after <= now()
              ORDER BY priority DESC, id
              FOR UPDATE SKIP LOCKED LIMIT 1)
RETURNING *;
```

- 退避：指数（1m, 5m, 15m, 1h, 4h），最大 5 次 → `dead`。
- 僵尸回收：`status='running' AND locked_at < now() - interval '30 min'` → 回 `pending`（对应 C5）。
- 任务契约：`type`, `payload jsonb`, `idempotency_key`, `max_attempt`；未知 type 直接 `dead`（不无限重试）。

### 9.5 审计链

```
audit_event(
  id, tenant_id, seq,          -- seq 为租户内单调递增（序列或行锁维护）
  actor_id, actor_type, ip, ua, request_id,
  action, object_type, object_id, result,
  detail jsonb,                 -- 结构化，不用字符串拼 JSON（对应 M16）
  prev_hash, hash,              -- hash = sha256(prev_hash || canonical(payload))
  created_at
)
```

- **append-only**：应用层无 UPDATE/DELETE 权限；DB 层用触发器拒绝（`BEFORE UPDATE OR DELETE RAISE EXCEPTION`）。
- **写入纪律**：与业务同事务；写失败则业务回滚（fail-closed）。高并发下用"租户级行锁 + 序列"控制链头，用**微秒截断**避免"自证篡改"。
- **日结**：每日生成 Merkle 根 + 事件区间 + 前一日根，形成锚点链；锚点可导出并离线校验。
- **证据包**：事件流（JSONL）+ 链材料 + 锚点 + 校验工具（单文件、零依赖、可离线运行）。

---

## 10. 部署架构

### 10.1 单机（私有化默认）

```
              ┌──────────────────────────────┐
 443 ────────►│ docvault-gateway (nginx)     │
              └───┬──────────────┬───────────┘
                  │              │
        ┌─────────▼────┐  ┌──────▼─────────┐
        │ docvault-    │  │ docvault-      │
        │ server       │  │ onlyoffice     │
        └──┬────┬──────┘  └────────────────┘
           │    │
   ┌───────▼─┐ ┌▼──────────┐  ┌──────────────┐  ┌───────────────┐
   │postgres │ │redis      │  │minio         │  │docvault-worker│
   └─────────┘ └───────────┘  └──────────────┘  └───────┬───────┘
                                                        │
                                                ┌───────▼────────┐
                                                │docvault-convert│
                                                └────────────────┘
```

- 数据卷：`pgdata`, `miniodata`, `onlyoffice-data`, `onlyoffice-fonts`, `app-tmp`, `logs`, `certs`。
- 端口：仅暴露 443（可选 80 跳转）；其余仅容器内网。
- 部署脚本：`deploy/compose/docker-compose.yml` + `install.sh`（生成密钥、初始化 DB、健康检查、打印初始管理员与访问地址）。
- 目标：**4 小时内从零到可用**（含 LDAP 接入）。

### 10.2 SaaS（K8s）

| 组件 | 副本 | 说明 |
|---|---|---|
| gateway（Ingress） | 2+ | 证书按租户域名（cert-manager） |
| server | 3+（HPA） | 无状态；迁移用 Job |
| worker | 2+ | 按队列深度扩缩 |
| transcode | 0–N（KEDA） | 按队列长度伸缩，节点亲和到高 CPU 池 |
| postgres | 主 + 只读副本 | 大表分区；PITR |
| redis | 集群模式 | 缓存与限流 |
| 对象存储 | S3/OSS | 生命周期策略 |
| onlyoffice | 2+（会话粘滞） | 按并发许可控制 |

**形态切换**：`DOCVAULT_MODE=standalone|saas`，差异仅在：租户解析来源（子域名/Header vs 单租户）、计费模块加载、平台后台路由。**同一镜像、同一迁移集**。

### 10.3 环境隔离

| 环境 | 目的 | 数据 |
|---|---|---|
| dev | 本地开发 | 种子数据（一键重置） |
| test | 自动化测试 | 每次跑批前重建 |
| staging | 预发布（与生产同构） | 脱敏数据 |
| prod | 生产 | 真实 |

**纪律**：不同环境不共用数据库/桶/密钥；生产凭据不进 CI 变量以外的任何地方；破坏性操作（清库/删桶）在 staging 与 prod 需二次确认 + 审计。

---

## 11. 安全架构

### 11.1 威胁模型（STRIDE 摘要）

| 威胁 | 场景 | 对策 |
|---|---|---|
| Spoofing | 账号盗用、会话劫持 | MFA、会话旋转、设备指纹、异常登录告警 |
| Tampering | 审计篡改、版本篡改 | 哈希链 + append-only + 版本不可变 |
| Repudiation | 否认曾下载/分享 | 逐次访问审计 + 证据包 |
| Information disclosure | 越权、链接泄漏、IDOR | 对象级授权 + 票据 + 统一 404 |
| DoS | 大文件/转码/登录爆破 | 限流 + 配额 + 队列 + 转码护栏 |
| Elevation of privilege | 授权越界、标签提权 | ceiling + deny 优先 + 标签只补 allow |

### 11.2 关键安全组件

| 组件 | 职责 | 纪律 |
|---|---|---|
| `clientip` | 解析真实来源 IP | 默认 RemoteAddr；只有配置了 `trust_proxy_cidrs` 才解析 XFF，且取**最右侧非信任跳** |
| `csrf` | 双提交 Cookie + SameSite=Lax | 仅对 `GET/HEAD/OPTIONS` 豁免；回调端点用独立验签而非 CSRF 豁免 |
| `secheaders` | CSP/HSTS/X-Frame-Options/X-Content-Type-Options/Referrer-Policy/Permissions-Policy | 默认拒绝内联脚本（`nonce`） |
| `ratelimit` | 分层限流（IP/用户/租户/接口） | 令牌桶，Redis 原子操作；降级为本机限流 |
| `uploadguard` | 扩展名白名单 + MIME 嗅探 + 大小 + 病毒扫描 + 文件名净化 | 双扩展名/大小写/Unicode 归一化都校验 |
| `ssrfguard` | 出站 URL 白名单（scheme + host + 禁私网） | 用于 Webhook、AI base_url、编辑器回调 |
| `redact` | 日志脱敏 | 密码/token/手机号/邮箱中段 |
| `licensectl` | 许可校验 | RSA 签名；到期降级可配 |

### 11.3 能力边界（对外一致表述）

- 防截屏：不可阻断，只能水印 + 失焦遮蔽 + 审计。
- PDF 权限位：可移除，不作为安全边界。
- 病毒扫描：依赖 ClamAV 类引擎，零日无法保证。
- 分享链接：可被截图/转发文字，安全性来自"可撤销 + 可追溯"。

---

## 12. 可观测性

| 层 | 方案 | 关键指标 |
|---|---|---|
| 日志 | 结构化 JSON + `request_id` + `tenant_id` + `user_id` | 错误率、慢请求、异常分布 |
| 指标 | Prometheus `/metrics`（需鉴权） | QPS、P95/P99、权限判定耗时、缓存命中率、队列深度、转码队列、邮件失败率、DB 连接池 |
| 追踪 | OpenTelemetry（采样率可配） | 跨 server→worker→convert 链路 |
| 告警 | 规则 + 邮件/Webhook | 5xx > 1%、P99 > 2s、队列积压 > 1000、审计写失败 > 0、LDAP 同步失败、磁盘 > 85% |
| 健康 | `/healthz`（存活）`/readyz`（就绪）+ 依赖状态页 | 依赖连通性、迁移版本一致 |

**纪律**：`/metrics` 必须鉴权（上一版 M27）；不允许"指标裸奔"。

---

## 13. 容量与扩展路径

| 瓶颈 | 阈值 | 扩展动作 |
|---|---|---|
| 单机 CPU（转码） | 转码等待 > 5 分钟 | 独立转码节点（KEDA/多机） |
| DB 写 | 审计表 > 5 亿 | 按月分区 + 冷归档；审计写异步化（保持 fail-closed） |
| DB 读 | 列表 P95 > 500ms | 只读副本；物化视图 |
| 对象存储 | 单桶 > 5000 万对象 | 按租户/年月分桶 |
| 权限判定 | P95 > 50ms | ACE 位图预计算（物化）、目录级权限快照 |
| 搜索 | P95 > 1s | 引入 OpenSearch（保留 PG 作为兜底） |

**明确不做**：一期不做分库分表（复杂度收益比差），靠"按租户归档 + 冷热分离"支撑到 200 租户。

---

## 14. 技术债登记（一期已知，二期处置）

| # | 债务 | 影响 | 计划 |
|---|---|---|---|
| D-01 | 全文检索仅 PG 分词，无 OCR/向量 | 扫描件搜不到 | M4 |
| D-02 | 无离线客户端 | 无法做本地副本控制 | M4 |
| D-03 | 无 HA | 单机可用性上限 | M3 |
| D-04 | 信创未适配 | 无法进部分标 | M3/M4 |
| D-05 | 无外发包 | 涉密场景缺口 | M4 |
| D-06 | 水印仅预览/下载，未覆盖视频帧 | 视频截图无溯源 | M4 |
| D-07 | 审计写与业务同事务，高并发下可能成瓶颈 | 极端场景慢 | 评估"审计预写 + 补偿"方案 |
| D-08 | 动态组规则引擎为简化实现 | 复杂规则不支持 | M4 |
| D-09 | 无多语言 UI（仅中英） | 出海受限 | M4 |
| D-10 | 计费仅导出账单，无在线支付 | SaaS 转化摩擦 | M3 |

---

## 15. 架构决策记录（ADR）

| # | 决策 | 备选 | 结论 | 理由 |
|---|---|---|---|---|
| ADR-01 | 模块化单体 | 微服务 | 采纳 | 私有化交付简单；性能可预测 |
| ADR-02 | PostgreSQL + RLS | MySQL/应用层过滤 | 采纳 | 双层隔离；RLS 是"忘记写 WHERE"的保险 |
| ADR-03 | 位图 ACE | 权限项行表 | 采纳 | 单行读取，判定快；代价是位定义变更需迁移 |
| ADR-04 | ltree 目录树 | 闭包表/递归 CTE | 采纳 | 继承查询高效，写入简单 |
| ADR-05 | 两段式票据 | 单 token | 采纳 | 泄漏可控；一次性语义可实现 |
| ADR-06 | outbox 通知 | 直接发送 | 采纳 | 与业务一致性 |
| ADR-07 | ONLYOFFICE | 自研/Collabora | 采纳（可切换） | 格式兼容与中文渲染 |
| ADR-08 | HLS 转码 | 直出原片 | 采纳 | 可控清晰度/防盗链/省带宽 |
| ADR-09 | 单迁移所有者 | 各服务各自迁移 | 采纳 | 避免迁移链断裂（C4） |
| ADR-10 | 审计 fail-closed | 尽力而为 | 采纳 | 举证能力是产品主张 |
| ADR-11 | 应急本地管理员 | 无兜底 | 采纳 | 目录故障可自救；强审计约束风险 |
| ADR-12 | 前端 URL 承载 UI 状态 | 内存状态 | 采纳 | 可分享/可回退/可刷新（踩坑 9） |

---

## 16. 架构风险

| # | 风险 | 影响 | 缓解 |
|---|---|---|---|
| AR-1 | 审计 fail-closed 在高并发下成为写入瓶颈 | 吞吐下降 | 分区 + 批量提交 + 压测门禁 + D-07 预案 |
| AR-2 | 权限缓存与 subject_version 失效不彻底 | 短窗越权 | 缓存 TTL 上限 30s；变更走广播；越权用例覆盖"改权后立即访问" |
| AR-3 | 位图 ACE 表达不了"仅某字段"级权限 | 表格单元格级权限做不了 | 明确不做（Filez 有此能力，我们不承诺） |
| AR-4 | 转码与预览共用 worker 队列导致长任务阻塞短任务 | 预览变慢 | 多队列 + 优先级 + 独立并发池 |
| AR-5 | convert 容器处理不可信文件存在解析器漏洞 | 容器逃逸 | 无网络、无凭据、只读根文件系统、临时卷、seccomp |
| AR-6 | SaaS 白标域名证书管理复杂 | 上线摩擦 | cert-manager + 自动化；一期支持"路径式"白标（`/t/{slug}`） |
| AR-7 | 多租户计量"漏记"导致少收 | 收入损失 | 计量写与业务同事务；日对账（三源比对） |

---

## 17. 代码组织（规划）

```
docvault/
├─ cmd/
│  ├─ server/          # API + 迁移 + 内嵌前端
│  ├─ worker/          # 队列消费者
│  └─ dvctl/           # 运维 CLI（迁移/备份/校验证据包/重置密码）
├─ internal/
│  ├─ platform/        # 配置/日志/错误/请求上下文/id 生成
│  ├─ db/              # 连接池、事务、RLS 中间件、迁移
│  ├─ authn/           # 本地/LDAP/会话/MFA/验证码
│  ├─ authz/           # 权限引擎（纯函数 + 解析器 + 解释链）
│  ├─ directory/       # LDAP/AD 同步
│  ├─ content/         # node/version/blob/upload
│  ├─ share/           # 分享/票据/一次性链接
│  ├─ media/           # 预览/转码/播放签名
│  ├─ editor/          # EditorProvider（onlyoffice/wopi）
│  ├─ notify/          # outbox/mail/sms/模板
│  ├─ audit/           # 哈希链/日结/证据包
│  ├─ search/
│  ├─ admin/
│  ├─ tenant/
│  ├─ license/
│  └─ httpapi/         # 路由/中间件/handler（薄）
├─ migrations/         # 单一所有者：server
├─ web/                # React + TS
├─ deploy/
│  ├─ compose/
│  ├─ helm/
│  └─ assets/          # 字体、模板、印章
├─ e2e/                # 浏览器 E2E + 越权用例 + 压测
└─ docs/               # 本套文档
```

**分层纪律**：`httpapi` 只做"取参 → 调 service → 组装响应"，不含业务规则；`authz` 与 `audit` 不依赖 `httpapi`（可独立测试）；`content`/`share` 不直接拼 SQL 字符串（参数化强制）。

---

## 18. 与上一版（0201）的架构差异

| 维度 | 0201（V2.1） | 0203（本版） | 差异理由 |
|---|---|---|---|
| 定位 | 尽调披露协作（VDR） | 通用 EDMS + 安全分享 | 客户需求变更 |
| 租户 | 单租户多组织 | 多租户（RLS） | SaaS 前置 |
| 权限 | 14 位 × L0-L8 × 12 功能位 | 15 位 + 档位 + 条件表达式 | 表达力保留，可理解性提升 |
| 分享 | 外链基础 | 两段式票据 + 一次性原子消费 | 安全深度 |
| 内容 | 本地/S3 并存 | 内容寻址 + 信封加密 + 去重 | 成本与安全 |
| 媒体 | 不支持 | HLS 转码 + 签名播放 | 新增强制需求 |
| 身份 | 本地 + TOTP | 本地 + LDAP/AD + 外部双因子 | 新增强制需求 |
| 通知 | 站内 + 邮件（SMTP） | 站内 + SMTP + Graph + SMS | 新增强制需求 |
| 审计 | 哈希链（日结未接） | 哈希链 + 日结锚定 + 离线校验工具 | 补齐承诺 |
| 交付 | 5 容器 | 8 容器（可选启停） | 功能增加 |

**复用判断**：`authz` 的判定内核思路、`audit` 的链实现、`syncer` 不在一期范围。**不复用代码，只复用已验证的设计结论**——因为数据模型与租户模型已变，强行复用会导致"两套租户假设并存"的历史债。
