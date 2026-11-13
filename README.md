# NeuroDMS

可私有化、也可多租户 SaaS 交付的企业文档管理系统。设计与实现同步推进，文档是评审基线，代码是可运行证据。

**当前版本：V1.0.0（正式版）** · 版本标识与回退步骤见 [`docs/37-版本发布-V1.0.0-与回退手册.md`](docs/37-版本发布-V1.0.0-与回退手册.md)

---

## 当前进度（诚实版）

| 里程碑 | 内容 | 状态 |
|---|---|---|
| 设计（G1） | 竞品研究、BRD、PRD、SAD、FSD、风险清单、越权用例集、版本锁定 | ✅ 已完成并评审 |
| **M1-1 骨架** | 配置 fail-fast、健康检查、安全响应头、真实来源 IP、**权限内核（15 位 + 6 档位 + 判定顺序）** | ✅ 已完成，测试全绿 |
| **M1-2 数据层** | 迁移（内嵌 + 校验和）、租户上下文、**RLS 双层隔离**、启动自检、数据库集成测试 | ✅ 已完成，5 项集成测试通过 |
| **M1-3 身份与会话** | Argon2id 口令、HS256 令牌、刷新令牌旋转、失败锁定、改密吊销、**LDAP/AD 绑定认证**、**外部用户二次验证（邮箱验证码）** | ✅ 完成（含 3 项目录登录测试、8 项 MFA 测试） |
| **M1-4 内容与授权** | 内容三层模型；上传/列目录/下载/**重命名/移动/删除（软删）/元数据**；**ACE 授权管理（grant/list/revoke，含封顶与防锁死）** | ✅ 完成（11 项接口测试） |
| **M1-5 分享** | 创建/撤销/公开兑换、一次性链接原子消费、**两段式票据**、**访问口令 / IP 白名单 / 外发审批**、统一失效表现、访问流水 | ✅ 完成（13 项测试，含 100 并发只成功 1 次） |
| **M1-8 审计** | 哈希链、链校验、只追加、**日结 Merkle 锚点（HMAC 签名）**、**证据包导出 + 独立离线校验器** | ✅ 完成（9 项测试，含跨实现签名一致性） |
| **M1-6 预览与编辑** | LibreOffice 转 PDF（按版本缓存 + single-flight）、ONLYOFFICE 集成（回调六步验签、URL 白名单、签名文件 URL） | ✅ **真机验证**：docx→PDF 200（17KB）、编辑器打开、改文保存产生版本 2（25KB）、预览随编辑刷新 |
| **M1-7 通知** | SMTP（STARTTLS 强校验）+ Microsoft Graph `sendMail` 双通道、outbox 重试与死信、验证码同步投递 | ✅ 完成（13 项测试，含最小 SMTP 服务端实收） |
| **M1-10 音视频** | HLS 多码率、**remux 优先**、4s fMP4 分片、签名播放地址、并发护栏、编码器自动探测 | ✅ **真机验证**：202→200（3 秒）、master/子列表/init/分片全部 200 |
| **M1-9 前端** | 登录（含二次验证）、空间/文件浏览、上传、**重命名/删除**、预览弹窗、**HLS 播放器**、**在线编辑页**、带口令分享、权限抽屉 | ✅ 完成（浏览器端到端验证）|
| **M2-11 前端补齐** | 视觉体系重构（深绿/海蓝、抽象几何母题、深浅双主题）、**拖拽上传 + 分片上传进度**、**批量打包下载/移动**、搜索、**密级徽标与定密抽屉**、水印标识、**治理台**（概览/成员角色/审计/密级/标签策略/降密审批）| ✅ 浏览器实测 14 张截图（含深色模式与审计员视角）|
| **M1-11 AC 门禁** | 78 条越权用例逐条追溯到测试；`scripts/ac-gate.sh` 校验覆盖并真跑 | ✅ 43 条可执行覆盖 / 10 条部分 / 25 条缺口（已归属 M2） |
| **M2-1 权限治理** | 继承断点（祖先 ACE 快照，含 deny，快照禁止单删）、权限解释接口（分步依据）、ACE 改档、版本定版 | ✅ 8 项测试（含 AC-37 提权路径封堵） |
| **M2-2 管理面与三权分立** | 系统/安全/审计三角色；兼任 409；末位管理员保护；管理面越权必留痕；审计员不能改配置 | ✅ 5 项接口测试 + rbac 单测 |
| **M2-3 密级体系** | **修复"引擎有密级、线上无密级"**（Class 未进判定）；定密不超自身；降密审批（禁自批）；标签只收紧；分享按密级强制审批 | ✅ 7 项测试 |
| **M2-4 安全加固** | 分档限流（公开端点单独更严）、ClamAV INSTREAM 真实协议、SVG 白名单净化、上传即定密 | ✅ 6 项测试 |
| **M2-5 协作与传输** | 批量下载/移动（整批预检、整体拒绝）、内部分享、分片上传 + 秒传（幂等）、文件搜索（转义通配符） | ✅ 11 项测试 |
| **M2-6 外用户生命周期** | 账号有效期、删除即吊销（epoch++/清缓存）、外部主体类型独立 | ✅ 3 项测试 |
| **M2-7 运维交付** | `scripts/backup.sh`、`restore.sh`、`restore-drill.sh`（**已实跑**）；`docs/08-运维手册` | ✅ 演练：18 迁移 / 89 审计事件恢复并核对通过 |
| **M2-8 分享邮箱验证** | 白名单（邮箱/域名）判定在发码之前；验证码绑定"链接+邮箱"；验证记录一次性消费；连错锁定 | ✅ 3 项测试 |
| **M2-9 溯源水印** | **pdfcpu（Apache-2.0）叠加全页斜向水印**；PDF 预览不再直出原件；水印失败即拒绝（不降级） | ✅ 6 项测试（含"预览 ≠ 原件"与合法性校验） |
| **M2-10 AC 门禁** | 78 条用例重新追溯 | ✅ **78 覆盖 / 0 部分 / 0 缺口** |
| **M3-1 租户生命周期** | 状态机（active/trial/readonly/suspended/deleted）、开通即交付管理员、**停用与吊销会话同事务**、逻辑删除+保留期、租户级配置（品牌/策略） | ✅ 4 项测试（含"停用后旧令牌立即 401"） |
| **M3-2 计量与对账** | 可累加量走事件账本（dedupe 幂等）+ 日聚合；瞬时量由**数据库触发器与业务写入同事务**维护；对账 LEFT JOIN + 回填修复；账单 CSV | ✅ 4 项测试（含 12 并发精确相等） |
| **M3-3 配额** | 用户数/存储/转码/API 四维；超限行为 reject/readonly/warn；存储与用户数在**触发器内加行锁**硬拦（直接写库也拒） | ✅ 3 项测试（含绕过应用层被 DV403 拦截） |
| **M3-4 白标与自有域名** | 品牌（产品名/主色/Logo/页脚）、按 slug 或 Host 解析、DNS TXT 归属验证、证书校验三件套、**私钥 AES-GCM 加密入库** | ✅ 2 项测试 + 校验单测（ACME 自动签发未实现，已注明） |
| **M3-5 灰度开关** | 全局总开关 + 稳定分桶放量 + 租户级覆盖；SHA-256 分桶（不用 hashtext）；**服务端拦截**而非隐藏界面 | ✅ 3 项测试 |
| **M3-6 平台运营后台** | 独立 `platform_user` 账号 + 不透明会话令牌（4h，可立即吊销）；ops/readonly 双角色；独立前端入口 `/platform`（多页构建）；平台审计独立成表 | ✅ 4 项测试 + 7 张浏览器截图 |
| **M3-7 账号管理** | 成员建号/改资料/启停/重置口令/角色授予；**RBAC 护栏**（仅 sysadmin、禁自授、禁授出高于自身、最后一个可用管理员保护、发起即吊销会话）；平台账号管理（ops/readonly，禁停用自己与最后一个 ops） | ✅ 10 项接口测试 |
| **M3-8 AC 门禁** | 新增 AC-79~AC-94（多租户 + 账号管理攻击面），累计 94 条 | ✅ **94 覆盖 / 0 部分 / 0 缺口** |

**已验证的容器编排**（2026-11-08 实跑）：
- `docker/` 下 4 个容器全部 healthy：`docvault-postgres`（18.6）、`docvault-redis`（Valkey 8）、`docvault-server`（1.74GB，含 LibreOffice + LGPL ffmpeg）、`docvault-onlyoffice`（ONLYOFFICE Docs 10.0.0）。
- 服务在容器内完成连接 → 迁移 → RLS 自检，`/readyz` 返回 `database: ok`。
- 端口为避开本机其他项目占用：postgres `55433`、redis `56380`、server `18090`、onlyoffice `18091`。
- **M3 真机验证**（2026-11-08）：平台账号自动初始化、开通租户后管理员可立即登录、停用后旧令牌立即 401、
  配额超限被数据库拦截（`ERROR: quota:storage`）、对账在 3 个租户上 0 偏差、账单 CSV 带 BOM 可直开。

**镜像内的能力（实测，不是"代码里有"）**：

| 能力 | 实测结果 |
|---|---|
| Office → PDF 预览 | `soffice` 25.8.7.3 转换成功，返回 `application/pdf`（17KB） |
| 在线编辑 | ONLYOFFICE 10.0.0 打开文档 → 输入文字 → 关闭页面 → **回调保存为新版本**（25KB） |
| 音视频转 HLS | 源片为 H.264/AAC 时走 remux，**202 → 200 约 3 秒**；master/子列表/init/分片全部 200 |
| ffmpeg 许可 | `--disable-gpl` 自建（8.1.3），构建期断言不含 `--enable-gpl`；H.264 编码用 openh264 |

---

## 目录结构

```
0203-NeuroDMS/
├─ cmd/
│  ├─ server/                API 进程入口
│  ├─ dirsync/               域账号同步 CLI（支持 -dry-run）
│  ├─ dirprobe/              LDAP/AD 只读排障工具
│  ├─ auditexport/           审计证据包导出
│  └─ auditverify/           独立离线校验器（不依赖本系统代码）
├─ internal/
│  ├─ auth/                  口令、令牌、会话、吊销、验证码、二次验证
│  ├─ authz/                 权限内核（纯函数，零外部依赖）
│  ├─ ace/                   主体快照、ACE 加载、授权管理
│  ├─ content/               空间/节点/版本/blob，重命名/移动/软删
│  ├─ share/                 分享、一次性消费、两段式票据、审批
│  ├─ audit/                 哈希链、日结锚点、证据包
│  ├─ directory/             LDAP/AD 认证与七阶段同步
│  ├─ preview/               LibreOffice 转 PDF + 缓存
│  ├─ onlyoffice/            编辑器配置、回调验签、签名文件 URL
│  ├─ media/                 HLS 转码、播放签名、编码器探测
│  ├─ notify/                SMTP / Microsoft Graph 双通道 + outbox
│  ├─ httpapi/               HTTP 端点（35 个）
│  ├─ bootstrap/             启动装配（种子、通知、目录）
│  ├─ db/ dbtest/            连接、迁移、租户上下文、RLS 自检、测试清理
│  └─ platform/              config / httpmw / webui
├─ migrations/               13 个 SQL 迁移（内嵌进二进制）
├─ docker/                   ★ 本项目专属容器目录（唯一真源）
│  ├─ docker-compose.yml     全部服务定义（含 office profile）
│  ├─ server.Dockerfile      API 镜像（LibreOffice + 自建 LGPL ffmpeg）
│  ├─ certs/                 域控根 CA（供 LDAPS 校验）
│  ├─ data/                  绑定挂载数据（不入库）
│  └─ README.md              启停与已知坑
├─ web/                      前端（React 19 + TS 7 + Vite 8）
│  ├─ src/pages/             登录 / 文件 / 权限抽屉 / 分享页 / 查看器 / 编辑页
│  └─ dist/                  构建产物，由 Go 服务托管
├─ scripts/
│  ├─ check.sh               提交前全量检查
│  └─ ac-gate.sh             78 条越权用例门禁
├─ docs/                     设计文档 + 覆盖矩阵 + 截图
└─ go.mod
```

---

## 快速开始

```bash
# 1. 检查与测试（不需要数据库；Windows Git Bash 亦可）
bash scripts/check.sh

# 2. 构建并本地启动（开发形态，允许弱配置）
go build -o bin/docvault-server ./cmd/server
DOCVAULT_MODE=development DOCVAULT_HTTP_ADDR=127.0.0.1:8081 ./bin/docvault-server
# 另开终端验证
curl -s http://127.0.0.1:8081/healthz
curl -s http://127.0.0.1:8081/readyz

# 3. 验证"配置缺失即拒绝启动"
DOCVAULT_MODE=saas ./bin/docvault-server
# 预期：退出码 2，并一次性列出全部缺失项
```

演示账号（仅当 `.env` 里 `DOCVAULT_DEV_SEED=1` 且库为空时创建）：
组织 `demo` / 账号 `admin` / 口令见 `docker/.env` 的 `DOCVAULT_DEV_ADMIN_PASSWORD`。
打开 `http://127.0.0.1:18090/` 即是界面。

> 端口请避开 8080/18080 等常用端口：本机 18080 已被 Jenkins 占用，占用时会以 `bind: forbidden` 退出而不是静默失败。
> `make` 为可选入口；本机未安装 make，`make test-race` 还需 CGO + gcc。

容器编排（本项目专属目录 `docker/`，唯一真源）：

```bash
cd docker
cp .env.example .env   # 至少填 POSTGRES_PASSWORD 与 DOCVAULT_JWT_SECRET

docker compose up -d                                   # 数据库 + 缓存
docker compose --profile app up -d --build             # 连同 API（含预览/转码能力）
docker compose --profile app --profile office up -d    # 再连同 ONLYOFFICE（在线编辑）
```

| 服务 | 端口 | 说明 |
|---|---|---|
| postgres | 127.0.0.1:55433 | PostgreSQL 18.6，数据在 `docker/data/postgres` |
| redis | 127.0.0.1:56380 | Valkey 8 |
| server | 127.0.0.1:18090 | API + 前端 + LibreOffice + ffmpeg |
| onlyoffice | 127.0.0.1:18091 | ONLYOFFICE Docs 10.0.0（可选） |

**不启动 office profile 也能用**：预览照常（LibreOffice 转 PDF），编辑入口返回 501 并由前端提示，
不是白屏——这是刻意的"能力缺失即降级"。

---

## 数据层（双层隔离）

- **迁移**：SQL 内嵌进二进制（`migrations/*.sql` + `embed`），按文件名顺序执行，记录 SHA-256 校验和；**已应用的历史脚本被改动即报错**，杜绝跨环境结构漂移。
- **第一层（应用）**：`db.WithTenant` 在事务内执行 `SET LOCAL app.tenant_id`，并在仓储层强制带租户条件。
- **第二层（数据库）**：所有业务表 `ENABLE` + `FORCE ROW LEVEL SECURITY`，策略为
  `tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid`。
  未设置上下文时比较结果为 NULL → **看不到任何行**，而不是看到全部。
- **运行时角色**：应用以 `SET LOCAL ROLE docvault_app` 执行（非超级用户、无 `BYPASSRLS`）。超级用户会绕过 RLS，因此**不能**用来跑业务查询——这是上一版没有明确区分而导致"RLS 看起来配了、实际没生效"的隐患。
- **启动自检**：扫描所有带 `tenant_id` 的表，缺 RLS 或缺少策略即**拒绝启动**并点名表名。

启动数据库并跑集成测试：

```bash
# 1. 启动本项目专属数据库容器（定义在 docker/docker-compose.yml，数据落在 docker/data/postgres）
cd docker && docker compose up -d postgres && cd ..

# 2. 跑集成测试（含"缺上下文看不到数据""跨租户写入被拒""漏加 RLS 被自检拦下"）
export DOCVAULT_TEST_DSN="postgres://docvault:<口令>@127.0.0.1:55433/docvault?sslmode=disable"
bash scripts/check.sh
```

> Go 模块代理使用 `https://goproxy.cn,direct`（官方代理在本网络返回 502），已写入 `scripts/check.sh` 与版本锁定表。

---

## 认证原语（M1-3a）

| 模块 | 内容 | 关键点 |
|---|---|---|
| `internal/auth/password.go` | Argon2id 哈希/校验、参数从编码串解析、`NeedsRehash` 平滑升级 | m=64MiB/t=3/p=4；常量时间比较；账号不存在时也执行等价开销（防时序枚举） |
| `internal/auth/token.go` | HS256 访问令牌、刷新令牌生成与摘要 | **拒绝 `alg=none`** 与算法混淆；刷新令牌只存 SHA-256，明文仅出现一次 |
| `migrations/0002_auth.sql` | 会话表 + 登录失败计数 + 锁定字段 | 会话表同样启用 RLS；刷新令牌摘要唯一索引 |

**刻意没做的事**：不把权限位写进访问令牌。令牌签发后无法撤回，若把权限塞进去，改权限后旧令牌仍会放行——权限必须每次判定时查库。

验证：

```bash
go test ./internal/auth/ -v            # 11 项，覆盖率 80.0%
go test ./... -race                    # 需 gcc（已装 WinLibs 16.2.0）
```

---

## 内容与对象级授权（M1-4）

三层模型：`node`（逻辑对象）→ `version`（内容快照）→ `blob`（内容寻址，同内容只存一份）。

接口：

| 方法 | 路径 | 权限位 |
|---|---|---|
| POST | `/v1/spaces` | 创建者自动获得 owner ACE |
| POST | `/v1/spaces/{id}/folders` | 父目录 `create` |
| POST | `/v1/spaces/{id}/files` | 父目录 `create`；同名文件自动追加为新版本 |
| GET | `/v1/spaces/{id}/nodes?parentId=` | 目录 `display` |
| GET | `/v1/nodes/{id}/content` | 对象 `download` |

**判定如何接上**：`ace.LoadSubject` 组装主体快照（部门祖先链 + 角色 + 用户组 + 密级 + 封顶），
`ace.LoadForNode` 取出空间根 + 祖先链的 ACE（越深 depth 越大），交给 `authz.Authorize` 纯函数判定。
无权访问与对象不存在统一返回 404，避免枚举。

### 授权管理接口

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/v1/acl` | 授予档位（viewer/commenter/contributor/editor/manager/owner） |
| GET | `/v1/acl?objectType=&objectId=` | 列出对象上的权限条目 |
| DELETE | `/v1/acl/{id}` | 撤销（**拒绝移除最后一个所有者**） |

三处设计要点：
1. **封顶只作用于授权**：授权方必须对对象有 `manage_acl`，且目标档位 ≤ 自身 `ceiling`，越界返回 `403 CEILING_EXCEEDED` 并留痕。
2. **默认 ceiling = 6**：早期默认 4 会让空间所有者连"管理者"都授不出去，与"交接所有权"这一常规业务冲突（由集成测试暴露后修正，见 FSD §3.4）。
3. **防锁死**：删除对象上最后一个 owner 级条目会被拒绝（`400 LAST_OWNER`），避免一次误操作让对象永久失去管理入口。

**两条易错点（都踩过）**：
1. 组表 `user_group` / `group_member` 在设计里有、迁移里漏了，判定读组成员时直接报 "relation does not exist"。已补迁移 `0007`。
2. Windows 上文件仍打开时 `os.Rename` 会失败（Linux 允许），内容落盘必须在改名**之前** Close——只在 Linux 跑测试会漏。

---

## 身份、目录与二次验证（M1-3）

| 能力 | 实现要点 |
|---|---|
| 本地账号 | Argon2id（64MiB/t=3/p=4）；刷新令牌只存摘要并旋转；失败 5 次锁定 |
| 域账号（LDAP/AD） | 先服务账号搜 DN、再用用户口令 bind；**空口令直接拒绝**（LDAP 匿名绑定会"成功"，这是经典绕过） |
| 二次验证（外用户） | 口令通过后**不签发任何令牌**，返回 202 + challenge；邮箱验证码校验通过才建会话 |
| 验证码 | 只存 HMAC；一码一次（原子消费）；错误计数落库；窗口内签发次数受限；只认最新一条 |
| 踢下线 | `session_epoch` + 10 秒缓存的吊销检查（PRD 要求 30 秒内），停用/改密/登出立即失效 |

```bash
# 同步域账号（建议先 --dry-run）
DOCVAULT_LDAP_URL=ldaps://dc1.example.com:636 \
DOCVAULT_LDAP_BASE_DN='DC=example,DC=com' \
DOCVAULT_LDAP_BIND_DN='CN=svc,OU=Service,DC=example,DC=com' \
DOCVAULT_LDAP_BIND_PASSWORD='***' \
DOCVAULT_LDAP_AD_MODE=1 \
go run ./cmd/dirsync -tenant demo -dry-run
```

同步的七阶段顺序不可换：拉快照 → 清洗去重 → upsert 用户 → 落部门 → upsert 组 →
展开嵌套组并关联 → 离职回收。最后一阶段会同时**吊销该账号的全部会话**，
否则"停用了但 15 分钟内还能用"。

---

### 给域控配 LDAPS（实测步骤，2026-11-08）

**先纠正一个常见误解**：AD CS 建好根 CA 只是有了"信任锚"，**LDAP 用的是域控自己的服务器证书**。
要跑 LDAPS，三件事缺一不可：域控有服务器证书 → 证书里有客户端访问的名字 → 客户端信任其根 CA。

本环境的实际状态（用 `openssl s_client` 与 `dirprobe` 实测）：

```
subject = CN=NFSDC01.neurongene.cn
issuer  = DC=cn, DC=neurongene, CN=neurongene-NFSDC01-CA     （有效期至 2031-11-08）
```

服务器证书已由 AD CS 自动注册（含 Kerberos/Server Authentication EKU），所以只剩"客户端信任"这一环。

**操作步骤**

1. **确认域控证书可用**（在域控上）：`certutil -store My`，应看到 `CN=NFSDC01....` 且私钥存在、
   应用程序策略含"服务器身份验证"。若没有，用 `certlm.msc` → 个人 → 申请新证书 → 选
   "Kerberos Authentication"（或 "Domain Controller"）模板。
2. **确认 636 在听**：从客户端 `Test-NetConnection <DC-IP> -Port 636`。
   新建证书后 636 通常立即可用；若握手仍失败，重启域控上的 NTDS 服务再试。
3. **从 AD 导出根 CA**（不用登服务器，AD 本身就是证书分发点）：

```bash
go run ./cmd/dirprobe -url ldaps://<DC-IP>:636 -insecure \
  -bind 'administrator@example.cn' -pass '***' \
  -save-ca docker/certs/example-root-ca.pem
```

   它读取 `CN=Certification Authorities,CN=Public Key Services,CN=Services,CN=Configuration,...`
   的 `cACertificate`，导出的就是域内所有机器实际信任的那张根证书。
4. **应用侧配置**（三项，注意没有 `ALLOW_PLAINTEXT`）：

```env
DOCVAULT_LDAP_URL=ldaps://192.168.225.128:636
DOCVAULT_LDAP_CA_FILE=/certs/neurongene-root-ca.pem
DOCVAULT_LDAP_TLS_NAME=NFSDC01.neurongene.cn   # 证书只有 DNS SAN，按 IP 连时必须
```

5. **验证**（不加 `-insecure`，这一步是全绿的才算通）：

```bash
go run ./cmd/dirprobe -url ldaps://<DC-IP>:636 \
  -ca docker/certs/example-root-ca.pem -tls-name NFSDC01.example.cn \
  -bind 'administrator@example.cn' -pass '***' -user <测试用户>
```

**三种失败要能区分开**（否则会误判成"证书没配好"）：

| 报错 | 含义 | 处置 |
|---|---|---|
| `certificate signed by unknown authority` | 客户端不信根 CA | 执行第 3、4 步 |
| `doesn't contain any IP SANs` | 链已受信，但按 IP 连、证书只有 DNS 名 | 设 `DOCVAULT_LDAP_TLS_NAME` |
| `Error initializing SSL/TLS`（StartTLS） | 域控没有可用服务器证书 | 回到第 1 步 |

实测：完成后域账号登录走 LDAPS，`/v1/auth/login` 返回 200，错误口令 401，启动日志不再出现明文告警。

---

### 与真实 AD 联调后的四条结论（2026-11-08）

在 Windows Server 2019 域控上实机跑通，过程中修掉 3 个只有真目录才会暴露的问题：

1. **认证过滤器与同步过滤器必须分开**。认证用 `(&(objectClass=user)(sAMAccountName=%s))`，
   同步若复用同一字符串，`%s` 会原样发出，结果是"52 个组、0 个人"。
   现分为 `UserFilter`（带占位符）与 `SyncUserFilter`（AD 默认 `(&(objectClass=user)(objectCategory=person))`）。
2. **AD 的 `objectGUID` 是二进制**，直接当字符串写 Postgres text 列会报编码错误。
   现转成 Windows 风格 GUID（`c9baa54f-3f94-42e2-ba15-7a867335f63d`），可与 AD 管理工具里的值直接对照。
3. **同步会把域内服务账号带进来**（实测 `krbtgt`）。默认排除 `krbtgt` / `DefaultAccount` / `WDAGUtilityAccount`，
   保留 `Administrator` 与 `Guest`，可用 `DOCVAULT_LDAP_EXCLUDE_ACCOUNTS` 追加。
4. **`objectClass=user` 在 AD 里包含计算机账号**，必须加 `objectCategory=person` 才只取人。
5. **AD 的 OU 不是用户属性，只能从 DN 解析**。账号挪进 OU 后，`department` 与 `ou` 属性都可能为空，
   只有 DN 变了。若按属性取部门，结果会是"所有人在 AD 里都有部门、在本系统里全都没有"。
   现按 DN 解析出 OU 链，并在本地建**两层以上**的部门树（权限按祖先链继承，摊平会让上级授权失效）。

实测证据（`ldap-lab` 租户）：

| 场景 | 结果 |
|---|---|
| 域账号正确口令登录 | `200` + 令牌；`/v1/me` 可用；审计 `auth.login=ok` |
| 错误口令 | `401 INVALID_CREDENTIALS`（与本地账号同一提示） |
| AD 中已禁用账号（Guest） | `403 ACCOUNT_DISABLED` |
| 离职回收（把 Base DN 收窄到无人的容器） | 4 个账号转 `suspended`，**全部会话同时吊销** |
| 恢复（全量再同步） | 恢复 4 个；`Guest` 因目录本身仍禁用而保持停用 |
| 嵌套组（`Denied RODC Password Replication Group`） | AD 里 8 个直接成员全是组或服务账号，本地正确展开出 `Administrator`、`ericadmin` |
| 幂等 | 第二次同步 `新建 0 / 更新 5`，无重复行 |
| 部门树（账号挪进 OU 后） | 从 DN 解析出 `Neurongene → Data&Tech`，本地建成两层部门树；`ericadmin`、`sunxin` 落到 `Data&Tech`，`windows2019` 落到 `NeuronAdminOffice` |
| LDAPS（CA 校验，不跳过） | 域账号登录 `200`；启动日志无明文告警 |

排查工具：`cmd/dirprobe` 逐步打印连接 → rootDSE → 绑定 → 用户搜索 → 用户绑定 → 组成员，
只读、不写目录；默认拒绝明文，需显式 `-allow-plaintext`。

---

## 分享安全（M1-5/M1-6a）

两段式票据：链接 token 只用于换 **5 分钟票据**，取字节只认票据。

| 策略 | 说明 |
|---|---|
| 一次性链接 | 单条 `UPDATE ... RETURNING` 原子消费；100 并发只成功 1 次 |
| 访问口令 | Argon2id 存储；**输错不消耗次数**（否则一次性链接输错一次就废了） |
| IP 白名单 | CIDR 数组；票单据绑定来源网段（IPv4 /24、IPv6 /64，避免移动网络漂移） |
| 外发审批 | 链接先 `pending`；审批人必须有 `manage_acl`，发起人不能自批 |
| 可收回 | 撤销分享时**同时吊销已发出的票据**，否则票据有效期内还能下载 |
| 不可枚举 | 不存在/已用尽/已过期/已撤销统一 `410 SHARE_UNAVAILABLE` |

---

## 预览、编辑与音视频（M1-6b/M1-10）

| 链路 | 实现 | 缺依赖时 |
|---|---|---|
| Office → PDF 预览 | LibreOffice 子进程；缓存 key = `节点+大小+更新时间+**实测渲染器版本**`；同版本并发只转一次；编辑保存后主动失效缓存 | 返回 `501 PREVIEW_UNAVAILABLE` |
| 在线编辑 | ONLYOFFICE Docs 10.0.0；配置 JWT 的载荷**就是配置对象本身**；`callbackUrl` 显式指向本系统；文档地址是**短时签名 URL** | 编辑入口返回 `501` |
| 音视频 | HLS：H.264/AAC 走 `-c copy` remux（秒级）；否则按分辨率转 360/720/1080；4 秒 fMP4 分片；**编码器运行时探测**（libx264 → libopenh264） | 返回 `501 MEDIA_UNAVAILABLE` |

**三条与部署拓扑相关的关键配置**（写错就会出现"编辑器能打开但不保存"）：

| 配置 | 含义 | 为什么必须分开 |
|---|---|---|
| `DOCVAULT_PUBLIC_URL` | 浏览器访问本系统的地址 | 浏览器要用 `127.0.0.1:18090` |
| `DOCVAULT_INTERNAL_URL` | 文档服务反向访问本系统的地址 | 容器网络里必须用 `docvault-server:8080` |
| `DOCVAULT_ONLYOFFICE_INTERNAL_URL` | 本系统访问文档服务的地址 | 文档服务回传的下载地址是 `127.0.0.1:18091/cache/...`，服务端抓不到，必须改写为 `docvault-onlyoffice` |

ONLYOFFICE 回调的六步校验（缺一步就有一个可被利用的洞）：

1. 必带 JWT；2. 签名正确（拒绝 `alg=none`）；3. 未过期；4. status 在白名单；
5. **回传 URL 主机在白名单**且不跟随跳转（SSRF 防护）；6. 回调里的 `key` 必须由该 `nodeId` 派生。

---

## 审计与取证（M1-8）

- 事件哈希链：与业务同事务写入，写不进就回滚；租户级 advisory lock 防分叉。
- **日结锚点**：每小时结算"昨天"，Merkle 根 + 链头 + HMAC 签名，写 `audit_anchor`。
- **证据包导出**与**独立校验器**（不依赖本系统代码，也不需要数据库）：

```bash
DOCVAULT_DB_DSN=... go run ./cmd/auditexport -tenant demo -out evidence.json
go run ./cmd/auditverify -bundle evidence.json -secret <锚点密钥>
```

校验器会重算每条事件的哈希、prev 链、每天的 Merkle 根与锚点签名；
`cmd/auditverify` 的测试里有一条**跨实现签名一致性**用例——
两套独立实现的 `anchorInput` 必须逐字节一致，否则"客户端验签永远失败"这种问题极难排查。

---

## 越权用例门禁（M1-11）

`docs/06` 定义 78 条越权用例；`docs/07` 把每条映射到**真实存在的测试函数**，由脚本强制校验：

```bash
bash scripts/ac-gate.sh            # 静态校验 + 执行（需 DOCVAULT_TEST_DSN）
```

三道硬规则：

1. 78 条一条不能少，漏写即失败；
2. 标 ✅ 的必须有测试名，且该函数在代码中真实存在、且能跑过；
3. 标 ◐/⬜ 的必须写明归属里程碑（M2），不允许"无主缺口"。

当前结果：**43 条可执行覆盖 / 10 条部分覆盖 / 25 条缺口**（缺口集中在 M2 业务：密级流程、
三权分立、批量操作、搜索、病毒扫描、水印、外用户生命周期、分片上传），46 个测试函数全部通过。

> 为什么值得单独做：测试存在 ≠ 用例被覆盖。没有映射表，"我们测了 78 条"只是一句话；
> 有了它，少一条就红，任何人都能复核。

---

## 前端（M1-9）

技术栈按版本锁定：React 19.3.1 + TypeScript 7.0.2 + Vite 8.3.5，产物由 Go 服务直接托管，同源无跨域。

```bash
cd web
npm install          # 首次
npm run build        # tsc -b && vite build → web/dist
# 开发期热更新（代理到本地后端）
npm run dev
```

页面：

| 路径 | 内容 |
|---|---|
| `/login` | 组织标识 + 账号 + 口令；**已支持二次验证（口令通过后停在验证码页，无任何令牌）**；回跳只允许站内相对路径 |
| `/files` | 空间列表（含新建空间）、文件表格、上传、新建文件夹、预览、播放、编辑、下载、分享、权限、**改名、删除** |
| `/files` → 预览弹窗 | 文本/图片/PDF/音视频内联渲染；服务端未装转换器时明确提示"下载后查看" |
| `/files` → 播放 | HLS 播放器（Safari 原生、Chrome 走按需加载的 hls.js），转码中显示进度 |
| `/edit/{id}` | 在线编辑页：动态加载文档服务 `api.js`，用服务端签发的配置实例化编辑器 |
| `/s/{token}` | 对外分享页（免登录）：**口令输入 → 票据 → 在线查看/下载**，失效统一提示 |

**浏览器端到端验证**（Playwright + Chromium，截图在 `docs/screenshots/`）：
登录 → 新建空间 → 上传 → 预览文本 → 带口令分享 → 匿名打开（错口令提示"口令不正确"、对口令进入）→ 在线查看正文；
在线编辑页加载出真实文档并**改文保存产生新版本**。控制台无脚本错误。

**设计取舍**：
- **未引入组件库**。版本锁定表里登记了 Ant Design 6.7.0，但 M1 只做最小可用界面，此时引入组件库等于在没有 UI 规范前锁定视觉语言；先用手写样式 + 设计令牌，UI 评审后再引。
- **未引入路由库**。只有三条路径且跳转都用 `location.assign`，引 react-router 会让 bundle 翻倍却无收益。
- **权限界面只暴露 5 个档位**，不暴露 15 个位——这是"可表达但可理解"的落地：位在服务端，档位在人面前。

**新增依赖**：`hls.js 1.7.4`，**按需动态加载**——静态引入会让首屏从 249KB 涨到 826KB，
而多数用户只是浏览文件列表，不需要播放器。

---

## 权限内核

`internal/authz` 是纯函数，不依赖数据库，因此可以先行把语义钉死。

- **15 个原子位**，分 4 组：可读性 / 内容操作 / 结构操作 / 分享与治理。
- **6 个档位**：查看者 → 评论者 → 贡献者 → 编辑者 → 管理者 → 所有者。
- **判定顺序固定**：租户 → 主体 → 对象 → 密级(MAC) → 显式拒绝 → 允许集合 → 条件 → 封顶 → 归一化。
- **两条硬约束**：
  1. 规则加载失败必须判拒（`ACL_LOAD_ERROR`），不允许降级为空权限后放行。
  2. 未知条件键视为不满足（fail-closed），不允许当作"无此条件"。

验证：

```bash
go test ./internal/authz/ -cover   # 当前 80.1%
```

---

## 已知阻塞

> 当前**没有阻塞 M1 交付的项**。下列 1–3 是环境与法务层面的待办，4–8 已闭环（保留记录便于追溯）。

| # | 阻塞 | 影响 | 需要谁处理 |
|---|---|---|---|
| 1 | Docker 镜像源配置已改（`docker.m.daocloud.io`）但**需重启 Docker Desktop 生效** | 重启前拉取仍可能偶发失败；重启会波及其他 20 个容器 | 重启时机由你决定（原配置已备份） |
| 2 | 本机 Go 1.26.3 / Node 22.22.2 低于锁定版本 | 本机能编译但非最终工具链 | 构建镜像已锁 1.27.3；Node 需在前端开工前升级 |
| 3 | ONLYOFFICE 在 SaaS 场景的 AGPLv3 合规意见未出 | 影响 SaaS 上线 | 法务 |
| 4 | ~~访问令牌吊销延迟~~ | 已解决：`session_epoch` + 10 秒缓存，停用/改密/登出后 ≤10s 生效（PRD 要求 30s） | 已闭环 |
| 5 | ~~镜像内没有 LibreOffice / ffmpeg~~ | **已解决**：镜像内装 LibreOffice 25.8.7.3 + 自建 LGPL ffmpeg 8.1.3（1.74GB），实测 docx→PDF、HLS 转码、在线编辑保存全部通过 | 已闭环 |
| 6 | ~~LDAP 未与真实目录联调~~ | **已联调**：Windows Server 2019 域控 `NFSDC01.neurongene.cn`（`DC=neurongene,DC=cn`），同步 5 人 / 52 组；域账号登录、错误口令、禁用账号、离职回收与恢复全部实机验证 | 已闭环 |
| 6.1 | ~~该域控未装 LDAP 证书~~ | **已解决**：AD CS 为域控签发了服务器证书（`CN=NFSDC01.neurongene.cn`，签发者 `neurongene-NFSDC01-CA`），636 可用；客户端导入根 CA + 指定校验名后**做真实链校验**，不再使用明文，也不再 `InsecureSkipVerify` | 已闭环（操作步骤见「给域控配 LDAPS」） |
| 7 | 外部账号二次验证依赖邮件通道 | 未配 SMTP/Graph 时 `mfa_required` 账号一律拒登（fail-closed，日志会告警） | 需要邮件通道 |
| 8 | ~~ONLYOFFICE 回调仅在测试内验证~~ | **已联调**：官方镜像 `onlyoffice/documentserver:10.0.0`，浏览器打开文档 → 改文 → 关闭 → 回调保存为新版本（实测版本 1→2，预览随之刷新） | 已闭环 |
| 9 | **LibreOffice 版本低于锁定值** | 锁 26.8.0，实际镜像为 Alpine 官方包 25.8.7.3（26.8 无现成包，按"只用官方安装包/源码"的约束不自行拼装） | 影响格式兼容性覆盖范围；已用实测版本号进缓存 key，升级后缓存自然失效 |

---

## 设计文档

从 `docs/README-文档索引与评审说明-v1.0.md` 开始。文档状态码约定：`✅` 有代码与测试证据，`🎯` 有设计无代码，**混用视为造假**。
