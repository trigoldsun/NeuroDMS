# 版本锁定表（versions.lock）

- 版本：v1.0 ｜ 日期：2026-11-08 ｜ 状态：**生效**
- 纪律依据：用户规范「必须使用最新稳定版（经产品官方网站及下载页确认），禁止旧版或 beta」
- 使用方式：CI 与构建脚本以本表为准；任何偏离必须在 PR 中说明原因并经评审

---

## 1. 已核实（本轮通过官方源确认）

| 层 | 组件 | 锁定版本 | 发布/核实日期 | 许可 | 核实来源 |
|---|---|---|---|---|---|
| 后端语言 | **Go** | **1.27.3** | 1.27.3 于 2026-10-19；1.27.0 于 2026-08-19 | BSD-3 | go.dev/doc/devel/release |
| HTTP 路由 | **chi** | **v5.5.0** | 2026-10-14（v5.4.0 于 2026-10-12） | MIT | github.com/go-chi/chi/releases |
| PG 驱动 | **pgx** | **v5.11.0** | 2026-09-07 | MIT | github.com/jackc/pgx |
| 数据库 | **PostgreSQL** | **18.6** | 18.x 当前 minor；19 仍为 beta 不采用 | PostgreSQL License | postgresql.org/support/versioning |
| 运行时（构建） | **Node.js** | **24.21.0 LTS「Krypton」** | 2026-09-07 | MIT | nodejs.org/en/about/previous-releases |
| 前端框架 | **React** | **19.3.1** | 2026-10-14（19.3 于 2026-09-09） | MIT | npm registry / react.dev |
| 语言 | **TypeScript** | **7.0.2** | 2026-08-20（7.0 于 2026-07-08，Go 实现编译器） | Apache-2.0 | npm registry |
| 构建 | **Vite** | **8.3.5** | 2026-10-21（8.x 默认 Rolldown） | MIT | npm registry / vite.dev |
| UI 组件 | **Ant Design** | **6.7.0** | 2026-11-04 | MIT | ant.design/components/changelog |
| 文档转换 | **LibreOffice** | **26.8.0** | 2026-08-26，EOS 2027-06-13 | MPL-2.0 | libreoffice.org + TDF 公告 |
| 在线编辑 | **ONLYOFFICE Docs** | **10.0** | 2026-10（JWT 默认启用） | **AGPLv3**（SaaS 需商业授权） | onlyoffice.com |
| PDF 水印 | **pdfcpu** | **v0.16.4** | 2026-10-28 | **Apache-2.0** | github.com/pdfcpu/pdfcpu |

### 1.3 水印字体（随镜像分发）

| 项 | 值 | 说明 |
|---|---|---|
| 字体 | **Watermark Sans Regular**（由 LXGW WenKai 子集化并改名） | SIL OFL 1.1；改名符合 OFL 对保留字体名的要求 |
| 轮廓 | **TrueType (glyf)** | pdfcpu 只支持 glyf；容器内 Noto Sans CJK 是 OpenType/CFF，会被拒绝 |
| 字符集 | GB2312 全量 6763 字 + ASCII + 常用全角标点（共 6897 字） | 覆盖日常人名与部门名 |
| 体积 | 3.3 MB（子集化前 24 MB） | 随镜像放在 `/app/assets/fonts/`，OFL.txt 一并分发 |
| 配置 | `DOCVAULT_WATERMARK_FONT` | 缺失时**回退 ASCII 水印**并打 WARN，不阻断启动 |

### 1.4 为什么水印不用 Ghostscript

Ghostscript 是 AGPLv3 或 Artifex 商业授权。官方 FAQ 明确：**闭源分发、SaaS 部署、或需要官方支持，都必须购买商业授权**。
本项目同时是"私有化闭源交付 + SaaS 双形态"，两条都命中，因此不采用。

改用 pdfcpu（Apache-2.0，纯 Go）：
- 无外部依赖，静态编入二进制；无 C 解释器攻击面（预览链路要处理用户上传的不可信文件）；
- 支持 CJK 水印自动换行（v0.15.0+）；
- 已知限制：**只支持 TrueType(glyf) 轮廓字体**，容器内 Noto Sans CJK 是 OpenType/CFF，会被拒绝。
  因此当前水印内容使用账号/邮箱/IP/时间（ASCII）；若需中文显示名，换一份 glyf 轮廓的 OFL 中文字体即可，调用方不变。

### 1.1 三条必须记住的版本决策

1. **PostgreSQL 19 不用**：仍处 beta。18.6 为当前 minor，支持至 2030-11。
2. **LibreOffice 不用 26.2.x**：26.2.6 虽为"成熟分支"，但 **2026-11-30 即 EOS**（距现在 3 周）。26.8.0 支持到 2027-06-13，故采用 26.8.0，并把"渲染回归"纳入 CI（版本新 = 格式回归风险高，必须用真实文件集验证）。
3. **TypeScript 7 是 Go 重写版**：编译快 8–12 倍，但 `strict` 为默认。若第三方类型包不兼容，**不允许降级到 6.x**，而是钉住具体不兼容包版本或替换。

---

## 2. 待锁定（编码首日按官方下载页确认后回填）

这些组件不写死版本号，是因为本轮未从官方下载页取得可信版本；编码首日必须逐个核实并回填，**不允许留空进入集成阶段**。

| 层 | 组件 | 锁定要求 | 官方页 | 特别约束 |
|---|---|---|---|---|
| 缓存 | Valkey（或 Redis） | 最新稳定 | valkey.io/download | 优先 Valkey（Redis 许可变更后） |
| 运行时基础镜像 | **Alpine Linux** | **3.24**（当前稳定分支，2026-06-09，EOS 2028-06-01） | 2026-10-21 发布 3.24.3 | — | alpinelinux.org/releases |
| 对象存储 | **pgsty/minio（社区 fork）** | **RELEASE.2026-09-16T00-00-00Z** | 2026-09 | AGPLv3 | 见 §1.2（官方社区版已停止分发） |

### 1.2 重要变更：MinIO 社区版已停止分发（影响选型）

事实（2026 年内分阶段发生）：

| 时间 | 事件 |
|---|---|
| 2026-04-25 | `minio/minio` GitHub 仓库归档（只读） |
| 2026-07-14 | `minio/mc` GitHub 仓库归档 |
| 2026-09-11 | Docker Hub 删除 `minio/minio` 与 `minio/mc` 镜像 |
| 2026-09-24 | `quay.io/minio/*` 开始返回 401 |
| 2026-09-30 | `dl.min.io` 对二进制返回 **410**，官方声明"CE 不再维护、不提供安全更新" |

官方改推 AIStor Free（自有许可）。**因此"用 MinIO 做对象存储"这条原设计前提已不成立。**

**处置（已改到代码与文档）**：
1. **单机默认使用本地 FS 后端**，不打包任何对象存储容器——减少一个可能失维的第三方依赖，对私有化交付是净收益。
2. 需要 S3 语义时：**对接客户自有 S3/OSS**（推荐，无镜像也无需维护）；如必须自带，只允许按**官方源码**自建，**不采用第三方 fork 镜像**（用户要求：容器只用官方镜像）。
3. 架构上把对象存储抽象为 `StorageBackend` 接口（local / s3 / oss），**不绑定任何单一实现**。
4. 风险登记：若客户环境无 S3，则只能走本地 FS，多节点部署时的共享存储需另行规划（登记到 BRD R10 后续评估）。

### 1.3 容器镜像纪律（用户要求，硬约束）

| 规则 | 说明 |
|---|---|
| 只用官方镜像 | `postgres` / `valkey` / `golang` / `alpine` / `nginx` 等均为官方镜像；厂商产品（如 `onlyoffice/documentserver`）用厂商官方镜像 |
| 无官方镜像时 | 按**官方安装包或官方源码**自建（如 LibreOffice 用发行版官方包或 TDF 官方安装包；ffmpeg 用官方源码或发行版包） |
| 禁止 | 任何社区 fork 镜像、`bitnamilegacy` 等转载镜像、来源不明的镜像 |
| 固定方式 | 生产按 digest 固定；开发至少按完整 tag 固定，禁止 `latest` |

### 1.4 依赖来源（Go 模块）

| 项 | 值 | 说明 |
|---|---|---|
| GOPROXY | `https://goproxy.cn,direct` | 官方代理 `proxy.golang.org` 在本网络返回 502，改用国内镜像；**仅作模块分发通道，不改依赖内容** |
| 依赖校验 | `go.sum` 必须提交 | CI 执行 `go mod verify` + `govulncheck` |
| 音视频 | ffmpeg / ffprobe | 最新稳定 | ffmpeg.org/download.html | **必须 LGPL 构建**（禁止 `--enable-gpl`），否则分发受限 |
| 反向代理 | Nginx | 最新 stable | nginx.org/en/download.html | 不用 mainline |
| 播放器 | hls.js | 最新稳定 | github.com/video-dev/hls.js/releases | — |
| PDF | PDF.js | 最新稳定 | mozilla.github.io/pdf.js | 定期跟进 CVE |
| 病毒扫描 | ClamAV | 最新稳定 | clamav.net/downloads | 病毒库更新策略需离线方案 |
| 迁移 | golang-migrate 或 goose | 最新稳定 | github.com/golang-migrate/migrate | 单一所有者执行（SAD §9.3） |
| 指标 | Prometheus / Grafana / Loki | 最新稳定 | prometheus.io/download | — |
| 追踪 | OpenTelemetry Go SDK | 最新稳定 | opentelemetry.io/docs/languages/go | — |
| 容器 | Docker Engine / Compose | 最新稳定 | docs.docker.com/engine/release-notes | Windows 桌面版仅开发用 |
| 编排 | Helm / K8s | 与目标客户集群匹配 | helm.sh | SaaS 阶段 |
| 弹性 | KEDA | 最新稳定 | keda.sh | 转码队列伸缩 |
| 证书 | cert-manager | 最新稳定 | cert-manager.io | 白标域名 |

---

## 3. 明确禁止使用

| 禁止项 | 原因 |
|---|---|
| PostgreSQL 19（beta） | 不可用于生产 |
| Node.js 20 及以下 | 已 EOL |
| LibreOffice 26.2.x / 25.8 及以下 | 26.2 于 2026-11-30 EOS；25.8 已 EOL |
| TypeScript 6.x 及以下 | 7.0 已稳定且为官方主线 |
| React 18 及以下 | 19.3 已稳定 |
| Ant Design 5.x | 6.x 已发布并稳定 |
| Vite 7 及以下 | 8.x 已稳定（Rolldown） |
| ONLYOFFICE CE 用于 SaaS 对外销售 | AGPLv3 合规风险，未获法务意见前禁止 |
| 任何 `beta` / `rc` / `alpha` 标签 | 用户规范明令 |
| `latest` 浮动标签（生产镜像） | 不可复现；必须 digest 固定 |

---

## 4. 供应链纪律

1. **镜像固定 digest**：`image@sha256:...`，不用 `:latest`。
2. **Go 依赖**：`go.sum` 必提交；CI 跑 `govulncheck` + `go mod verify`。
3. **npm 依赖**：提交 `package-lock.json`；CI 跑 `npm audit --audit-level=high`。
4. **SBOM**：`syft dir:. -o spdx-json`，随每个 release 产出。
5. **幻觉包防护**：新增依赖前必须确认包存在于官方 registry 且有真实仓库；禁止直接安装模型给出的包名。
6. **EOL 检查**：CI 中执行脚本比对 `endoflife.date` 数据，命中 EOL 即失败。
7. **chi 安全通告跟进**：chi 近期有 7 条 GHSA（含 2026-10-14 一条 low），升级到 5.5.0 后仍需订阅通告。

---

## 5. 回填记录

| 日期 | 组件 | 回填版本 | 核实人 | 备注 |
|---|---|---|---|---|
| 2026-11-08 | Go / chi / pgx / PostgreSQL / Node / React / TS / Vite / antd / LibreOffice / ONLYOFFICE | 见 §1 | — | 本轮设计阶段核实 |
| 2026-11-08 | **postgres:18.6-alpine** | 容器内实测 `PostgreSQL 18.6` | 实测 | 曾用 `postgres:18-alpine` 得到 18.3，已改为精确 tag |
| 2026-11-08 | **golang:1.27.3-alpine / alpine:3.24 / valkey/valkey:8-alpine** | 已拉取到本地 | 实测 | 均为官方镜像 |
| 2026-11-08 | **pgx v5.11.0** | 已写入 go.mod 并通过构建 | 实测 | 经 goproxy.cn 获取 |
| （待填） | 其余 §2 组件 | — | — | 编码首日 |

---

## 6. 本轮偏离记录（必须可见，不许隐藏）

| # | 偏离 | 事实 | 影响 | 处置 |
|---|---|---|---|---|
| DV-01 | 本机 Go 为 **1.26.3**，低于锁定的 1.27.3 | 主机工具链未升级 | 若 `go.mod` 写 `go 1.27.3`，本机无法编译 | `go.mod` 语言版本写 `1.26` 作为编译下限；**构建镜像固定 `golang:1.27.3`**，CI 用 1.27.3 编译并测试。上线前需在本机或 CI 侧确认 1.27.3 双跑通过 |
| DV-02 | 本机 Node 为 **22.22.2**，低于锁定的 24.21.0 LTS | 主机工具链未升级 | 前端尚未开工，暂无实际影响 | 前端里程碑开始前升级，或统一在容器内构建 |
| DV-03 | Docker 镜像拉取 | 首次失败（镜像源 `docker.mirrors.ustc.edu.cn` 已失效 + 官方 registry 直连不可达），**重试后恢复** | 已拉取所需镜像 | daemon.json 已改为 `https://docker.m.daocloud.io` 并备份原文件；**需重启 Docker Desktop 生效**，因有 20 个其他项目容器在跑，未擅自重启 |
| DV-03b | 容器编排已端到端验证 | 2026-11-08 实跑：`docker/` 下 postgres 18.6 + valkey 8 + server 三容器 healthy，`/readyz` 返回 `database: ok` | 无 | 构建期曾因容器内默认 `proxy.golang.org` 不可达导致 `go mod download` 失败，已在 Dockerfile 用 `ARG GOPROXY_URL` 显式指定并允许覆盖 |
| DV-04 | 对象存储 | 官方社区版停止分发 | 见 §1.2 | 已改为本地 FS 默认 + 不打包对象存储镜像 |
| DV-05 | 本机无 `make`、无 `gcc` | **已解决**：winget 安装 WinLibs GCC 16.2.0（UCRT），`go test -race` 已实跑通过 | — | `scripts/check.sh` 会自动探测 WinLibs 路径；本机仍无 `make`，统一用脚本 |
| DV-06 | 本机安装的 ffmpeg 为 `8.1.1-full_build`（含 GPL 组件） | 个人环境便利安装 | 若误打进交付镜像会造成许可污染 | 交付镜像**只允许 LGPL 构建**；构建脚本需断言 `ffmpeg -version` 输出不含 `--enable-gpl` |
| DV-07 | Go 模块代理改为 `goproxy.cn` | 官方 `proxy.golang.org` 返回 502 | 依赖来源变化 | 已登记 §1.4；`go.sum` 保证内容一致性 |
| DV-11 | LibreOffice 版本 | 锁定 26.8.0，Alpine 3.24 官方仓库只有 25.8.7.3 | 格式兼容范围略有差异 | 版本号运行时实测并入缓存 key；交付文档如实标注 25.8 |
| DV-12 | ffmpeg 由源码自建 | 各发行版包均为 GPL 构建（含 libx264） | 无 libx264，CPU 转码用 openh264 | 构建期断言禁止 `--enable-gpl`；remux 路径不受影响 |
| DV-08 | PG 容器版本曾为 18.3 | `postgres:18-alpine` 的缓存标签指向 18.3 | 与锁定 18.6 不一致 | 已改用 `postgres:18.6-alpine`，容器内实测 18.6 |
| DV-09 | Docker 镜像源配置已改但未生效 | 改 daemon.json 需重启 Docker Desktop | 拉取仍可能在下次重启前偶发失败 | 备份文件：`~/.docker/daemon.json.bak-*`；重启时机由用户决定 |

---

## 6.5 本轮新增依赖（M1 后半程）

| 组件 | 锁定版本 | 用途 | 许可证 | 说明 |
|---|---|---|---|---|
| `github.com/go-ldap/ldap/v3` | **v3.4.15** | LDAP/AD 绑定认证与同步 | MIT | 经 `goproxy.cn` 获取，`go.sum` 固定内容 |
| 其传递依赖 | `go-asn1-ber v1.5.8`、`Azure/go-ntlmssp v0.1.1`、`google/uuid v1.6.0` | LDAP 报文与 NTLM 绑定 | MIT/BSD | 间接引入 |

**运行时外部程序（缺失即降级，不阻塞启动）**

| 程序 | 用途 | 缺失时行为 |
|---|---|---|
| `soffice`（LibreOffice 26.8） | Office → PDF 预览 | 预览接口返回 501，前端提示下载查看 |
| `ffmpeg` / `ffprobe` | 音视频转 HLS | 播放接口返回 501，前端提示下载播放 |

**两条许可硬约束**

1. **ffmpeg 必须是 LGPL 构建**。本机为 `8.1.1-full_build`（含 `--enable-gpl`），只用于本地测试；
   交付镜像必须用 LGPL 构建，构建期断言 `ffmpeg -version` 输出不含 `--enable-gpl`。
2. **LibreOffice（MPL-2.0）与 ONLYOFFICE（AGPLv3）许可证不同**，不能互相替代。
   本机未安装 LibreOffice，因此"真实转 PDF"未被验证，只验证了缓存、并发去重与失败降级。

---

## 6.6 交付镜像实际装配（2026-11-08 实测）

| 组件 | 镜像内实际版本 | 与锁定值的关系 |
|---|---|---|
| Go | 1.27.3（构建阶段） | 一致 |
| Alpine | 3.24 | 一致 |
| LibreOffice | **25.8.7.3**（Alpine 官方包） | ⚠️ 低于锁定 26.8.0，记为 DV-11 |
| ffmpeg | **8.1.3（源码自建，`--disable-gpl --enable-libopenh264`）** | 无现成 LGPL 包，按"源码自建"约束构建，记为 DV-12 |
| ONLYOFFICE Docs | **10.0.0**（官方镜像 `onlyoffice/documentserver`） | 一致 |
| openh264 | 2.6.0（运行时库） | 新增 |
| hls.js（前端） | 1.7.4（按需动态加载） | 首版登记为"待锁定"，现锁定 |
| cloudflared（发布） | 官方镜像 `cloudflare/cloudflared:latest`（摘要 `sha256:4955524a…c5ba`，构建 2026-10-30） | 新增 |

**两个刻意的取舍**

1. **不用 Alpine 的 ffmpeg 包**：实测其配置含 `--enable-gpl --enable-libx264`，
   随商业产品分发会带来 GPL 传染与专利风险。改为源码构建并在 Dockerfile 里做**构建期断言**
   （`ffmpeg -version` 不含 `--enable-gpl`，否则镜像构建失败）。
   代价：CPU 转码无 libx264，改用 openh264；源片达标时走 remux，不受影响。
2. **LibreOffice 用 25.8 而非锁定的 26.8**：Alpine 3.24 官方仓库只提供 25.8.7.3。
   按"只用官方镜像/官方安装包/源码"的约束，不自行为一个转换组件拼装源码编译。
   影响是可处理的：渲染器版本号**运行时实测**并进入缓存 key，将来换成 26.x 时旧缓存自然失效。

## 7. 变更记录

| 版本 | 日期 | 变更 |
|---|---|---|
| v1.0 | 2026-11-08 | 首版：11 项已核实 + 14 项待锁定 + 禁止清单 + 供应链纪律 |
| v1.1 | 2026-11-08 | 新增 §6.6 交付镜像实际装配；记录 DV-11（LibreOffice 25.8）/ DV-12（ffmpeg 源码自建 LGPL）/ hls.js 1.7.4 锁定 |
| v1.2 | 2026-11-09 | 登记 cloudflared（公网发布）；见 `10-公网发布（Cloudflare Tunnel）-v1.0.md` |
