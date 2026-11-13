# 本项目专属容器目录

本项目所有容器、数据卷与容器配置都集中在本目录，不散落到其他位置。

```
docker/
├─ docker-compose.yml   唯一真源：全部服务定义
├─ .env                 实际配置（含密钥，不入库）
├─ .env.example         配置模板
├─ server.Dockerfile    API 镜像构建
├─ data/                绑定挂载的数据目录（不入库）
│  └─ postgres/
└─ README.md            本文件
```

## 首次准备

```bash
cd docker
cp .env.example .env
# 填写 POSTGRES_PASSWORD 与 DOCVAULT_JWT_SECRET
#   POSTGRES_PASSWORD: openssl rand -hex 16
#   DOCVAULT_JWT_SECRET: openssl rand -hex 24
```

## 启停

```bash
# 核心依赖（数据库 + 缓存）
docker compose up -d

# 连同 API（需构建镜像）
docker compose --profile app up -d --build

# 查看状态与日志
docker compose ps
docker compose logs -f postgres

# 停止（保留 data/ 内数据）
docker compose down

# 停止并删除数据（危险：会丢库，需二次确认）
docker compose down -v && rm -rf data/postgres
```

## 端口约定

| 服务 | 宿主端口 | 说明 |
|---|---|---|
| postgres | `127.0.0.1:55433` | 仅回环，不对外暴露 |
| redis | `127.0.0.1:56379` | 仅回环 |
| server | `127.0.0.1:8080` | 生产由 gateway 终止 TLS |

使用非默认端口是为避开本机其他项目的 `5432` / `6379` / `8080` 占用。

## 已知坑（都踩过）

1. **PostgreSQL 18 官方镜像的数据目录变了**：`/var/lib/postgresql/18/docker`，挂载点必须是 `/var/lib/postgresql`。挂 `.../data` 会导致容器退出码 1，并在日志里提示 "unused mount/volume"。
2. **镜像源**：本机 `~/.docker/daemon.json` 原有镜像源两个都已失效，已改为 `https://docker.m.daocloud.io`（重启 Docker Desktop 后生效）。
3. **数据目录权限**：`data/postgres` 由容器内 postgres 用户写入；若在 Linux 宿主上出现权限错误，需 `chown -R 999:999 data/postgres`。
4. **不要用 `docker run` 临时起容器**：所有服务必须定义在 `docker-compose.yml` 中，否则会出现"容器在跑但没人知道它从哪来"的情况。

## 镜像纪律

- 只用官方镜像：`postgres` / `valkey` / `golang` / `alpine`。
- 无官方镜像时按官方安装包或源码自建，禁止使用第三方 fork 镜像。
- 对象存储不打包：MinIO 社区版已停止分发，单机默认使用本地 FS 后端，需要 S3 语义时对接客户自有 S3/OSS。

---

## 在线编辑（可选 profile：office）

```bash
docker compose --profile app --profile office up -d
```

| 项 | 值 |
|---|---|
| 镜像 | `onlyoffice/documentserver:10.0.0`（官方镜像） |
| 端口 | `127.0.0.1:18091` |
| 数据 | `data/onlyoffice/{data,log,db,rabbitmq,redis}` |
| 必填配置 | `DOCVAULT_ONLYOFFICE_JWT_SECRET`（`.env`） |

**三个地址必须区分，写错的表现是"编辑器能打开但保存不了"：**

| 变量 | 作用 | 本项目取值 |
|---|---|---|
| `DOCVAULT_PUBLIC_URL` | 浏览器访问本系统 | `http://127.0.0.1:18090` |
| `DOCVAULT_INTERNAL_URL` | 文档服务回调本系统 | `http://docvault-server:8080` |
| `DOCVAULT_ONLYOFFICE_INTERNAL_URL` | 本系统抓取文档服务的回传文件 | `http://docvault-onlyoffice` |

最后一项是必须的：文档服务回传的下载地址是 `http://127.0.0.1:18091/cache/...`（按浏览器访问时的 Host 拼的），
在本服务容器里 127.0.0.1 是它自己，必然 `connection refused`。

`ALLOW_PRIVATE_IP_ADDRESS=true` 也是必须的，否则文档服务拒绝回源到容器网络的私网地址。
