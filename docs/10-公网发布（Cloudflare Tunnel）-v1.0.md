# DocVault 公网发布（Cloudflare Tunnel）v1.0.0

- 日期：2026-11-09 ｜ 状态：**已上线并验证**
- 适用环境：开发/演示环境对外发布（`ndms.neurongene.cn`）
- 关联文档：`03-系统架构设计（SAD）`、`08-运维手册`、`versions.lock.md`

---

## 1. 结论先行

系统已通过 Cloudflare Tunnel 发布到互联网：

| 用途 | 公网地址 | 源站 |
|---|---|---|
| 文档中心（应用） | `https://ndms.neurongene.cn` | `http://docvault-server:8080` |
| 在线编辑（ONLYOFFICE） | `https://office.neurongene.cn` | `http://docvault-onlyoffice:80` |

采用 **命名隧道 + 远程配置（remote config）**：入站规则存在 Cloudflare 侧，源站不保存路由文件，
也不开放任何入站端口。证书、WAF、DDoS 由 Cloudflare 边缘处理，源站链路为出站 QUIC。

---

## 2. 拓扑

```
浏览器 ──HTTPS──▶ Cloudflare 边缘
                    │  (代理 CNAME → <TUNNEL_ID>.cfargotunnel.com)
                    ▼
              cloudflared（本项目容器，出站 QUIC 7844）
                    │  docker 网络 docvault-net
        ┌───────────┴────────────┐
        ▼                        ▼
  docvault-server:8080    docvault-onlyoffice:80
```

关键点：

1. **不需要公网 IP、不需要端口映射**。`127.0.0.1:18090/18091` 的本地映射保留，仅供本机调试。
2. **Cloudflare 到源站不是"回源 HTTP"**，而是隧道；因此源站无需 TLS 证书，
   区域内 SSL 模式保持 `Full`（Cloudflare 侧到隧道为加密链路）。
3. 两个主机名共用**同一条隧道**，靠 ingress 规则分流；未命中的主机名一律 `http_status:404`。

---

## 3. 资源与配置

### 3.1 Cloudflare 侧

| 项 | 值 |
|---|---|
| Zone | `neurongene.cn`（status=active，NS `cecelia/john.ns.cloudflare.com`） |
| Tunnel | `docvault-ndms`（`config_src=cloudflare`） |
| DNS | `ndms` → CNAME `<TUNNEL_ID>.cfargotunnel.com`（Proxied）<br>`office` → 同上（Proxied） |
| SSL 模式 | Full |
| Always Use HTTPS | 开启 |

### 3.2 编排侧

`docker/docker-compose.yml` 新增 `cloudflared` 服务，归属 **`edge` profile**：

- 镜像 `cloudflare/cloudflared:latest`（官方；2026-10-30 构建）
- 指标端口仅绑 `127.0.0.1:18092`
- 不入 `depends_on`：`server` 属于 `app` profile，跨 profile 依赖会让
  `--profile edge` 单独启动直接报错；隧道对源站掉线本身是自愈的

`.env` 新增（不入库）：

```
DOCVAULT_PUBLIC_URL=https://ndms.neurongene.cn
DOCVAULT_TRUST_PROXY_CIDRS=172.25.0.0/16
DOCVAULT_CF_TUNNEL_TOKEN=<隧道令牌>
DOCVAULT_ONLYOFFICE_URL=https://office.neurongene.cn
DOCVAULT_ONLYOFFICE_ALLOWED_HOSTS=office.neurongene.cn,docvault-onlyoffice,onlyoffice,127.0.0.1
```

### 3.3 启停

```bash
docker compose --profile app --profile edge up -d      # 应用 + 隧道
docker compose --profile app up -d                     # 仅应用（本地形态）
docker compose logs -f cloudflared                     # 排障
```

---

## 4. 为什么必须配 `TRUST_PROXY_CIDRS`

这是本次发布暴露出的一个真实缺陷，已修复（`internal/platform/httpmw` 新增 `RealIP`）。

**问题**：`httpapi.clientIP` 只读 `r.RemoteAddr`，而可信代理只在限流键里用了一次。
走隧道后所有请求的对端都是 cloudflared 容器地址，导致：

- 审计日志、水印页脚的来源 IP 全部相同 → 取证信息失效；
- 分享链接的 IP 白名单变成"要么全拦、要么全放"。

**修法**：`httpmw.RealIP(trusted)` 在直连来源可信时把 `r.RemoteAddr` 改写为真实客户端地址，
下游所有既有取 IP 的位置自动正确；`trusted` 为空时完全不采信 `X-Forwarded-For`
（本地直连场景下 XFF 由客户端控制，采信即为伪造）。

**验证**：经公网访问后，`share_visit.ip` 记录为真实出口 IP（此前为 `172.25.0.4`）。

---

## 5. 验收记录（2026-11-09）

| 项 | 结果 |
|---|---|
| `https://ndms.neurongene.cn/` | 200，标题 `DocVault`，真实浏览器渲染正常 |
| 登录（公网路径） | 200 → `/files`，`/v1/me` 返回 `roles=["secadmin","sysadmin"]` |
| 静态资源 | 与镜像内 `web/dist` 哈希一致 |
| 隧道状态 | `healthy`，4 条 QUIC 连接 |
| `office.neurongene.cn` | `api.js` 200（67 KB）、`/healthcheck` 200 |
| 文档服务取文件 | 容器内按签名地址 200，字节数与库中一致；无签名 403 |
| 来源 IP 穿透 | `share_visit.ip` = 真实公网 IP |
| CSP | 仅放行 `'self'` 与 `https://office.neurongene.cn`，无 `127.0.0.1` 残留 |

---

## 6. 已知项与建议

1. **编辑器 UI 未做完整往返验证**：演示数据里的 `.*.docx` 是 9 字节占位文件，
   文档服务取到的是无效 docx。配置与传输链路均已验证，实际打开/保存需用真实 Office 文档复核。
2. **Cloudflare Web Analytics 信标被 CSP 拦截**（`static.cloudflareinsights.com`）。
   对文档系统而言这是**预期行为**：不放行第三方脚本。若控制台提示该域名的统计数据缺失，
   属于正常现象，不建议为此放宽 CSP。
3. **HSTS 未开启**。HSTS 是 zone 级、且 `includeSubDomains` 会影响该域下所有子域，
   需确认无"只提供 HTTP 的其他子域"后再决定，未擅自修改。
4. **`.cn` 域名的合规提示**：以中国大陆为服务对象时，域名对外提供网站服务涉及 ICP 备案；
   若长期对外运营，建议先确认备案状态，避免被注册局或接入方处置。
5. **凭据管理**：本次使用的 Cloudflare API 令牌以明文出现在会话中，
   建议在控制台**轮换**该令牌，并把新令牌只放在 `.env` / 受限目录（`~/.cf-ndms/`，已收紧 ACL）。
6. **隧道令牌即身份**：持有 `DOCVAULT_CF_TUNNEL_TOKEN` 者可顶替本连接器。
   轮换方式：控制台 Rotate token → 更新 `.env` → `docker compose up -d cloudflared`。

---

## 7. 回滚

按影响从小到大：

```bash
# 1) 只停隧道：站点立刻 502/1033，本地服务不受影响
docker compose --profile app stop cloudflared

# 2) 摘除公网入口：删除两条 DNS 记录（或用 API 置 proxied=false）
# 3) 彻底撤销：删除隧道 docvault-ndms（控制台或用 API）
```

源站数据、镜像、数据库均不受影响；回滚不涉及任何内容变更。
