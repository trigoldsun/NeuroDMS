// Command server 是 DocVault 的 API 进程。
//
// 本阶段（M1-1）只提供：配置 fail-fast、健康检查、安全响应头、真实来源 IP 解析。
// 后续按 README §7 的顺序叠加：权限引擎接入 → 身份 → 内容 → 分享 → 预览编辑 → 通知 → 音视频 → 审计。
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"docvault/internal/acmecert"
	"docvault/internal/audit"
	"docvault/internal/auth"
	"docvault/internal/bootstrap"
	"docvault/internal/content"
	"docvault/internal/db"
	"docvault/internal/dept"
	"docvault/internal/directory"
	"docvault/internal/entitlement"
	"docvault/internal/feature"
	"docvault/internal/httpapi"
	"docvault/internal/iam"
	"docvault/internal/integrations"
	"docvault/internal/license"
	"docvault/internal/media"
	"docvault/internal/metering"
	"docvault/internal/mpmsg"
	"docvault/internal/netinfo"
	"docvault/internal/notify"
	"docvault/internal/onlyoffice"
	"docvault/internal/platform/config"
	"docvault/internal/platform/httpmw"
	"docvault/internal/platform/webui"
	"docvault/internal/platformauth"
	"docvault/internal/preview"
	"docvault/internal/scan"
	"docvault/internal/secretbox"
	"docvault/internal/sms"
	"docvault/internal/tenant"
	"docvault/internal/watermark"
	"docvault/migrations"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func main() {
	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	// 根上下文：后台任务（通知重试队列等）挂在它上面，进程退出时统一取消。
	// 不要用 startCtx —— 它会在启动完成后被 cancel，后台任务会被一起干掉。
	rootCtx, rootStop := context.WithCancel(context.Background())
	defer rootStop()

	cfg, err := config.Load(os.Getenv)
	if err != nil {
		// 配置错误属于部署期故障，必须显式退出而不是带默认值硬跑
		log.Error("配置校验失败，拒绝启动", "err", err.Error())
		os.Exit(2)
	}

	trusted, err := parsePrefixes(cfg.TrustProxyCIDRs)
	if err != nil {
		log.Error("可信代理网段非法", "err", err.Error())
		os.Exit(2)
	}

	// ---- 数据库：连接 → 迁移 → RLS 自检 ----
	// 顺序不可颠倒：迁移未完成就开工会让后续请求打在错误结构上；
	// RLS 自检不通过则说明有人新增了表却没加隔离，必须拒绝启动。
	var pool *pgxpool.Pool
	if cfg.DBDSN != "" {
		startCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		pool, err = db.Connect(startCtx, cfg.DBDSN)
		if err != nil {
			cancel()
			log.Error("数据库连接失败，拒绝启动", "err", err.Error())
			os.Exit(2)
		}
		defer pool.Close()

		applied, err := db.Migrate(startCtx, pool, migrations.Files)
		if err != nil {
			cancel()
			log.Error("数据库迁移失败，拒绝启动", "err", err.Error())
			os.Exit(2)
		}
		if len(applied) > 0 {
			log.Info("已应用迁移", "versions", applied)
		}

		missing, err := db.AssertRLSCoverage(startCtx, pool)
		if err != nil {
			cancel()
			log.Error("RLS 自检无法完成，拒绝启动", "err", err.Error())
			os.Exit(2)
		}
		if len(missing) > 0 {
			cancel()
			tables := make([]string, 0, len(missing))
			for _, m := range missing {
				tables = append(tables, m.Table+"("+m.Reason+")")
			}
			log.Error("RLS 自检失败：以下表带 tenant_id 但缺少行级隔离，拒绝启动", "tables", tables)
			os.Exit(2)
		}
		// 权限模型自检（只告警，不阻止启动）。
		//
		// 当前部署以 docvault（超级用户/带 BYPASSRLS）连接，隔离靠
		// WithTenant 里的 SET LOCAL ROLE docvault_app 生效——也就是说，
		// **任何绕过 WithTenant 的查询都拥有跨租户读能力，且没有任何数据库层兜底**。
		// 这不是缺陷本身（平台级函数确实需要高权限），但它是"必须让运维看见"的前提：
		// 否则一次疏忽（在新 handler 里直接用连接池）就会静默变成跨租户越权。
		//
		// 彻底的做法是让业务连接改用 docvault_app、另开一个管理连接给平台函数；
		// 在那之前，至少让这条前提出现在启动日志里。
		var elevated bool
		if qerr := pool.QueryRow(startCtx,
			`SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname = current_user`).Scan(&elevated); qerr == nil && elevated {
			log.Warn("数据库连接角色为超级用户或带 BYPASSRLS：行级隔离仅在 WithTenant 事务内生效，" +
				"请求路径不得直接使用连接池查询（详见 docs/28）")
		}
		cancel()
		log.Info("数据库就绪：迁移与 RLS 自检通过")

		// 空库时创建演示账号（生产默认关闭）
		if cfg.DevSeed {
			if cfg.DevAdminPassword == "" {
				log.Warn("已开启种子数据但未设置 DOCVAULT_DEV_ADMIN_PASSWORD，跳过")
			} else {
				// 独立上下文：startCtx 在迁移完成后已 cancel，
				// 复用它会让种子操作立刻返回 context canceled 并拖入重启循环。
				seedCtx, seedCancel := context.WithTimeout(context.Background(), 20*time.Second)
				res, seedErr := bootstrap.SeedDemo(seedCtx, pool, cfg.DevTenantSlug, cfg.DevAdminUser, cfg.DevAdminPassword)
				seedCancel()
				if seedErr != nil {
					log.Error("种子数据初始化失败", "err", seedErr.Error())
					os.Exit(2)
				}
				if res.Created {
					log.Info("已创建演示账号", "tenant", res.TenantSlug, "user", res.AdminUser)
				}
			}
		}
	} else {
		log.Warn("未配置 DOCVAULT_DB_DSN，以无数据库模式启动（仅开发用途）")
	}

	mux := http.NewServeMux()

	// tlsCertFor 由下面的业务装配块注入：按 SNI 从租户域名取证书。
	// 为空表示本进程不终止 TLS（走隧道或反向代理的部署）。
	var tlsCertFor func(*tls.ClientHelloInfo) (*tls.Certificate, error)
	// acmeRenewer 供启动后的续期协程使用（装配块内创建）。
	var acmeRenewer *acmecert.Service

	// ---- 业务路由：需要数据库与有效签名密钥 ----
	if pool != nil {
		if len(cfg.JWTSecret) < 32 {
			log.Warn("未配置有效的 DOCVAULT_JWT_SECRET（需≥32字节），认证与分享接口未启用")
		} else {
			store, err := content.New(pool, cfg.StorageDir)
			if err != nil {
				log.Error("内容存储初始化失败，拒绝启动", "err", err.Error(), "dir", cfg.StorageDir)
				os.Exit(2)
			}
			authSvc := auth.New(pool, []byte(cfg.JWTSecret), auth.DefaultConfig())

			// 短信认证服务（阿里云 PNVS）。三种状态都要显式：
			// 已配置 / 未配置（功能关闭）/ 配置了但启用失败（打日志，不阻断启动——
			// 短信登录只是登录方式之一，不该让整个系统起不来）。
			var platformSMS sms.Provider
			switch {
			case cfg.SMSMock:
				if cfg.Mode == "production" {
					log.Error("生产环境禁止使用短信 mock（DOCVAULT_SMS_MOCK=1），拒绝启动")
					os.Exit(2)
				}
				platformSMS = sms.NewMock("123456")
				log.Warn("短信认证服务使用模拟通道（固定验证码 123456），仅限开发环境")
			case cfg.SMSAccessKeyID != "":
				p, serr := sms.NewAliyun(
					cfg.SMSAccessKeyID, cfg.SMSAccessKeySecret,
					cfg.SMSSignName, cfg.SMSTemplateCode, cfg.SMSSchemeName)
				if serr != nil {
					log.Error("短信认证服务配置不完整，短信登录未启用", "err", serr.Error())
				} else {
					platformSMS = p
					log.Info("短信认证服务已启用（阿里云 dypnsapi）")
				}
			default:
				log.Info("短信认证服务未配置（DOCVAULT_SMS_* 为空），短信登录不可用")
			}
			// 配置加密密钥：证书私钥与目录服务账号口令都用它。
			// 在这里创建（只依赖 cfg），后面几处复用同一个实例。
			box, boxErr := secretbox.New(cfg.SecretKey)
			if boxErr != nil {
				log.Warn("配置加密未启用（自定义域名证书、目录服务账号口令将无法保存）", "reason", boxErr.Error())
			}

			// 凭证中心：第三方服务的租户级配置（短信/SSO/在线编辑…）。
			// 必须在短信服务之前建：短信服务要按租户读 integration_config。
			integReg := integrations.NewRegistry()
			sms.Register(integReg)
			integStore := integrations.NewStore(pool, box, integReg)
			// 短信服务：租户自带通道优先，否则平台环境变量通道（platformSMS）。
			// key 用 JWT 密钥派生：验证码只存 HMAC，需要一个进程级秘密。
			smsSvc := sms.NewService(pool, integStore, []byte(cfg.JWTSecret), platformSMS)
			authSvc.SetSMS(smsSvc)

			// 目录认证：配置优先取数据库（管理台可改），无记录时回退环境变量。
			// 必须按租户解析：不同租户可能接不同的域；启动时固定一个连接
			// 会让"改了配置要重启"重新出现。
			dirStore := directory.NewStore(pool, box)
			var envDir *directory.Settings
			if cfg.LDAPURL != "" && cfg.LDAPBaseDN != "" {
				envDir = &directory.Settings{
					Enabled: true, URL: cfg.LDAPURL, StartTLS: cfg.LDAPStartTLS,
					InsecureSkipVerify: cfg.LDAPInsecure, TLSName: cfg.LDAPTLSName,
					BindDN: cfg.LDAPBindDN, BindPassword: cfg.LDAPBindPassword,
					BaseDN: cfg.LDAPBaseDN, UserFilter: cfg.LDAPUserFilter,
					SyncFilter: cfg.LDAPSyncFilter, GroupFilter: cfg.LDAPGroupFilter,
					ExcludeAccounts: cfg.LDAPExcludeAccounts, ADMode: cfg.LDAPADMode,
					AllowPlaintext: cfg.LDAPAllowPlaintext,
				}
				if cfg.LDAPCAFile != "" {
					if raw, rerr := os.ReadFile(cfg.LDAPCAFile); rerr == nil {
						envDir.CAPEM = string(raw)
					} else {
						log.Warn("读取 LDAP CA 证书失败（将按系统信任库校验）", "err", rerr.Error())
					}
				}
			}
			dirResolver := directory.NewResolver(dirStore, envDir)
			dirRunner := directory.NewRunner(pool, dirResolver, log)
			authSvc.SetDirectory(bootstrap.TenantDirectory{Res: dirResolver})
			if envDir != nil {
				log.Info("LDAP/AD 认证已启用来源：环境变量", "base", cfg.LDAPBaseDN, "ad", cfg.LDAPADMode)
			} else {
				log.Info("目录认证未配置（可在管理台「系统设置 · 目录认证」启用）")
			}
			go dirRunner.RunScheduler(rootCtx, 5*time.Minute)

			// IP 归属地：配了 mmdb 才启用；没配只显示"内网/公网"。
			// 缺库不能让启动失败——它是访问记录里的附加信息，不是功能前提。
			geo, gerr := netinfo.Open(cfg.GeoIPDB)
			if gerr != nil {
				log.Warn("IP 归属地未启用（数据库无法打开）", "path", cfg.GeoIPDB, "err", gerr.Error())
			} else if geo != nil {
				defer func() { _ = geo.Close() }()
				log.Info("IP 归属地已启用", "db", cfg.GeoIPDB)
			}

			// 租户服务：这里就需要它——邮件主题与发件人显示名要用租户自己的系统名称。
			// 之前是在 M3 区块才创建，导致通知装配拿不到品牌。
			tenantSvc := tenant.New(pool)

			// 本地版许可证：只验签，不联网。
			// 公钥为空 = 云端版，不接受许可证（界面显示"无需许可证"）。
			var licPub ed25519.PublicKey
			if cfg.LicensePublicKey != "" {
				pk, lerr := license.ParsePublicKey(cfg.LicensePublicKey)
				if lerr != nil {
					// 公钥写错不阻断启动，但必须显眼：否则客户以为导入的许可证生效了，
					// 实际每次验签都失败。
					log.Error("许可证公钥无效，许可证功能未启用", "err", lerr.Error())
				} else {
					licPub = pk
					log.Info("许可证校验已启用", "pub", license.MaskKey(cfg.LicensePublicKey))
				}
			}
			licMgr := license.NewManager(pool, licPub)
			if licMgr.Enabled() {
				// 启动时把已存许可证重新应用一次：容器重建后租户档位可能来自旧备份，
				// 幂等地写回"许可证声明的档位"比依赖人工核对可靠。
				var primaryTenant string
				if e := pool.QueryRow(context.Background(),
					`SELECT id::text FROM tenant
					  WHERE deleted_at IS NULL ORDER BY created_at LIMIT 1`).Scan(&primaryTenant); e == nil {
					if e := licMgr.Reapply(context.Background(), primaryTenant); e != nil {
						log.Warn("许可证重放失败（不影响启动，界面会显示原因）", "err", e.Error())
					}
				}
			}

			// 自动签发证书（ACME）。配置写错必须**拒绝启动**：
			// 把 "http-01" 拼成 "http01 " 当成 off 处理，客户会以为开了自动续期，
			// 直到证书过期那天才发现——这类"静默降级"比启动失败贵得多。
			acmeMode, acmeErr := acmecert.ParseMode(cfg.ACMEMode)
			if acmeErr != nil {
				log.Error("ACME 配置错误，拒绝启动", "err", acmeErr.Error())
				os.Exit(2)
			}
			acmeSvc := acmecert.New(pool, box, acmecert.Config{
				Mode:         acmeMode,
				Email:        cfg.ACMEEmail,
				DirectoryURL: cfg.ACMEDirectoryURL,
				HTTP01Addr:   cfg.ACMEHTTPAddr,
			}, func(ctx context.Context, tenantID, host, certPEM string, keyPEM []byte) error {
				// 与手工上传走**同一个**写入路径：证书校验、私钥加密、AAD 绑定
				// 都只有一份实现，不会出现"自动签的证书握手失败"这种分叉故障。
				_, err := tenantSvc.SetCertificateFrom(ctx, box, tenantID, host, certPEM, keyPEM, "acme")
				return err
			})
			acmeRenewer = acmeSvc
			if err := acmeSvc.Start(context.Background()); err != nil {
				// 不退出：证书由反代/边缘托管的部署照样要能跑。
				// 失败原因会通过 Status 显示在页面上（见 acmecert.startErr）。
				log.Error("ACME 挑战端口监听失败，自动签发不可用", "err", err.Error())
			} else if acmeMode != acmecert.ModeOff {
				log.Info("自动签发已启用", "mode", string(acmeMode),
					"directory", acmeSvc.Status().DirectoryURL)
			}

			// 按 SNI 取证书（只有本进程终止 TLS 时才用到）。
			if cfg.TLSListen != "" {
				tlsCertFor = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
					c, cerr := tenantSvc.CertificateFor(context.Background(), box, hello.ServerName)
					if cerr == nil {
						return c, nil
					}
					// 没有匹配的租户域名时回落到默认证书（例如主站域名）。
					if cfg.TLSFallbackCert != "" && cfg.TLSFallbackKey != "" {
						fb, ferr := tls.LoadX509KeyPair(cfg.TLSFallbackCert, cfg.TLSFallbackKey)
						if ferr == nil {
							return &fb, nil
						}
					}
					// 两者都没有：让握手失败。返回一张自签证书会训练用户忽略证书告警。
					return nil, fmt.Errorf("没有为 %q 配置证书", hello.ServerName)
				}
			}

			// 邮件通道：环境变量是平台默认，租户可在管理台配置自己的发件邮箱。
			// 配置里有密文口令，与证书私钥共用同一个加密实例。
			mailStore := notify.NewStore(pool, box)

			// 通知通道：配了就接上二次验证；没配则 mfa_required 账号拒登（fail-closed）
			notifier, nerr := bootstrap.BuildNotifier(&cfg, pool, mailStore,
				func(ctx context.Context, tenantID string) string {
					slug, err := tenantSvc.SlugOf(ctx, tenantID)
					if err != nil {
						return ""
					}
					b, err := tenantSvc.BrandingBySlug(ctx, slug)
					if err != nil {
						return ""
					}
					return b.ProductName
				}, log)
			if nerr != nil {
				log.Error("通知通道装配失败，拒绝启动", "err", nerr.Error())
				os.Exit(2)
			}
			// 分享链接的邮件外发复用它：Outbox 为空时"邮件分享"会明确返回不可用
			var notifierOutbox *notify.Outbox
			var mailRouter *notify.Router
			if notifier == nil {
				log.Warn("未配置 SMTP/Graph，外部账号（mfa_required）将无法登录；邮件分享不可用")
			} else {
				notifierOutbox = notifier.Outbox
				mailRouter = notifier.Router
				bootstrap.SetupMFA(authSvc, pool, []byte(cfg.JWTSecret), notifier)
				// 后台重试队列：进程退出时随根 ctx 一起停
				go notifier.Outbox.Run(rootCtx, 5*time.Second)
			}

			// 在线预览：装没装 LibreOffice 决定能力，装不上就降级（不阻止启动）
			var prevCache *preview.Cache
			if cfg.PreviewEnabled {
				if lo := preview.NewLibreOffice(cfg.PreviewDir); lo != nil {
					c, perr := preview.NewCache(cfg.PreviewDir, lo)
					if perr != nil {
						log.Warn("预览缓存初始化失败，在线预览不可用", "err", perr.Error())
					} else {
						prevCache = c
						log.Info("在线预览已启用", "renderer", lo.Name(), "dir", cfg.PreviewDir)
					}
				} else {
					log.Warn("未找到 LibreOffice(soffice)，Office 文档预览将提示下载查看")
				}
			}

			// RAW 预览：需要 LibRaw（dcraw_emu）+ ffmpeg。缺任何一个都只是"不支持 RAW"，
			// 不影响其他类型——所以失败只记日志，不阻止启动。
			var rawRenderer *preview.RawRenderer
			if rr, rerr := preview.NewRawRenderer(preview.RawOptions{
				CacheDir:      filepath.Join(cfg.StorageDir, "..", "rawcache"),
				MaxEdge:       2400,
				Quality:       3,
				MaxConcurrent: 2, // 单张峰值 644MB，2 并发是 8GB 机器上的安全值
				Timeout:       120 * time.Second,
			}); rerr != nil {
				log.Warn("RAW 预览未启用（缺 LibRaw 或 ffmpeg）", "err", rerr.Error())
			} else {
				rawRenderer = rr
				log.Info("RAW 预览已启用", "renderer", rr.Name())
			}

			// 在线编辑：未配置文档服务时整个编辑能力关闭，前端不显示编辑入口
			office := onlyoffice.New(onlyoffice.Config{
				URL: cfg.OfficeURL,
				// 文档服务抓文件、回调都走容器网络内部地址，
				// 不能用浏览器那份 127.0.0.1（在它眼里是自己）
				PublicURL:        cfg.InternalURL,
				Secret:           cfg.OfficeJWTSecret,
				InternalURL:      cfg.OfficeInternalURL,
				AllowedHosts:     cfg.OfficeAllowedHosts,
				MaxCallbackBytes: 512 << 20,
			})
			if office != nil {
				log.Info("在线编辑已启用", "documentServer", cfg.OfficeURL,
					"allowedHosts", cfg.OfficeAllowedHosts)
			}

			// 音视频：没有 ffmpeg 时整个播放能力关闭（前端降级为下载）
			var mediaSvc *media.Service
			if cfg.MediaEnabled {
				concurrency := cfg.MediaConcurrency
				if concurrency <= 0 {
					concurrency = runtime.NumCPU() / 2
					if concurrency < 1 {
						concurrency = 1
					}
				}
				if err := os.MkdirAll(cfg.MediaDir, 0o750); err != nil {
					log.Warn("媒体目录创建失败，音视频播放不可用", "err", err.Error())
				} else {
					mediaSvc = media.New(media.Config{
						Dir:           cfg.MediaDir,
						Secret:        cfg.JWTSecret,
						PublicURL:     cfg.OfficePublicURL,
						MaxConcurrent: concurrency,
					})
					if mediaSvc != nil {
						log.Info("音视频播放已启用", "dir", cfg.MediaDir, "concurrency", concurrency)
					} else {
						log.Warn("未找到 ffmpeg/ffprobe，音视频将提示下载播放")
					}
				}
			}

			// 日结锚点：每小时尝试结算"昨天"，幂等，重启不会重复
			anchorSecret := []byte(cfg.AnchorSecret)
			if len(anchorSecret) == 0 {
				anchorSecret = []byte(cfg.JWTSecret)
				log.Warn("未配置 DOCVAULT_ANCHOR_SECRET，暂用 JWT 密钥签名锚点（建议分开）")
			}
			go audit.RunDailyAnchors(rootCtx, pool, anchorSecret, log, time.Hour)
			// 日志保留期清理：只删被日结锚点覆盖的前缀（默认 2 年，可按租户配置）
			go audit.RunRetention(rootCtx, pool, log, 6*time.Hour)

			// 水印初始化：资源目录不可用是致命的（服务无法出带水印的预览）；
			// 中文字体缺失只降级为 ASCII（仍然有水印，只是不显示中文名）。
			wm, werr := watermark.New(cfg.WatermarkDir, cfg.WatermarkFont)
			if wm == nil {
				log.Error("水印初始化失败，拒绝启动（预览必须带水印）", "err", werr)
				os.Exit(2)
			}
			if werr != nil {
				log.Warn("水印已降级为 ASCII（中文名不会显示）", "err", werr)
			} else {
				log.Info("水印已启用", "cjkFont", wm.HasCJKFont(), "font", cfg.WatermarkFont)
			}

			// ---- M3：多租户 SaaS 能力 ----
			meterSvc := metering.New(pool)
			featureSvc := feature.New(pool)
			// 能力授权：档位默认 + 单租户特批 + 平台强制关（docs/47）。
			// 三个消费方共用同一个实例，避免"解析口径不一致"这种最难查的问题。
			entSvc := entitlement.New(pool)
			tenantSvc.SetEntitlements(entSvc)
			authSvc.SetEntitlements(entSvc)
			platformAuth := platformauth.New(pool)

			// 平台账号初始化：空表时才建。口令来自环境变量，不写进镜像。
			if cfg.PlatformAdminEmail != "" {
				created, berr := platformAuth.Bootstrap(rootCtx, cfg.PlatformAdminEmail,
					cfg.PlatformAdminPassword, "平台运营")
				if berr != nil {
					log.Error("平台账号初始化失败", "err", berr)
					os.Exit(2)
				}
				if created {
					log.Info("已创建首个平台运营账号", "email", cfg.PlatformAdminEmail)
				}
			}

			// 证书私钥加密复用上面创建好的 box（未配置密钥时功能不可用，而不是明文落库）
			// API 调用计量：进程内聚合，定期落库。
			// 这是运营观察指标，不是计费口径（计费按存储与用户数，由触发器保证精确）。
			go func() {
				t := time.NewTicker(10 * time.Second)
				defer t.Stop()
				for {
					select {
					case <-rootCtx.Done():
						flushCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
						_ = meterSvc.FlushAPICalls(flushCtx)
						cancel()
						return
					case <-t.C:
						flushCtx, cancel := context.WithTimeout(rootCtx, 5*time.Second)
						if err := meterSvc.FlushAPICalls(flushCtx); err != nil {
							log.Warn("API 用量落库失败（下轮重试）", "err", err)
						}
						cancel()
					}
				}
			}()

			// 过期上传会话清理：断点续传的复用时窗是 24 小时，
			// 超过之后这些会话不会被再复用，但分片文件仍占磁盘。
			// 启动时先跑一次，避免"部署前积压的孤儿会话"再等一整个周期。
			go func() {
				prune := func() {
					pctx, cancel := context.WithTimeout(rootCtx, 2*time.Minute)
					defer cancel()
					n, err := store.PruneStaleSessions(pctx, 24*time.Hour)
					if err != nil {
						log.Warn("清理过期上传会话失败（下轮重试）", "err", err)
					} else if n > 0 {
						log.Info("已清理过期上传会话", "count", n)
					}

					// 分享口令尝试记录：锁定过期后只剩排查价值，留 30 天。
					// 与上传会话共用这一轮任务——不值得为一行 DELETE 再起一个定时器。
					var pruned int64
					if err := pool.QueryRow(pctx,
						`SELECT platform_prune_share_attempts($1)`, 30*24*time.Hour).Scan(&pruned); err != nil {
						log.Warn("清理分享口令尝试记录失败（下轮重试）", "err", err)
					} else if pruned > 0 {
						log.Info("已清理分享口令尝试记录", "count", pruned)
					}
				}
				prune()
				t := time.NewTicker(6 * time.Hour)
				defer t.Stop()
				for {
					select {
					case <-rootCtx.Done():
						return
					case <-t.C:
						prune()
					}
				}
			}()

			// 域身份单点登录：配置不成立时 Enabled 为 false 并带原因，
			// 接口自然不可用（fail-closed），不会出现"配错但还在跑"
			ssoSettings := httpapi.NewSSOSettings(cfg.SSOEnabled, cfg.SSOHeader, cfg.SSOSecret,
				cfg.SSOTrustedCIDRs, cfg.SSODefaultTenant, log)
			if ssoSettings.Enabled {
				log.Info("域身份单点登录已启用", "header", ssoSettings.Header,
					"tenant", ssoSettings.DefaultTenant)
			} else if cfg.SSOEnabled {
				log.Warn("域身份单点登录未生效", "reason", ssoSettings.Reason)
			}

			// 小程序订阅消息：字段映射与跳转版本先校验再装配。
			// 配错必须在**启动时**失败——跑到线上才报 47003，
			// 现象是"用户授权成功、余额扣了、消息永远不到"，最难查。
			mpFields, ferr := mpmsg.ParseFields(cfg.WxTodoFields)
			if ferr != nil {
				log.Error("DOCVAULT_WX_TODO_FIELDS 配置非法，拒绝启动", "err", ferr.Error())
				os.Exit(2)
			}
			mpState, serr := mpmsg.ParseMPState(cfg.WxMPState)
			if serr != nil {
				log.Error("DOCVAULT_WX_MP_STATE 配置非法，拒绝启动", "err", serr.Error())
				os.Exit(2)
			}
			mpSvc := mpmsg.New(mpmsg.Config{
				AppID: cfg.WxAppID, AppSecret: cfg.WxAppSecret,
				TodoTemplateID: cfg.WxTodoTemplateID,
				Fields:         mpFields, MPState: mpState,
			}, pool)
			if mpSvc.Enabled() {
				log.Info("小程序审批提醒已启用", "template", cfg.WxTodoTemplateID, "state", mpState)
			} else {
				log.Info("小程序审批提醒未启用（缺 DOCVAULT_WX_APPID/_APPSECRET/_TODO_TEMPLATE）")
			}

			api := &httpapi.API{
				Pool:          pool,
				Auth:          authSvc,
				Content:       store,
				Preview:       prevCache,
				Raw:           rawRenderer,
				Office:        office,
				Media:         mediaSvc,
				MetricsToken:  cfg.MetricsToken,
				PlatformToken: cfg.PlatformToken,
				Scanner:       scan.New(cfg.ClamAVAddr, time.Duration(cfg.ClamAVTimeout)*time.Second),
				// 预览一律叠加溯源水印（AC-55）：这是"通过预览取回原件"的唯一防线
				Watermark:    wm,
				Tenants:      tenantSvc,
				IAM:          iam.New(pool),
				Depts:        dept.New(pool),
				Metering:     meterSvc,
				Features:     featureSvc,
				Entitlements: entSvc,
				Acme:         acmeSvc,
				License:      licMgr,
				PlatformAuth: platformAuth,
				Outbox:       notifierOutbox,
				Mail:         mailStore,
				MailRouter:   mailRouter,
				Geo:          geo,
				// 小程序订阅消息：三项微信配置缺一即整体关闭（Enabled()=false），
				// 分享创建时只做一次"跳过"判断，不会产生外呼。
				MP:            mpSvc,
				SecretBox:     box,
				SMS:           smsSvc,
				SMSConfigured: platformSMS != nil,
				Integrations:  integStore,
				Directory:     dirStore,
				DirResolver:   dirResolver,
				DirRunner:     dirRunner,
				SSO:           ssoSettings,
				Log:           log,
				// 外发链接的对外地址：邮件里的分享链接必须指向公网域名，
				// 不能用请求头推导（反代后面拿到的常是内网 Host）
				PublicBaseURL: cfg.OfficePublicURL,
			}
			// 审计与业务同事务写入；写不进审计则请求失败（fail-closed）
			api.OnAudit = func(ctx context.Context, tenantID string, ev httpapi.AuditEntry) error {
				return db.WithTenant(ctx, pool, tenantID, func(tx pgx.Tx) error {
					return audit.Append(ctx, tx, tenantID, audit.Event{
						ActorID: ev.ActorID, ActorType: ev.ActorType, Action: ev.Action,
						ObjectType: ev.ObjectType, ObjectID: ev.ObjectID,
						Result: ev.Result, Detail: ev.Detail,
						IP: ev.IP, RequestID: ev.RequestID,
					})
				})
			}
			api.Register(mux)
			log.Info("业务接口已启用", "routes", "auth/shares/share-public/content", "storage", cfg.StorageDir)
		}
	}
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		checks := map[string]string{"config": "ok"}

		// 数据库就绪：真实探活，不靠"进程还活着"冒充
		if pool != nil {
			cctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
			defer cancel()
			if err := pool.Ping(cctx); err != nil {
				checks["database"] = "unavailable: " + err.Error()
				writeJSON(w, http.StatusServiceUnavailable, map[string]any{
					"status": "not_ready", "mode": cfg.Mode, "checks": checks,
				})
				return
			}
			checks["database"] = "ok"
		} else {
			checks["database"] = "skipped（未配置 DSN）"
		}

		writeJSON(w, http.StatusOK, map[string]any{
			"status": "ready",
			"mode":   cfg.Mode,
			"checks": checks,
		})
	})
	mux.HandleFunc("/version", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"name": "docvault", "mode": cfg.Mode})
	})
	// 前端静态资源（未构建时自动降级为 404，不影响纯 API 使用）
	spa := webui.New(cfg.WebDir)
	if spa.Available() {
		log.Info("前端资源已挂载", "dir", cfg.WebDir)
	} else {
		log.Warn("未找到前端产物，仅提供 API", "dir", cfg.WebDir)
	}

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// API 命名空间下的未知路径仍返回 JSON，避免前端路由吞掉接口错误
		if strings.HasPrefix(r.URL.Path, "/v1/") {
			writeJSON(w, http.StatusNotFound, map[string]any{
				"code": "NOT_FOUND", "message": "not found", "route": r.URL.Path,
			})
			return
		}
		if !spa.Available() {
			writeJSON(w, http.StatusNotFound, map[string]any{
				"code": "NOT_FOUND", "message": "not found",
				"hint": "前端未构建：npm run build", "route": r.URL.Path,
			})
			return
		}
		spa.ServeHTTP(w, r)
	})

	// 限流：分四档而不是一刀切（E2E 验收 F-06）。
	//
	// 早先登录与外链共用一个 2 rps 的桶，结果是**两件互不相干的事互相误伤**：
	// 同一办公网 10 人早上同时登录会 429；外链页首屏（兑换 + 票据 + 列表）连发也会 429。
	// 分档依据见 httpmw.DefaultRules 的注释与 docs 技术文档 7.1「环境变量」表。
	limiter := httpmw.RateLimitRules(httpmw.DefaultRules(httpmw.Limits{
		API:         cfg.RateRPS,
		APIBurst:    cfg.RateBurst,
		Public:      cfg.PublicRateRPS,
		PublicBurst: cfg.PublicRateBurst,
		Login:       cfg.LoginRateRPS,
		LoginBurst:  cfg.LoginRateBurst,
		Ticket:      cfg.TicketRateRPS,
		TicketBurst: cfg.TicketRateBurst,
	}, trusted))

	// RealIP 放在访问日志之外：否则日志里的 ip 字段永远是反向代理地址。
	// 它只改 r.RemoteAddr，后续所有取来源 IP 的地方（审计、IP 白名单、水印、限流）
	// 都自动拿到真实客户端地址。
	handler := httpmw.RequestID(
		httpmw.Recover(log)(
			httpmw.RealIP(trusted)(
				httpmw.AccessLog(log)(
					limiter(
						httpmw.SecurityHeadersFor(cfg.OfficeURL)(mux))))))

	srv := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		// ReadTimeout 是**整个请求体**的读取时限，不是"两次读之间"的空闲时限。
		//
		// 原来是 60 秒，后果是：移动网络上行约 250 Kbps 时，一个 4 MB 的文件要传 130 秒，
		// 60 秒就被服务端掐断；客户端看到的是 400「请使用 multipart/form-data 上传」，
		// 排查方向被完全带偏（以为是格式或编码问题）。实测日志里就是 dur_ms=60000 + 400。
		//
		// 放到 10 分钟：8 MB 分片在最差的上行速率下也够用，同时不给慢速攻击留无限窗口。
		// 真正防大包的是 MaxBytesReader 与租户配额，不靠这个值。
		ReadTimeout:  10 * time.Minute,
		WriteTimeout: 0, // 大文件流式下载不能有整体写超时
		IdleTimeout:  120 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		log.Info("server listening", "addr", cfg.HTTPAddr, "mode", cfg.Mode, "trusted_proxies", len(trusted))
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	// 证书续期：每 12 小时扫一次"30 天内到期且由我方签发"的域名。
	// 放在启动之后而不是之前：续期要联网，失败不该影响服务起来。
	if acmeRenewer != nil {
		go acmeRenewer.RenewLoop(ctx, 12*time.Hour, log)
	}

	// 可选 HTTPS 监听：证书按 SNI 从 tenant_domain 取。
	// 只有"域名直指本机"的部署才需要它；隧道/反代部署保持 DOCVAULT_TLS_LISTEN 为空。
	if cfg.TLSListen != "" && tlsCertFor != nil {
		tlsSrv := &http.Server{
			Addr:    cfg.TLSListen,
			Handler: handler,
			TLSConfig: &tls.Config{
				GetCertificate: tlsCertFor,
				MinVersion:     tls.VersionTLS12,
			},
			ReadHeaderTimeout: 10 * time.Second,
			ReadTimeout:       10 * time.Minute,
			IdleTimeout:       120 * time.Second,
		}
		go func() {
			log.Info("HTTPS 监听已启动", "addr", cfg.TLSListen)
			// 证书来自 GetCertificate，所以文件名传空串（Go 支持这种用法）。
			if err := tlsSrv.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Error("HTTPS 监听异常退出", "err", err.Error())
			}
		}()
	}

	select {
	case err := <-errCh:
		log.Error("服务异常退出", "err", err.Error())
		os.Exit(1)
	case <-ctx.Done():
		log.Info("收到停止信号，开始排空在途请求")
	}

	// 优雅停机：先停止接收新请求，再给存量请求 30 秒排空窗口
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Error("排空超时，强制退出", "err", err.Error())
		os.Exit(1)
	}
	log.Info("已退出")
}

func parsePrefixes(raw []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(raw))
	for _, s := range raw {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
