-- 邮件服务配置（租户级，可在管理台配置）
--
-- 背景：邮件通道此前只能靠 DOCVAULT_SMTP_* / DOCVAULT_GRAPH_* 环境变量配置，
-- 改一次要动 .env 并重建容器。SaaS 场景下每个租户想用自己的发件邮箱
-- （公司域名、退信进自己的邮箱、SPF/DKIM 自己维护），运维在客户现场
-- 更没有改环境变量的条件。目录认证（0030）已经用同一套思路解决过同类问题，
-- 这里沿用：数据库配置优先，无记录时回退环境变量，保证既有部署不受影响。
--
-- 为什么不塞进 tenant_config.policy：
--   1. 有两个**密文**字段（SMTP 口令、Graph 客户端密钥），jsonb 里混放密文
--      容易在导出/比对/回滚时被当成普通配置；
--   2. 字段多且有取值约束（端口范围、TLS 模式枚举），列约束比约定更可靠。
--
-- 口令/密钥为空表示"沿用已保存的值"（界面不回显，留空即不改）。

CREATE TABLE IF NOT EXISTS mail_config (
    tenant_id uuid PRIMARY KEY REFERENCES tenant(id) ON DELETE CASCADE,

    -- inherit = 用平台/环境变量的默认通道；smtp / graph = 本租户自有通道
    mode      text NOT NULL DEFAULT 'inherit'
        CHECK (mode IN ('inherit', 'smtp', 'graph')),

    from_addr text NOT NULL DEFAULT '',
    from_name text NOT NULL DEFAULT '',
    reply_to  text NOT NULL DEFAULT '',

    -- ---- SMTP ----
    smtp_host text NOT NULL DEFAULT '',
    smtp_port int  NOT NULL DEFAULT 587 CHECK (smtp_port BETWEEN 1 AND 65535),
    smtp_tls  text NOT NULL DEFAULT 'starttls'
        CHECK (smtp_tls IN ('none', 'starttls', 'tls')),
    smtp_user text NOT NULL DEFAULT '',
    smtp_password_enc bytea,
    -- 自签名证书的内网网关才需要；默认 false（关掉校验等于放弃中间人防护）
    smtp_insecure boolean NOT NULL DEFAULT false,
    -- 明文连接 + 带口令时，必须显式勾选，否则拒绝保存（见 Validate）
    smtp_allow_plaintext boolean NOT NULL DEFAULT false,

    -- ---- Exchange Online / Microsoft 365（Graph sendMail）----
    -- 微软已对 Exchange Online 停用 SMTP AUTH 基本认证，Graph 是长期支持路径
    graph_tenant_id     text NOT NULL DEFAULT '',
    graph_client_id     text NOT NULL DEFAULT '',
    graph_client_secret_enc bytea,
    graph_sender        text NOT NULL DEFAULT '',
    -- 主权云/测试环境可覆盖（21Vianet 等）
    graph_login_base    text NOT NULL DEFAULT '',
    graph_base          text NOT NULL DEFAULT '',

    updated_at timestamptz NOT NULL DEFAULT now(),
    updated_by uuid,

    -- 最近一次"发送测试邮件"的结论，供管理员回到页面时看到结果
    last_test_at    timestamptz,
    last_test_to    text,
    last_test_ok    boolean,
    last_test_error text
);

ALTER TABLE mail_config ENABLE ROW LEVEL SECURITY;
ALTER TABLE mail_config FORCE ROW LEVEL SECURITY;
CREATE POLICY mail_config_isolation ON mail_config
    USING (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON mail_config TO docvault_app;

COMMENT ON TABLE mail_config IS
    '租户级邮件通道配置；口令与客户端密钥以 secretbox 密文落库，接口永不回显';

-- 通知队列按租户统计"积压/失败/终止"要给管理员看，避免"用户没收到但没人知道"
CREATE INDEX IF NOT EXISTS ix_notification_status_tenant
    ON notification(tenant_id, status, created_at DESC);
