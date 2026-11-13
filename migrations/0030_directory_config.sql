-- 目录认证配置（LDAP / AD）
--
-- 为什么单独一张表而不是塞进 tenant_config.policy：
--   1. 这里有一个**密文**字段（bind 口令），jsonb 里混放密文容易在导出、
--      比对、回滚时被当成普通配置处理；
--   2. 字段多且都有取值约束，列约束比 jsonb 里"约定俗成"更可靠；
--   3. 未来要多目录并存（PRD-IAM-21）时，这张表加 directory_id 即可扩展，
--      而 policy 里再嵌数组会很快失控。
--
-- 配置优先级：本表有行 → 用本表；无行 → 回退环境变量 DOCVAULT_LDAP_*（兼容既有部署）。

CREATE TABLE directory_config (
    tenant_id             uuid PRIMARY KEY REFERENCES tenant(id) ON DELETE CASCADE,
    enabled               boolean NOT NULL DEFAULT false,

    url                   text NOT NULL DEFAULT '',
    start_tls             boolean NOT NULL DEFAULT false,
    insecure_skip_verify  boolean NOT NULL DEFAULT false,
    ca_pem                text NOT NULL DEFAULT '',
    tls_name              text NOT NULL DEFAULT '',

    bind_dn               text NOT NULL DEFAULT '',
    -- 密文（secretbox）。为空表示服务账号不需要绑定（匿名）或维持原值
    bind_password_enc     bytea,

    base_dn               text NOT NULL DEFAULT '',
    user_filter           text NOT NULL DEFAULT '',
    sync_filter           text NOT NULL DEFAULT '',
    group_filter          text NOT NULL DEFAULT '',
    exclude_accounts      text[] NOT NULL DEFAULT '{}',

    ad_mode               boolean NOT NULL DEFAULT false,
    allow_plaintext       boolean NOT NULL DEFAULT false,
    sync_interval_minutes int NOT NULL DEFAULT 0
        CHECK (sync_interval_minutes >= 0 AND sync_interval_minutes <= 1440),

    updated_at            timestamptz NOT NULL DEFAULT now(),
    updated_by            uuid
);

ALTER TABLE directory_config ENABLE ROW LEVEL SECURITY;
ALTER TABLE directory_config FORCE ROW LEVEL SECURITY;
CREATE POLICY directory_config_isolation ON directory_config
    USING (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON directory_config TO docvault_app;

-- 自动同步调度用：按租户间隔挑出"该跑的人"。
-- 条件是"最近一次成功同步早于 now - interval"，没有索引会退化成全表扫描 + 子查询。
CREATE INDEX ix_sync_ok_tenant ON directory_sync(tenant_id, started_at DESC)
    WHERE status = 'ok';
