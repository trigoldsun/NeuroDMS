-- 0053_integrations.sql
--
-- 凭证中心与短信本地核验（docs/47 §4.4–4.5）。
--
-- 两件事分开说：
--
-- 1) integration_config：把"第三方服务凭证"从环境变量搬到租户级配置。
--    形态与已有的 mail_config / directory_config 一致（密文落库、只写不读），
--    但不重写那两张表——它们已经跑通、有测试、有错误分类，
--    为了"表结构统一"重写线上配置是零收益的冒险。
--
-- 2) sms_code：非阿里云通道没有"核验"接口，验证码必须由我方生成并核验。
--    这里只存 HMAC，不存明文；单行覆盖旧码；消费原子化。
--
-- 存量行为不变：没有任何 integration_config 行时，短信仍走环境变量配置的平台通道。

BEGIN;

-- ---------- 凭证中心 ----------
CREATE TABLE IF NOT EXISTS integration_config (
    tenant_id   uuid NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
    -- kind 是能力域：sms | mail | directory | sso | onlyoffice | storage | geoip | antivirus
    kind        text NOT NULL,
    -- provider 是具体厂商/协议：aliyun | tencent | huawei | ctyun | smtp | graph | ldap | oidc ...
    provider    text NOT NULL,
    -- 非密字段（AppId、签名、模板 ID、区域、Endpoint…）
    config      jsonb NOT NULL DEFAULT '{}'::jsonb,
    -- 密文字段（AccessKeySecret 等）打包成一个 JSON 再整体加密；
    -- AAD 绑定 tenant+kind+provider，把 A 租户的密文复制到 B 的行里解不开。
    secret_enc  bytea,
    -- 同类只允许一个生效；换通道时旧配置留在原地，出问题可以切回
    is_active   boolean NOT NULL DEFAULT false,
    -- unconfigured | configured | ok | failed
    status      text NOT NULL DEFAULT 'unconfigured'
                CHECK (status IN ('unconfigured', 'configured', 'ok', 'failed')),
    last_test_at    timestamptz,
    last_test_ok    boolean,
    last_test_error text NOT NULL DEFAULT '',
    -- 测试失败的原因分类（前端按码给文案，不做字符串匹配）
    last_test_code  text NOT NULL DEFAULT '',
    updated_by  text NOT NULL DEFAULT '',
    updated_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, kind, provider)
);

-- 部分唯一索引：同类只能有一个 is_active
CREATE UNIQUE INDEX IF NOT EXISTS uq_integration_active
    ON integration_config (tenant_id, kind) WHERE is_active;

GRANT SELECT, INSERT, UPDATE, DELETE ON integration_config TO docvault_app;

ALTER TABLE integration_config ENABLE ROW LEVEL SECURITY;
ALTER TABLE integration_config FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS integration_config_isolation ON integration_config;
CREATE POLICY integration_config_isolation ON integration_config
    USING (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);

-- ---------- 短信验证码（local 模式） ----------
--
-- 与 sms_send_log 的分工：
--   sms_send_log 记"发过几次"（频控、审计、失败原因）；
--   sms_code     记"当前这个号上还有一个什么码"（核验用）。
--
-- 只存 HMAC：6 位数字只有 100 万种，明文或裸哈希在库泄露后都能被穷举。
CREATE TABLE IF NOT EXISTS sms_code (
    tenant_id   uuid NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
    -- 与 sms_send_log 同口径（HMAC(phone)），两边能对上但都不可逆
    phone_hash  bytea NOT NULL,
    code_hash   bytea NOT NULL,
    provider    text NOT NULL,
    sent_at     timestamptz NOT NULL DEFAULT now(),
    expires_at  timestamptz NOT NULL,
    attempts    int NOT NULL DEFAULT 0,
    consumed_at timestamptz,
    PRIMARY KEY (tenant_id, phone_hash)
);

CREATE INDEX IF NOT EXISTS ix_sms_code_expiry ON sms_code(expires_at);

GRANT SELECT, INSERT, UPDATE, DELETE ON sms_code TO docvault_app;

ALTER TABLE sms_code ENABLE ROW LEVEL SECURITY;
ALTER TABLE sms_code FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS sms_code_isolation ON sms_code;
CREATE POLICY sms_code_isolation ON sms_code
    USING (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);

COMMENT ON TABLE integration_config IS '租户级第三方凭证；密文字段只写不读（docs/47 §4.4）';
COMMENT ON TABLE sms_code IS '短信 local 模式的验证码状态；只存 HMAC，单行覆盖，消费原子化';

COMMIT;
