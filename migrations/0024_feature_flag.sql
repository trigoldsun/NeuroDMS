-- 灰度开关（M3-5）
--
-- 语义（求值顺序固定，不可调换）：
--   1) 租户级显式覆盖最高——运营已经就某个租户做了决定，不该被百分比再覆盖一次；
--   2) 全局总开关 default_enabled 为假时，一律关闭（这是"一键止血"的开关）；
--   3) rollout_percent 决定放量比例，100 = 全量，0 = 关闭；
--   4) 分桶用 hash(tenant_id + 开关名)，**同一租户永远落在同一桶**——
--      否则用户会看到功能忽有忽无（比"没上线"更糟）。
--
-- 分桶在应用层用 SHA-256 计算而不是用 PG 的 hashtext：
-- hashtext 的实现不保证跨大版本稳定，数据库升级会让所有租户突然换桶，
-- 表现为"某天全体用户的功能开关同时变了"。这种 bug 极难排查。

CREATE TABLE IF NOT EXISTS feature_flag (
    code            text PRIMARY KEY,
    description     text NOT NULL DEFAULT '',
    -- 全局总开关：false 时除显式覆盖外一律关闭（应急止血用）
    default_enabled boolean NOT NULL DEFAULT false,
    rollout_percent int NOT NULL DEFAULT 0 CHECK (rollout_percent BETWEEN 0 AND 100),
    updated_at      timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT feature_flag_code_chk CHECK (code ~ '^[a-z0-9]+(\.[a-z0-9_]+)+$')
);

CREATE TABLE IF NOT EXISTS tenant_feature (
    tenant_id  uuid NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
    code       text NOT NULL REFERENCES feature_flag(code) ON DELETE CASCADE,
    enabled    boolean NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, code)
);

ALTER TABLE tenant_feature ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_feature FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_feature_isolation ON tenant_feature
    USING (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);

-- 租户侧只读：开关由平台运营改，客户不能给自己开功能
GRANT SELECT ON tenant_feature TO docvault_app;
GRANT SELECT ON feature_flag TO docvault_app;

-- 初始开关。刻意只放"真的会被门控的能力"，不建空壳：
-- 一个没有调用点的开关等于一个没人维护的谎言。
INSERT INTO feature_flag (code, description, default_enabled, rollout_percent) VALUES
    ('share.external', '对外分享链接（关闭后创建外链一律拒绝，已存在的链接按原样继续）', true, 100),
    ('branding.custom_domain', '租户绑定自有域名（需要平台上传证书）', true, 100),
    ('share.email_verify', '分享访客邮箱验证码', true, 100),
    ('media.transcode', '音视频转码（关闭后仅播放已转码产物）', true, 100)
ON CONFLICT (code) DO NOTHING;

-- 平台侧：批量读取某租户的覆盖项
CREATE OR REPLACE FUNCTION platform_tenant_features(p_slug text)
RETURNS TABLE (code text, enabled boolean, updated_at timestamptz)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE v_id uuid;
BEGIN
    SELECT t.id INTO v_id FROM tenant t WHERE t.slug = p_slug AND t.deleted_at IS NULL;
    IF v_id IS NULL THEN
        RAISE EXCEPTION 'tenant not found' USING ERRCODE = 'DV404';
    END IF;
    RETURN QUERY
    SELECT f.code, f.enabled, f.updated_at
      FROM tenant_feature f WHERE f.tenant_id = v_id ORDER BY f.code;
END $$;

REVOKE ALL ON FUNCTION platform_tenant_features(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION platform_tenant_features(text) TO docvault_app;
