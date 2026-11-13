-- 租户自有域名与证书（M3-4）
--
-- 三个决定（都有代价，写清楚以便将来复核）：
--
-- 1) host 全局唯一，不做"每租户一份命名空间"。
--    同一個域名指向两个租户没有正确语义，而按 Host 解析租户是白标的入口，
--    一旦有歧义就会把 A 的分享页渲染成 B 的品牌。
--
-- 2) 私钥不明文入库。存 key_enc（AES-GCM 密文），密钥来自 DOCVAULT_SECRET_KEY。
--    未配置该密钥时，绑定证书的接口直接拒绝——宁可"暂不支持上传证书"，
--    也不要把私钥明文写进随时会被 pg_dump 出去的库里。
--
-- 3) 域名归属用 DNS TXT 挑战验证，不用 HTTP 文件。
--    HTTP 验证要求服务端主动向客户填写的域名发请求，这正是 SSRF 的经典形态；
--    DNS 查询没有"请求打到内网地址"的问题，安全边界更清楚。
--
-- 未实现：ACME 自动签发。原因不是工作量，而是自动签发要求 80/443 从公网可达，
-- 私有化交付环境通常不具备；做成"看似自动、实际依赖运维开端口"的功能更容易误导人。
-- 因此证书由平台运营上传，过期时间入库，到期前告警。

CREATE TABLE IF NOT EXISTS tenant_domain (
    host             text PRIMARY KEY,
    tenant_id        uuid NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
    is_primary       boolean NOT NULL DEFAULT false,
    -- 归属验证
    verify_token     text NOT NULL,
    verified_at      timestamptz,
    -- 证书（可空：先绑域名、后传证书）
    cert_pem         text,
    key_enc          bytea,
    cert_not_after   timestamptz,
    cert_fingerprint text,
    created_at       timestamptz NOT NULL DEFAULT now(),
    updated_at       timestamptz NOT NULL DEFAULT now(),
    -- 主机名必须是小写、无协议、无路径；带端口/大写会让 SNI 匹配失败
    CONSTRAINT tenant_domain_host_chk CHECK (
        host ~ '^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$'
    ),
    CONSTRAINT tenant_domain_key_pair_chk CHECK (
        (cert_pem IS NULL AND key_enc IS NULL) OR (cert_pem IS NOT NULL AND key_enc IS NOT NULL)
    )
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_tenant_domain_primary
    ON tenant_domain (tenant_id) WHERE is_primary;
CREATE INDEX IF NOT EXISTS idx_tenant_domain_tenant ON tenant_domain (tenant_id);

ALTER TABLE tenant_domain ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_domain FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_domain_isolation ON tenant_domain
    USING (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON tenant_domain TO docvault_app;

-- 按 Host 解析租户：公开分享页在**没有**租户上下文时也要能定位品牌与租户。
-- 只返回解析所需的最小信息，不返回证书私钥。
CREATE OR REPLACE FUNCTION public_resolve_domain(p_host text)
RETURNS TABLE (tenant_id uuid, tenant_slug text, is_primary boolean, verified boolean)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
BEGIN
    RETURN QUERY
    SELECT d.tenant_id, t.slug, d.is_primary, d.verified_at IS NOT NULL
      FROM tenant_domain d
      JOIN tenant t ON t.id = d.tenant_id
     WHERE d.host = lower(p_host)
       AND d.verified_at IS NOT NULL
       AND t.status NOT IN ('deleted', 'suspended')
       AND t.deleted_at IS NULL;
END $$;

-- 平台侧：列出租户的域名（含证书到期，用于告警）
CREATE OR REPLACE FUNCTION platform_domains(p_slug text)
RETURNS TABLE (host text, is_primary boolean, verified boolean,
               has_cert boolean, cert_not_after timestamptz, created_at timestamptz)
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
    SELECT d.host, d.is_primary, d.verified_at IS NOT NULL,
           d.cert_pem IS NOT NULL, d.cert_not_after, d.created_at
      FROM tenant_domain d WHERE d.tenant_id = v_id ORDER BY d.is_primary DESC, d.host;
END $$;

REVOKE ALL ON FUNCTION public_resolve_domain(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION platform_domains(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public_resolve_domain(text) TO docvault_app;
GRANT EXECUTE ON FUNCTION platform_domains(text) TO docvault_app;

COMMENT ON COLUMN tenant_domain.key_enc IS '证书私钥的 AES-GCM 密文；密钥来自 DOCVAULT_SECRET_KEY，缺失时不允许上传证书';
