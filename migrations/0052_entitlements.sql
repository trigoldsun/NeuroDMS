-- 0052_entitlements.sql
--
-- 能力授权层（docs/47 §4.1–4.3）。
--
-- 背景：在此之前"卖没卖某项能力"只能靠改档位。基础版客户单买自定义域名，
-- 只能整档升到旗舰版，连带送出 AD、邮件、短信——既收少了钱，也让"档位"
-- 失去意义。本迁移把"授权"从代码常量里拆出来，做成一张可以按租户改的表。
--
-- 三个刻意的决定：
--   1. **只放布尔型能力**。版本保留数、上传上限、席位、每席容量仍由
--      edition.Spec 给上限、tenant_quota 给单租户覆盖。把它们搬进来会制造
--      第三处事实，而触发器和配额判定已经读前两处了。
--   2. **三态靠"有没有行"表达**，不写 state='inherit'。多一个状态值，
--      就多一类"这个值是跟随还是显式关"的判断错误。
--   3. **过期不落库、不靠定时任务**，运行时按 expires_at 判。定时任务停摆
--      会让特批变成永久白送（与 edition.Resolve 的取舍一致）。
--
-- 存量行为必须不变：0035 把存量租户回填成 business，而 business 的默认列
-- 与当前 Spec 的 6 个布尔完全一致。因此上线当天没有任何客户的能力发生变化。

BEGIN;

-- ---------- 能力定义 ----------
CREATE TABLE IF NOT EXISTS entitlement_def (
    code              text PRIMARY KEY,
    name              text NOT NULL,
    description       text NOT NULL DEFAULT '',
    basic_default     boolean NOT NULL DEFAULT false,
    pro_default       boolean NOT NULL DEFAULT false,
    flagship_default  boolean NOT NULL DEFAULT false,
    -- 是否允许租户自己关/开（有自管开关的才为 true）
    tenant_settable   boolean NOT NULL DEFAULT false,
    -- 是否允许平台一票否决（合规/故障）
    platform_lockable boolean NOT NULL DEFAULT true,
    -- 按量计费：SaaS 上开通即产生成本，界面要提示
    metered           boolean NOT NULL DEFAULT false,
    -- 依赖的资源（展示用，不做强制）：integration.sms / integration.mail ...
    requires          text[]  NOT NULL DEFAULT '{}',
    sort_order        int     NOT NULL DEFAULT 100,
    updated_at        timestamptz NOT NULL DEFAULT now()
);

COMMENT ON TABLE entitlement_def IS '能力定义与三档默认值（docs/47 §3）；只放布尔能力';
COMMENT ON COLUMN entitlement_def.tenant_settable IS '租户是否可自管；无自管开关的能力为 false';

-- ---------- 租户覆盖 ----------
CREATE TABLE IF NOT EXISTS tenant_entitlement (
    tenant_id  uuid NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
    code       text NOT NULL REFERENCES entitlement_def(code) ON DELETE CASCADE,
    state      text NOT NULL CHECK (state IN ('on', 'off')),
    reason     text NOT NULL DEFAULT '',
    -- NULL = 长期有效（合同内买断/长期加购）
    expires_at timestamptz,
    updated_by text NOT NULL DEFAULT '',
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, code)
);

CREATE INDEX IF NOT EXISTS ix_tenant_entitlement_expiry
    ON tenant_entitlement(expires_at) WHERE expires_at IS NOT NULL;

COMMENT ON TABLE tenant_entitlement IS '租户级授权覆盖；无行 = 跟随档位默认，过期行按无行处理';

-- ---------- 平台强制关 ----------
CREATE TABLE IF NOT EXISTS entitlement_lock (
    code       text PRIMARY KEY REFERENCES entitlement_def(code) ON DELETE CASCADE,
    locked     boolean NOT NULL DEFAULT false,
    reason     text NOT NULL DEFAULT '',
    updated_at timestamptz NOT NULL DEFAULT now()
);

COMMENT ON TABLE entitlement_lock IS '平台一票否决（合规下线/故障止血），优先于授权与自管';

-- ---------- RLS 与授权 ----------
-- entitlement_def / entitlement_lock 是全局表：不加 RLS，只给读。
GRANT SELECT ON entitlement_def TO docvault_app;
GRANT SELECT ON entitlement_lock TO docvault_app;

GRANT SELECT, INSERT, UPDATE, DELETE ON tenant_entitlement TO docvault_app;

ALTER TABLE tenant_entitlement ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_entitlement FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS tenant_entitlement_isolation ON tenant_entitlement;
CREATE POLICY tenant_entitlement_isolation ON tenant_entitlement
    USING (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);

-- ---------- 种子：14 项布尔能力（docs/47 §3） ----------
INSERT INTO entitlement_def
    (code, name, description, basic_default, pro_default, flagship_default,
     tenant_settable, platform_lockable, metered, requires, sort_order)
VALUES
    ('share.external', '外链分享',
     '创建对外分享链接；合规下线时可全局关闭，存量链接默认不失效',
     true, true, true, false, true, false, '{}', 10),
    ('classification', '密级管控',
     '定密、按密级限制可见范围；基础版只能保持 0 级',
     false, true, true, false, false, false, '{}', 20),
    ('dir.auth', '目录认证',
     'AD/LDAP 登录与组织资料同步',
     false, true, true, true, false, false, '{integration.directory}', 30),
    ('mail.outbound', '邮件外发',
     '服务端代发审批通知与分享邮件；未配通道时降级为 mailto',
     false, true, true, false, true, false, '{integration.mail}', 40),
    ('upload.folder', '整目录上传',
     '保留层级批量上传（一次创建大量目录与文件），默认关闭',
     false, true, true, true, false, false, '{}', 50),
    ('sms.login', '短信验证码登录',
     '手机号 + 短信验证码登录；按条计费，需先配置短信通道',
     false, true, true, true, true, true, '{integration.sms}', 60),
    ('share.email_verify', '访客邮箱验证码',
     '外链访客访问前需完成邮箱验证',
     false, true, true, false, true, false, '{integration.mail}', 70),
    ('collab.external', '外部协作账号',
     '为供应商/客户创建 external 类型账号',
     false, true, true, false, false, false, '{}', 80),
    ('branding.custom_domain', '自定义域名',
     '绑定自有域名并使用其品牌与证书；需要 DNS 与证书配置',
     false, false, true, true, true, false, '{}', 90),
    ('sso', '统一登录 SSO',
     'SAML 2.0 / OIDC / OAuth2 单点登录',
     false, false, true, false, false, false, '{integration.idp}', 100),
    ('audit.export', '审计证据包导出',
     '按时间范围导出可校验的审计证据包（安全底线，不可关闭）',
     true, true, true, false, false, false, '{}', 110),
    ('watermark', '预览溯源水印',
     '预览页叠加阅读者信息；安全底线，建议不做成开关',
     true, true, true, false, false, false, '{}', 120),
    ('edit.online', '在线编辑',
     'OnlyOffice 在线编辑；SaaS 上占用我方容器资源',
     false, true, true, false, true, false, '{integration.onlyoffice}', 130),
    ('media.transcode', '音视频转码',
     '视频转码后可在线播放；关闭后已转码产物照常播放',
     false, true, true, false, true, true, '{}', 140)
ON CONFLICT (code) DO NOTHING;

-- ---------- 平台侧读：某租户的能力全貌 ----------
-- 返回"定义 + 覆盖 + 全局锁"，档位默认值由调用方按**生效档位**选列，
-- 因为宽限期与到期判定在 Go 里（edition.Resolve），SQL 重写一遍必然分叉。
CREATE OR REPLACE FUNCTION platform_tenant_entitlements(p_slug text)
RETURNS TABLE (
    code              text,
    name              text,
    description       text,
    basic_default     boolean,
    pro_default       boolean,
    flagship_default  boolean,
    tenant_settable   boolean,
    platform_lockable boolean,
    metered           boolean,
    requires          text[],
    sort_order        int,
    state             text,
    reason            text,
    expires_at        timestamptz,
    updated_by        text,
    locked            boolean,
    lock_reason       text
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_id uuid;
BEGIN
    SELECT t.id INTO v_id FROM tenant t
     WHERE t.slug = lower(btrim(p_slug)) AND t.deleted_at IS NULL;

    IF v_id IS NULL THEN
        RAISE EXCEPTION '租户不存在' USING ERRCODE = 'DV404';
    END IF;

    RETURN QUERY
    SELECT d.code, d.name, d.description,
           d.basic_default, d.pro_default, d.flagship_default,
           d.tenant_settable, d.platform_lockable, d.metered,
           d.requires, d.sort_order,
           e.state, COALESCE(e.reason, ''), e.expires_at, COALESCE(e.updated_by, ''),
           COALESCE(l.locked, false), COALESCE(l.reason, '')
      FROM entitlement_def d
      LEFT JOIN tenant_entitlement e ON e.code = d.code AND e.tenant_id = v_id
      LEFT JOIN entitlement_lock   l ON l.code = d.code
     ORDER BY d.sort_order, d.code;
END $$;

REVOKE ALL ON FUNCTION platform_tenant_entitlements(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION platform_tenant_entitlements(text) TO docvault_app;

-- ---------- 平台侧写：单租户单项授权 ----------
-- p_state: inherit（删行，回到档位默认）/ on / off
--
-- 返回改前改后，供 auditDiff 记 before/after。审计写不了时调用方要回滚——
-- "授权改了但没痕迹"比"改失败"更难查。
CREATE OR REPLACE FUNCTION platform_tenant_set_entitlement(
    p_slug     text,
    p_code     text,
    p_state    text,
    p_reason   text,
    p_expires  timestamptz,
    p_operator text
)
RETURNS TABLE (
    prev_state   text,
    prev_reason  text,
    prev_expires timestamptz,
    cur_state    text,
    cur_reason   text,
    cur_expires  timestamptz
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_id     uuid;
    v_state  text;
    v_prev   text;
    v_preason text;
    v_pexp   timestamptz;
BEGIN
    SELECT t.id INTO v_id FROM tenant t
     WHERE t.slug = lower(btrim(p_slug)) AND t.deleted_at IS NULL
       FOR UPDATE;

    IF v_id IS NULL THEN
        RAISE EXCEPTION '租户不存在' USING ERRCODE = 'DV404';
    END IF;

    IF NOT EXISTS (SELECT 1 FROM entitlement_def WHERE code = p_code) THEN
        RAISE EXCEPTION '未知能力编码' USING ERRCODE = 'DV003';
    END IF;

    v_state := lower(btrim(COALESCE(p_state, '')));
    IF v_state NOT IN ('inherit', 'on', 'off') THEN
        RAISE EXCEPTION '授权状态只能是 inherit / on / off' USING ERRCODE = 'DV002';
    END IF;

    SELECT e.state, e.reason, e.expires_at
      INTO v_prev, v_preason, v_pexp
      FROM tenant_entitlement e
     WHERE e.tenant_id = v_id AND e.code = p_code;

    IF v_state = 'inherit' THEN
        DELETE FROM tenant_entitlement WHERE tenant_id = v_id AND code = p_code;
        RETURN QUERY SELECT COALESCE(v_prev, ''), COALESCE(v_preason, ''), v_pexp,
                            ''::text, ''::text, NULL::timestamptz;
        RETURN;
    END IF;

    INSERT INTO tenant_entitlement
        (tenant_id, code, state, reason, expires_at, updated_by, updated_at)
    VALUES
        (v_id, p_code, v_state, COALESCE(p_reason, ''), p_expires,
         COALESCE(p_operator, ''), now())
    ON CONFLICT (tenant_id, code) DO UPDATE
        SET state = EXCLUDED.state,
            reason = EXCLUDED.reason,
            expires_at = EXCLUDED.expires_at,
            updated_by = EXCLUDED.updated_by,
            updated_at = now();

    RETURN QUERY SELECT COALESCE(v_prev, ''), COALESCE(v_preason, ''), v_pexp,
                        v_state, COALESCE(p_reason, ''), p_expires;
END $$;

REVOKE ALL ON FUNCTION platform_tenant_set_entitlement(text, text, text, text, timestamptz, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION platform_tenant_set_entitlement(text, text, text, text, timestamptz, text) TO docvault_app;

-- ---------- 平台全局强制关 ----------
CREATE OR REPLACE FUNCTION platform_entitlement_lock(
    p_code   text,
    p_locked boolean,
    p_reason text
)
RETURNS TABLE (prev_locked boolean, cur_locked boolean)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_prev boolean;
BEGIN
    IF NOT EXISTS (SELECT 1 FROM entitlement_def WHERE code = p_code) THEN
        RAISE EXCEPTION '未知能力编码' USING ERRCODE = 'DV003';
    END IF;

    SELECT l.locked INTO v_prev FROM entitlement_lock l WHERE l.code = p_code;

    INSERT INTO entitlement_lock (code, locked, reason, updated_at)
    VALUES (p_code, p_locked, COALESCE(p_reason, ''), now())
    ON CONFLICT (code) DO UPDATE
        SET locked = EXCLUDED.locked,
            reason = EXCLUDED.reason,
            updated_at = now();

    RETURN QUERY SELECT COALESCE(v_prev, false), p_locked;
END $$;

REVOKE ALL ON FUNCTION platform_entitlement_lock(text, boolean, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION platform_entitlement_lock(text, boolean, text) TO docvault_app;

COMMIT;
