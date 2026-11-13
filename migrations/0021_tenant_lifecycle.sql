-- 租户生命周期、租户级配置、用量与配额骨架（M3-1）
--
-- 设计要点（改之前先读）：
--
-- 1) 状态机显式化：active / trial / readonly / suspended / deleted。
--    "readonly" 是试用到期与超限降级**共用**的形态。它必须在中心一处被识别，
--    而不是每个写接口各写一遍 if——那样必然漏掉某个新接口。
--
-- 2) 停用必须与状态变更**同事务**吊销会话。
--    只把 status 改成 suspended 而不动 session_epoch，已签发的访问令牌
--    还能继续用到过期（最长 15 分钟），表现就是"后台显示已停用，人还在用"。
--    这条在 platform_tenant_set_status 里一次做掉，不依赖应用层记得调用。
--
-- 3) 删除是逻辑删除 + 保留期：deleted_at + retention_until，
--    物理清理由后台按保留期执行，且必须二次确认（PRD-TEN-02）。
--
-- 4) 跨租户能力只以 SECURITY DEFINER 函数存在，并显式 REVOKE PUBLIC。
--    不给应用角色 BYPASSRLS：那等于把"隔离"整体关掉，只为省几个函数。

-- ---------- 1. tenant 扩展 ----------

ALTER TABLE tenant
    ADD COLUMN IF NOT EXISTS plan            text NOT NULL DEFAULT 'standard',
    ADD COLUMN IF NOT EXISTS trial_ends_at   timestamptz,
    ADD COLUMN IF NOT EXISTS suspended_at    timestamptz,
    ADD COLUMN IF NOT EXISTS retention_until timestamptz,
    ADD COLUMN IF NOT EXISTS contact_email   text;

-- 原约束是内联 CHECK，名字由 PostgreSQL 自动生成
ALTER TABLE tenant DROP CONSTRAINT IF EXISTS tenant_status_check;
ALTER TABLE tenant ADD CONSTRAINT tenant_status_check
    CHECK (status IN ('active', 'trial', 'readonly', 'suspended', 'deleted'));

-- slug 是租户在主機名/登录框里的唯一标识，必须限制字符集：
-- 允许任意字符会让"租户绑定域名"与"按 slug 解析"出现难以排查的歧义。
ALTER TABLE tenant DROP CONSTRAINT IF EXISTS tenant_slug_chk;
ALTER TABLE tenant ADD CONSTRAINT tenant_slug_chk
    CHECK (slug ~ '^[a-z0-9][a-z0-9-]{1,40}$');

-- ---------- 2. 租户级配置（品牌 + 策略） ----------

CREATE TABLE IF NOT EXISTS tenant_config (
    tenant_id       uuid PRIMARY KEY REFERENCES tenant(id) ON DELETE CASCADE,
    -- 品牌：全部为"可空即用默认"，避免每个租户都被迫填一遍
    product_name    text NOT NULL DEFAULT '文档中心',
    primary_color   text NOT NULL DEFAULT '#12724a',
    accent_color    text NOT NULL DEFAULT '#0b5fa5',
    logo            bytea,
    logo_mime       text,
    footer_text     text NOT NULL DEFAULT '',
    support_email   text NOT NULL DEFAULT '',
    email_from_name text NOT NULL DEFAULT '',
    -- 策略：允许演进的键值，类型与取值范围在应用层校验（见 tenantcfg 包）
    policy          jsonb NOT NULL DEFAULT '{}'::jsonb,
    updated_at      timestamptz NOT NULL DEFAULT now(),
    -- 颜色在数据库层就约束住：坏值会直接进 CSS，前端表现为"整站变黑白"
    CONSTRAINT tenant_config_color_chk CHECK (
        primary_color ~ '^#[0-9a-fA-F]{6}$' AND accent_color ~ '^#[0-9a-fA-F]{6}$'
    ),
    -- Logo 只接受位图与 SVG；SVG 已在上传链路净化，这里只做类型白名单
    CONSTRAINT tenant_config_logo_chk CHECK (
        logo IS NULL OR logo_mime IN ('image/png', 'image/jpeg', 'image/svg+xml', 'image/webp')
    ),
    CONSTRAINT tenant_config_logo_size_chk CHECK (logo IS NULL OR octet_length(logo) <= 262144)
);

ALTER TABLE tenant_config ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_config FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_config_isolation ON tenant_config
    USING (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON tenant_config TO docvault_app;

-- ---------- 3. 用量快照（计量真源之一：可累加项） ----------

-- 只放**瞬时量（gauge）**：存储字节数与在册用户数。
--
-- 为什么不含"本月转码秒数/今日调用数"：
-- 那类是可累加量（counter），一旦在这里用 "窗口到了就清零" 维护，
-- 就必须在每次写入时判断窗口，任何一次判断错误都要等下个窗口才能自愈。
-- 可累加量走 usage_event + usage_daily（0022），窗口靠查询时聚合得出，
-- 天然没有"忘记重置"的问题。
CREATE TABLE IF NOT EXISTS tenant_usage (
    tenant_id     uuid PRIMARY KEY REFERENCES tenant(id) ON DELETE CASCADE,
    -- 两个值都由触发器维护（见 0022），与业务写入同事务提交。
    -- 不在应用层做累加：漏调一次或重试一次，偏差就永久留在账上。
    storage_bytes bigint NOT NULL DEFAULT 0 CHECK (storage_bytes >= 0),
    active_users  int NOT NULL DEFAULT 0 CHECK (active_users >= 0),
    updated_at    timestamptz NOT NULL DEFAULT now()
);

-- 用量只读：写入只能发生在 SECURITY DEFINER 的触发器里（见 0022）。
-- 给应用层 UPDATE 权限等于允许"随手改账"——那还不如不计量。
GRANT SELECT ON tenant_usage TO docvault_app;

ALTER TABLE tenant_usage ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_usage FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_usage_isolation ON tenant_usage
    USING (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);

-- ---------- 4. 配额 ----------

CREATE TABLE IF NOT EXISTS tenant_quota (
    tenant_id            uuid PRIMARY KEY REFERENCES tenant(id) ON DELETE CASCADE,
    -- NULL 表示不限
    max_users            int,
    max_storage_bytes    bigint,
    max_transcode_seconds bigint,
    max_api_calls_day    bigint,
    -- 超限行为：reject（拒绝）| readonly（降级为只读）| warn（只告警）
    on_exceed            text NOT NULL DEFAULT 'reject'
                         CHECK (on_exceed IN ('reject', 'readonly', 'warn')),
    updated_at           timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT tenant_quota_positive_chk CHECK (
        (max_users IS NULL OR max_users >= 0) AND
        (max_storage_bytes IS NULL OR max_storage_bytes >= 0) AND
        (max_transcode_seconds IS NULL OR max_transcode_seconds >= 0) AND
        (max_api_calls_day IS NULL OR max_api_calls_day >= 0)
    )
);

-- 配额只读：由平台侧函数写入，客户侧只能看
GRANT SELECT ON tenant_quota TO docvault_app;

ALTER TABLE tenant_quota ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_quota FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_quota_isolation ON tenant_quota
    USING (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);

-- ---------- 5. 平台侧函数（最小面跨租户） ----------

-- 开通租户：只写 tenant / tenant_config / tenant_usage / tenant_quota，
-- 不碰任何业务表——业务初始化走正常的租户上下文（见 Go 侧 createTenant）。
CREATE OR REPLACE FUNCTION platform_tenant_create(
    p_slug          text,
    p_name          text,
    p_plan          text,
    p_trial_days    int,
    p_contact_email text
) RETURNS uuid
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_id      uuid;
    v_status  text := 'active';
    v_trial   timestamptz;
    v_plan    text := COALESCE(nullif(p_plan, ''), 'standard');
BEGIN
    IF p_slug !~ '^[a-z0-9][a-z0-9-]{1,40}$' THEN
        RAISE EXCEPTION 'invalid slug' USING ERRCODE = 'DV002';
    END IF;
    IF p_name IS NULL OR btrim(p_name) = '' THEN
        RAISE EXCEPTION 'invalid name' USING ERRCODE = 'DV002';
    END IF;

    IF p_trial_days IS NOT NULL AND p_trial_days > 0 THEN
        v_status := 'trial';
        v_trial  := now() + make_interval(days => p_trial_days);
    END IF;

    INSERT INTO tenant (id, slug, name, status, plan, trial_ends_at, contact_email)
    VALUES (gen_random_uuid(), p_slug, btrim(p_name), v_status, v_plan, v_trial,
            nullif(btrim(COALESCE(p_contact_email, '')), ''))
    RETURNING id INTO v_id;

    INSERT INTO tenant_config (tenant_id) VALUES (v_id) ON CONFLICT DO NOTHING;
    INSERT INTO tenant_usage  (tenant_id) VALUES (v_id) ON CONFLICT DO NOTHING;
    INSERT INTO tenant_quota  (tenant_id) VALUES (v_id) ON CONFLICT DO NOTHING;

    RETURN v_id;
END $$;

-- 状态变更：与"吊销会话"同事务。
--
-- 为什么吊销放这里而不是 handler 里：
--   1) 任何人（含将来的 CLI、定时任务）改状态时都不会漏；
--   2) 与状态变更同一事务，不存在"状态改了但吊销失败"的中间态。
CREATE OR REPLACE FUNCTION platform_tenant_set_status(
    p_slug   text,
    p_status text
-- OUT 参数不能叫 tenant_id：PL/pgSQL 里它会与表列同名，
-- 导致 "WHERE tenant_id = v_id" 报 ambiguous column reference。
-- 这类错误在写函数时不会暴露，只有真正执行到那一行才失败。
) RETURNS TABLE (tid uuid, prev_status text, cur_status text)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_id   uuid;
    v_prev text;
BEGIN
    IF p_status NOT IN ('active', 'trial', 'readonly', 'suspended', 'deleted') THEN
        RAISE EXCEPTION 'invalid status' USING ERRCODE = 'DV002';
    END IF;

    SELECT t.id, t.status INTO v_id, v_prev
      FROM tenant t
     WHERE t.slug = p_slug AND t.deleted_at IS NULL
       FOR UPDATE;
    IF v_id IS NULL THEN
        RAISE EXCEPTION 'tenant not found' USING ERRCODE = 'DV404';
    END IF;

    UPDATE tenant SET
        status         = p_status,
        suspended_at   = CASE WHEN p_status = 'suspended' THEN now() ELSE NULL END,
        deleted_at     = CASE WHEN p_status = 'deleted' THEN COALESCE(deleted_at, now()) ELSE deleted_at END,
        retention_until = CASE WHEN p_status = 'deleted'
                               THEN COALESCE(retention_until, now() + interval '30 days')
                               ELSE retention_until END,
        trial_ends_at  = CASE WHEN p_status = 'trial' AND trial_ends_at IS NULL
                              THEN now() + interval '14 days' ELSE trial_ends_at END
     WHERE id = v_id;

    -- 只有"彻底不可用"的两个状态才踢人。
    -- readonly 是刻意保留登录的：用户要能进去看自己的文件、导出数据。
    IF p_status IN ('suspended', 'deleted') THEN
        UPDATE app_user u SET session_epoch = u.session_epoch + 1 WHERE u.tenant_id = v_id;
        UPDATE session ss SET revoked_at = now()
         WHERE ss.tenant_id = v_id AND ss.revoked_at IS NULL;
    END IF;

    RETURN QUERY SELECT v_id, v_prev, p_status;
END $$;

-- 租户列表：平台运营的主视图。
-- 返回的是"规模与状态"，不含任何业务明细（文件名、内容、用户名单都不给）。
CREATE OR REPLACE FUNCTION platform_tenant_list()
RETURNS TABLE (
    slug            text,
    name            text,
    status          text,
    plan            text,
    created_at      timestamptz,
    trial_ends_at   timestamptz,
    suspended_at    timestamptz,
    retention_until timestamptz,
    contact_email   text,
    users           bigint,
    storage_bytes   bigint,
    files           bigint
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
BEGIN
    RETURN QUERY
    SELECT t.slug, t.name, t.status, t.plan, t.created_at,
           t.trial_ends_at, t.suspended_at, t.retention_until,
           COALESCE(t.contact_email, ''),
           (SELECT count(*) FROM app_user u WHERE u.tenant_id = t.id AND u.deleted_at IS NULL),
           COALESCE((SELECT us.storage_bytes FROM tenant_usage us WHERE us.tenant_id = t.id), 0),
           (SELECT count(*) FROM node n WHERE n.tenant_id = t.id AND n.kind = 'file' AND n.deleted_at IS NULL)
      FROM tenant t
     WHERE t.status <> 'deleted'
     ORDER BY t.created_at;
END $$;

-- 单个租户：与列表同口径，避免前端为了看一个租户把全量列表拉下来。
CREATE OR REPLACE FUNCTION platform_tenant_get(p_slug text)
RETURNS TABLE (
    slug text, name text, status text, plan text, created_at timestamptz,
    trial_ends_at timestamptz, suspended_at timestamptz, retention_until timestamptz,
    contact_email text, users bigint, storage_bytes bigint, files bigint
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
BEGIN
    RETURN QUERY
    SELECT t.slug, t.name, t.status, t.plan, t.created_at,
           t.trial_ends_at, t.suspended_at, t.retention_until,
           COALESCE(t.contact_email, ''),
           (SELECT count(*) FROM app_user u WHERE u.tenant_id = t.id AND u.deleted_at IS NULL),
           COALESCE((SELECT us.storage_bytes FROM tenant_usage us WHERE us.tenant_id = t.id), 0),
           (SELECT count(*) FROM node n WHERE n.tenant_id = t.id AND n.kind = 'file' AND n.deleted_at IS NULL)
      FROM tenant t
     WHERE t.slug = p_slug AND t.status <> 'deleted';
END $$;

REVOKE ALL ON FUNCTION platform_tenant_get(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION platform_tenant_get(text) TO docvault_app;

-- 公开品牌读取：登录页与分享页要按租户展示品牌，此时**没有**租户上下文。
-- 只返回品牌字段，不返回策略、配额、联系方式等内部信息。
CREATE OR REPLACE FUNCTION public_branding(p_slug text)
RETURNS TABLE (
    slug          text,
    name          text,
    status        text,
    product_name  text,
    primary_color text,
    accent_color  text,
    logo          bytea,
    logo_mime     text,
    footer_text   text,
    updated_at    timestamptz
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
BEGIN
    RETURN QUERY
    SELECT t.slug, t.name, t.status,
           COALESCE(c.product_name, '文档中心'),
           COALESCE(c.primary_color, '#12724a'),
           COALESCE(c.accent_color, '#0b5fa5'),
           c.logo, COALESCE(c.logo_mime, ''),
           COALESCE(c.footer_text, ''),
           COALESCE(c.updated_at, t.created_at)
      FROM tenant t
      LEFT JOIN tenant_config c ON c.tenant_id = t.id
     WHERE t.slug = p_slug AND t.deleted_at IS NULL;
END $$;

REVOKE ALL ON FUNCTION platform_tenant_create(text, text, text, int, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION platform_tenant_set_status(text, text) FROM PUBLIC;
REVOKE ALL ON FUNCTION platform_tenant_list() FROM PUBLIC;
REVOKE ALL ON FUNCTION public_branding(text) FROM PUBLIC;

GRANT EXECUTE ON FUNCTION platform_tenant_create(text, text, text, int, text) TO docvault_app;
GRANT EXECUTE ON FUNCTION platform_tenant_set_status(text, text) TO docvault_app;
GRANT EXECUTE ON FUNCTION platform_tenant_list() TO docvault_app;
GRANT EXECUTE ON FUNCTION public_branding(text) TO docvault_app;

COMMENT ON FUNCTION platform_tenant_set_status(text, text)
    IS '平台运营：变更租户状态；停用/删除与吊销全部会话在同一事务内完成';

-- 配额的读写都必须在平台侧（客户不能给自己调额）。
-- 读用函数而不是直接 SELECT：平台侧没有租户上下文，RLS 会挡住普通查询。
CREATE OR REPLACE FUNCTION platform_tenant_quota(p_slug text)
RETURNS TABLE (
    max_users             int,
    max_storage_bytes     bigint,
    max_transcode_seconds bigint,
    max_api_calls_day     bigint,
    on_exceed             text
)
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
    SELECT q.max_users, q.max_storage_bytes, q.max_transcode_seconds,
           q.max_api_calls_day, q.on_exceed
      FROM tenant_quota q WHERE q.tenant_id = v_id;
END $$;

CREATE OR REPLACE FUNCTION platform_tenant_set_quota(
    p_slug                text,
    p_max_users           int,
    p_max_storage_bytes   bigint,
    p_max_transcode       bigint,
    p_max_api_calls_day   bigint,
    p_on_exceed           text
) RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE v_id uuid;
BEGIN
    IF p_on_exceed NOT IN ('reject', 'readonly', 'warn') THEN
        RAISE EXCEPTION 'invalid on_exceed' USING ERRCODE = 'DV002';
    END IF;
    SELECT t.id INTO v_id FROM tenant t WHERE t.slug = p_slug AND t.deleted_at IS NULL;
    IF v_id IS NULL THEN
        RAISE EXCEPTION 'tenant not found' USING ERRCODE = 'DV404';
    END IF;
    -- 立刻校验一次：把配额调到当前用量之下是合法的（客户应当被限制），
    -- 但不能是负数——那会让后续所有写请求都失败且原因难查。
    IF p_max_users IS NOT NULL AND p_max_users < 0 THEN
        RAISE EXCEPTION 'invalid max_users' USING ERRCODE = 'DV002';
    END IF;
    IF p_max_storage_bytes IS NOT NULL AND p_max_storage_bytes < 0 THEN
        RAISE EXCEPTION 'invalid max_storage' USING ERRCODE = 'DV002';
    END IF;

    INSERT INTO tenant_quota (tenant_id, max_users, max_storage_bytes,
                              max_transcode_seconds, max_api_calls_day, on_exceed, updated_at)
    VALUES (v_id, p_max_users, p_max_storage_bytes, p_max_transcode, p_max_api_calls_day,
            p_on_exceed, now())
    ON CONFLICT (tenant_id) DO UPDATE SET
        max_users = EXCLUDED.max_users,
        max_storage_bytes = EXCLUDED.max_storage_bytes,
        max_transcode_seconds = EXCLUDED.max_transcode_seconds,
        max_api_calls_day = EXCLUDED.max_api_calls_day,
        on_exceed = EXCLUDED.on_exceed,
        updated_at = now();
END $$;

REVOKE ALL ON FUNCTION platform_tenant_quota(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION platform_tenant_set_quota(text, int, bigint, bigint, bigint, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION platform_tenant_quota(text) TO docvault_app;
GRANT EXECUTE ON FUNCTION platform_tenant_set_quota(text, int, bigint, bigint, bigint, text) TO docvault_app;
