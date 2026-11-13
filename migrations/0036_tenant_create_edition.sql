-- 0036：开通租户时直接指定档位
--
-- 背景（docs/23 §5）：
--   开通接口 platform_tenant_create 从来没有档位参数，tenant.edition 走列默认 basic，
--   于是"开通"与"授权"是两步：开通完必须再进详情页改档，漏做就是客户拿着专业版合同
--   用着基础版。与此同时开通表单里有个叫"套餐"的输入框，写的是 tenant.plan ——
--   一个全系统没有任何代码读取的自由文本。
--
--   结果是两种错法：① 漏改档；② 在"套餐"里填了 professional，以为设好了。
--   第二种更难查，因为表单看上去"填过了"。
--
-- 本迁移做三件事：
--   1. plan 变成 edition 的镜像（触发器强制），从此"套餐"这个词在库里只有一个含义；
--   2. 开通函数支持档位与到期日，一步到位；
--   3. 列表/详情返回真实档位，运营台不再靠猜。

BEGIN;

-- ---------------------------------------------------------------- 1. plan 镜像

-- 为什么用触发器而不是在两个写入函数里各写一遍：
-- 写入路径现在有两条（开通、改档），将来还会有（批量导入、续费自动延期）。
-- 每加一条路径就要记得同步一次，迟早漏。触发器让"分叉"这件事在结构上不可能发生。
CREATE OR REPLACE FUNCTION tenant_sync_plan()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    -- plan 是历史字段（0021 引入），保留是为了兼容仍按老列名查库的报表。
    -- 它不再承载语义：档位只有一个真源 edition。
    NEW.plan := NEW.edition;
    RETURN NEW;
END $$;

DROP TRIGGER IF EXISTS trg_tenant_sync_plan ON tenant;
CREATE TRIGGER trg_tenant_sync_plan
    BEFORE INSERT OR UPDATE OF edition, plan ON tenant
    FOR EACH ROW EXECUTE FUNCTION tenant_sync_plan();

COMMENT ON COLUMN tenant.plan IS
    '已废弃：edition 的镜像，由 trg_tenant_sync_plan 强制同步。判定一律读 edition。';

-- 存量回填：现在库里的 plan 是 'standard' 之类，与真实档位无关，直接对齐。
UPDATE tenant SET plan = edition WHERE plan IS DISTINCT FROM edition;

-- ---------------------------------------------------------------- 2. 开通带档位

-- 保留 5 参数版本不动：仍在跑的旧镜像会调用它，删掉会让旧容器在回滚时开不了租户。
-- 新版本以重载形式出现，旧版委托给它（档位传 basic，与旧版"走列默认值"的行为一致）。
CREATE OR REPLACE FUNCTION platform_tenant_create(
    p_slug              text,
    p_name              text,
    p_plan              text,
    p_trial_days        int,
    p_contact_email     text,
    p_edition           text,
    p_edition_expires   timestamptz
) RETURNS uuid
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_id     uuid;
    v_ed     text;
    v_reason text;
BEGIN
    v_ed := lower(btrim(COALESCE(NULLIF(p_edition, ''), 'basic')));
    IF v_ed NOT IN ('basic', 'professional', 'business') THEN
        -- 与改档函数同一个错误码，调用方只需处理一次
        RAISE EXCEPTION '未知档位' USING ERRCODE = 'DV002';
    END IF;

    -- 复用旧函数的 slug/名称校验与入座顺序，避免两份校验慢慢长歪。
    v_id := platform_tenant_create(p_slug, p_name, p_plan, p_trial_days, p_contact_email);

    -- 开通时不做降档校验：新租户没有任何对象，任何档位都能表达。
    UPDATE tenant
       SET edition            = v_ed,
           edition_expires_at = p_edition_expires
     WHERE id = v_id;

    -- 与改档共用同一张历史表，这样"这个租户什么时候变成专业版"只有一处答案。
    v_reason := CASE
        WHEN p_edition_expires IS NULL THEN '开通时指定'
        ELSE '开通时指定，到期 ' || to_char(p_edition_expires, 'YYYY-MM-DD')
    END;
    INSERT INTO tenant_edition_change
        (tenant_id, from_edition, to_edition, from_expires, to_expires, reason, operator)
    VALUES (v_id, NULL, v_ed, NULL, p_edition_expires, v_reason, 'platform');

    RETURN v_id;
END $$;

REVOKE ALL ON FUNCTION platform_tenant_create(text, text, text, int, text, text, timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION platform_tenant_create(text, text, text, int, text, text, timestamptz) TO docvault_app;

COMMENT ON FUNCTION platform_tenant_create(text, text, text, int, text, text, timestamptz)
    IS '平台运营：开通租户并直接授予档位（一步完成，避免"开通后忘记改档"）';

-- ---------------------------------------------------------------- 3. 返回真实档位

-- 返回类型变了必须 DROP 再建。列顺序只在末尾追加，仍按列名查询的旧镜像不受影响。
DROP FUNCTION IF EXISTS platform_tenant_list();
CREATE OR REPLACE FUNCTION platform_tenant_list()
RETURNS TABLE (
    slug                text,
    name                text,
    status              text,
    plan                text,
    created_at          timestamptz,
    trial_ends_at       timestamptz,
    suspended_at        timestamptz,
    retention_until     timestamptz,
    contact_email       text,
    users               bigint,
    storage_bytes       bigint,
    files               bigint,
    edition             text,
    edition_expires_at  timestamptz
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
           (SELECT count(*) FROM node n WHERE n.tenant_id = t.id AND n.kind = 'file' AND n.deleted_at IS NULL),
           t.edition, t.edition_expires_at
      FROM tenant t
     WHERE t.status <> 'deleted'
     ORDER BY t.created_at;
END $$;

REVOKE ALL ON FUNCTION platform_tenant_list() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION platform_tenant_list() TO docvault_app;

DROP FUNCTION IF EXISTS platform_tenant_get(text);
CREATE OR REPLACE FUNCTION platform_tenant_get(p_slug text)
RETURNS TABLE (
    slug                text,
    name                text,
    status              text,
    plan                text,
    created_at          timestamptz,
    trial_ends_at       timestamptz,
    suspended_at        timestamptz,
    retention_until     timestamptz,
    contact_email       text,
    users               bigint,
    storage_bytes       bigint,
    files               bigint,
    edition             text,
    edition_expires_at  timestamptz
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
           (SELECT count(*) FROM node n WHERE n.tenant_id = t.id AND n.kind = 'file' AND n.deleted_at IS NULL),
           t.edition, t.edition_expires_at
      FROM tenant t
     WHERE t.slug = p_slug AND t.status <> 'deleted';
END $$;

REVOKE ALL ON FUNCTION platform_tenant_get(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION platform_tenant_get(text) TO docvault_app;

COMMIT;
