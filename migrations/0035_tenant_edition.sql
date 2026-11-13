-- 0035_tenant_edition.sql
--
-- 租户档位（docs/17 §2、§4）。
--
-- 在此之前，"三档"只存在于报价单里：代码中没有任何地方判断租户买了哪一档，
-- 所有租户拿到的都是全功能。本迁移把档位落成一个可判定的字段。
--
-- 两个关键取舍：
--   1. 存量租户一律回填 business。加字段当天如果默认成 basic，
--      所有在线客户会立刻失去密级、AD、邮件分享——这不是"上线分档"，
--      是"上线集体降级"，必然引发投诉。存量豁免必须显式做。
--   2. 到期时间允许为空（永久）。SaaS 存量合同多为长期，不能强制填期限。

BEGIN;

ALTER TABLE tenant ADD COLUMN IF NOT EXISTS edition text NOT NULL DEFAULT 'basic';
ALTER TABLE tenant DROP CONSTRAINT IF EXISTS tenant_edition_chk;
ALTER TABLE tenant ADD CONSTRAINT tenant_edition_chk
    CHECK (edition IN ('basic', 'professional', 'business'));

-- 到期时间：NULL 表示不限期。到期后由运行时判定降级，不落库、不依赖定时任务。
ALTER TABLE tenant ADD COLUMN IF NOT EXISTS edition_expires_at timestamptz;

COMMENT ON COLUMN tenant.edition IS '租户档位：basic / professional / business';
COMMENT ON COLUMN tenant.edition_expires_at IS '档位到期时间；NULL 表示不限期。到期后运行时按 basic 计算能力';

-- 存量豁免：迁移执行时尚未创建"新租户"，因此这条只影响已有租户。
UPDATE tenant SET edition = 'business'
 WHERE edition = 'basic'
   AND created_at < now();

-- 改档历史：只追加。审计里也要有一条，但审计是链式事件流，
-- 这里保留的是"当前档位是怎么来的"，便于客服回答"我们什么时候买的、谁改的"。
CREATE TABLE IF NOT EXISTS tenant_edition_change (
    id           bigserial PRIMARY KEY,
    tenant_id    uuid NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
    from_edition text,
    to_edition   text NOT NULL,
    from_expires timestamptz,
    to_expires   timestamptz,
    reason       text,
    operator     text NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ix_edition_change_tenant
    ON tenant_edition_change(tenant_id, created_at DESC);

GRANT SELECT, INSERT ON tenant_edition_change TO docvault_app;
GRANT UPDATE (edition, edition_expires_at) ON tenant TO docvault_app;

ALTER TABLE tenant_edition_change ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_edition_change FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_edition_change_isolation ON tenant_edition_change
    USING (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);

-- ---------- 平台侧改档 ----------
--
-- 用 SECURITY DEFINER 而不是让应用直接 UPDATE tenant：
-- 平台接口要改的是"别的租户"的行，应用连接受 RLS 约束只能看自己，
-- 现有平台端点（set_status 等）也都是这个模式。
--
-- 降档校验放在函数内、与更新同一事务：
-- 先查后改如果分成两次往返，两个运营并发降档时都可能通过校验。
CREATE OR REPLACE FUNCTION platform_tenant_set_edition(
    p_slug     text,
    p_edition  text,
    p_expires  timestamptz,
    p_reason   text,
    p_operator text
)
RETURNS TABLE (
    tid             uuid,
    prev_edition    text,
    cur_edition     text,
    prev_expires    timestamptz,
    cur_expires     timestamptz,
    blocked_count   bigint,
    blocked_samples text[]
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_id      uuid;
    v_prev    text;
    v_prev_exp timestamptz;
    v_target  text;
    v_blocked bigint := 0;
    v_samples text[];
BEGIN
    SELECT t.id, t.edition, t.edition_expires_at
      INTO v_id, v_prev, v_prev_exp
      FROM tenant t
     WHERE t.slug = lower(btrim(p_slug))
       FOR UPDATE;

    IF v_id IS NULL THEN
        RAISE EXCEPTION '租户不存在' USING ERRCODE = 'DV404';
    END IF;

    v_target := lower(btrim(p_edition));
    IF v_target NOT IN ('basic', 'professional', 'business') THEN
        RAISE EXCEPTION '未知档位' USING ERRCODE = 'DV002';
    END IF;

    -- 降档兼容性：目标档位表达不了的密级必须先降下来。
    -- 这里连回收站里的对象也一起算——恢复出来同样是违规数据。
    IF v_target = 'basic' THEN
        SELECT count(*), (array_agg(n.name ORDER BY n.name))[1:5]
          INTO v_blocked, v_samples
          FROM node n
         WHERE n.tenant_id = v_id AND n.classification > 0;
    ELSIF v_target = 'professional' THEN
        SELECT count(*), (array_agg(n.name ORDER BY n.name))[1:5]
          INTO v_blocked, v_samples
          FROM node n
         WHERE n.tenant_id = v_id AND n.classification IN (1, 2, 5, 6);
    END IF;

    IF v_blocked > 0 THEN
        -- 不改任何东西，把清单带回去让运营先处理数据
        RETURN QUERY SELECT v_id, v_prev, v_prev, v_prev_exp, v_prev_exp, v_blocked, v_samples;
        RETURN;
    END IF;

    UPDATE tenant
       SET edition = v_target, edition_expires_at = p_expires
     WHERE id = v_id;

    INSERT INTO tenant_edition_change
        (tenant_id, from_edition, to_edition, from_expires, to_expires, reason, operator)
    VALUES
        (v_id, v_prev, v_target, v_prev_exp, p_expires, p_reason, p_operator);

    RETURN QUERY SELECT v_id, v_prev, v_target, v_prev_exp, p_expires, 0::bigint, NULL::text[];
END $$;

REVOKE ALL ON FUNCTION platform_tenant_set_edition(text, text, timestamptz, text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION platform_tenant_set_edition(text, text, timestamptz, text, text) TO docvault_app;

-- 查询某租户的档位与最近变更
CREATE OR REPLACE FUNCTION platform_tenant_edition(p_slug text)
RETURNS TABLE (
    tid        uuid,
    edition    text,
    expires_at timestamptz,
    changes    jsonb
)
LANGUAGE sql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
    SELECT t.id, t.edition, t.edition_expires_at,
           COALESCE((
               SELECT jsonb_agg(x ORDER BY x.created_at DESC)
                 FROM (
                     SELECT c.from_edition, c.to_edition, c.from_expires, c.to_expires,
                            c.reason, c.operator, c.created_at
                       FROM tenant_edition_change c
                      WHERE c.tenant_id = t.id
                      ORDER BY c.created_at DESC
                      LIMIT 20
                 ) x
           ), '[]'::jsonb)
      FROM tenant t
     WHERE t.slug = lower(btrim(p_slug));
$$;

REVOKE ALL ON FUNCTION platform_tenant_edition(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION platform_tenant_edition(text) TO docvault_app;

COMMIT;
