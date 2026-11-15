-- 0058_entitlement_defaults_align.sql
--
-- 增值功能"默认停用"与写入口对齐（docs/56）。
--
-- 背景：三个档位的**对象**密级写入口一直是有判定的（上传、改密级），
-- 但**成员**密级（app_user.classification）没有，导致基础版租户新建账号
-- 仍能选 0–6 全部 7 档并写进库；同时开通租户时首个管理员被硬编码成 1 级。
-- 本迁移收两件事：
--   1. 清掉"从未拥有过密级能力"的租户里档位表达不了的成员密级；
--   2. 降档校验把成员密级纳入（此前只查 node，降档后账号上残留的 1–6 级会"冬眠"，
--      再升档时又复活，客户无法解释）。
--
-- 刻意不处理的情况：declared 是高档位但**已过期**的租户（生效档位回落 basic）。
-- 那类客户的密级数据是"曾经合法拥有"的，续费后应当恢复，不能趁降级清掉。
-- 只有"从来没买过"（tenant.edition = 'basic'）才清。
--
-- 返回列不变（仍是 7 列），旧镜像回滚时函数签名仍然对得上。

BEGIN;

-- ---------- 1. 存量修正：基础版且无密级加购 ----------
--
-- 判断"有没有真的买过密级"：tenant_entitlement 里有一条有效的 classification=on。
-- basic + 单项加购密级的客户确实能用密级（classLevels 会给 business 全集），
-- 清掉等于偷偷降级。
WITH basic_no_class AS (
    SELECT t.id
      FROM tenant t
     WHERE t.edition = 'basic'
       AND t.deleted_at IS NULL
       AND NOT EXISTS (
           SELECT 1
             FROM tenant_entitlement te
            WHERE te.tenant_id = t.id
              AND te.code = 'classification'
              AND te.state = 'on'
              AND (te.expires_at IS NULL OR te.expires_at > now())
       )
)
UPDATE app_user u
   SET classification = 0,
       updated_at = now()
  FROM basic_no_class b
 WHERE u.tenant_id = b.id
   AND u.deleted_at IS NULL
   AND u.classification > 0;

-- ---------- 2. 降档校验：对象 + 成员 ----------

DROP FUNCTION IF EXISTS platform_tenant_set_edition(text, text, timestamptz, text, text);

CREATE FUNCTION platform_tenant_set_edition(
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
    v_id           uuid;
    v_prev         text;
    v_prev_exp     timestamptz;
    v_target       text;
    v_obj_blocked  bigint := 0;
    v_obj_samples  text[];
    v_user_blocked bigint := 0;
    v_user_samples text[];
    v_has_class_ent boolean := false;
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

    -- basic + 单项加购密级时，客户确实拥有密级能力（与 classLevels 同口径），不拦。
    SELECT EXISTS (
        SELECT 1
          FROM tenant_entitlement te
         WHERE te.tenant_id = v_id
           AND te.code = 'classification'
           AND te.state = 'on'
           AND (te.expires_at IS NULL OR te.expires_at > now())
    ) INTO v_has_class_ent;

    -- 降档兼容性：目标档位表达不了的密级必须先降下来。
    -- 对象连回收站里的也一起算（恢复出来同样是违规数据）；
    -- 成员只算未删除的（删掉的账号登不进来，不构成越权）。
    IF v_target = 'basic' AND NOT v_has_class_ent THEN
        SELECT count(*), (array_agg(n.name ORDER BY n.name))[1:5]
          INTO v_obj_blocked, v_obj_samples
          FROM node n
         WHERE n.tenant_id = v_id AND n.classification > 0;

        SELECT count(*), (array_agg('成员 ' || u.username ORDER BY u.username))[1:5]
          INTO v_user_blocked, v_user_samples
          FROM app_user u
         WHERE u.tenant_id = v_id AND u.deleted_at IS NULL AND u.classification > 0;
    ELSIF v_target = 'professional' THEN
        SELECT count(*), (array_agg(n.name ORDER BY n.name))[1:5]
          INTO v_obj_blocked, v_obj_samples
          FROM node n
         WHERE n.tenant_id = v_id AND n.classification IN (1, 2, 5, 6);

        SELECT count(*), (array_agg('成员 ' || u.username ORDER BY u.username))[1:5]
          INTO v_user_blocked, v_user_samples
          FROM app_user u
         WHERE u.tenant_id = v_id AND u.deleted_at IS NULL AND u.classification IN (1, 2, 5, 6);
    END IF;

    IF v_obj_blocked + v_user_blocked > 0 THEN
        -- 不改任何东西，把清单带回去让运营先处理数据。
        -- 样本里带"成员 "前缀，运营一眼能看出是账号还是文件被挡。
        RETURN QUERY SELECT v_id, v_prev, v_prev, v_prev_exp, v_prev_exp,
                            v_obj_blocked + v_user_blocked,
                            (COALESCE(v_obj_samples, ARRAY[]::text[]) ||
                             COALESCE(v_user_samples, ARRAY[]::text[]))[1:8];
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

COMMENT ON FUNCTION platform_tenant_set_edition(text, text, timestamptz, text, text)
    IS '平台改档：降档前校验对象与成员密级是否在目标档位可表达范围内；basic+加购密级不拦';

COMMIT;
