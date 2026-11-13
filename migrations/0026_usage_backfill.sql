-- 计量升级路径：为存量租户补齐账本行，并修正对账的 JOIN 口径（M3-2 修订）
--
-- 两个真实问题，都是"只在升级时出现"的那一类：
--
-- 1) 存量租户没有 tenant_usage / tenant_quota / tenant_config 行。
--    0021 只给"新开通的租户"插入这些行（platform_tenant_create 里做的），
--    而升级前就存在的租户不会经过那条路径。
--    后果：对账时这些租户被 INNER JOIN 直接丢掉——报表上"没有偏差"，
--    实际上是"根本没统计",这比显示偏差更危险。
--
-- 2) 触发器虽然会按需 INSERT tenant_usage，但那只在"下一次文件变动"时发生。
--    一个长期没人上传的租户，账面上会一直是空的。
--
-- 因此这里做两件事：回填缺失行（幂等）、把对账改成 LEFT JOIN 并在修正模式下补齐。

-- ---------- 1. 回填 ----------

INSERT INTO tenant_config (tenant_id)
SELECT t.id FROM tenant t
ON CONFLICT (tenant_id) DO NOTHING;

INSERT INTO tenant_quota (tenant_id)
SELECT t.id FROM tenant t
ON CONFLICT (tenant_id) DO NOTHING;

-- 回填账本时要按事实值算初值，不能插 0 了事：
-- 否则升级瞬间所有存量租户的存储用量都变成 0，配额形同失效。
INSERT INTO tenant_usage (tenant_id, storage_bytes, active_users)
SELECT t.id,
       COALESCE((SELECT sum(n.size_bytes) FROM node n
                  WHERE n.tenant_id = t.id AND n.kind = 'file' AND n.deleted_at IS NULL), 0),
       COALESCE((SELECT count(*) FROM app_user u
                  WHERE u.tenant_id = t.id AND u.deleted_at IS NULL AND u.status <> 'suspended'), 0)
  FROM tenant t
ON CONFLICT (tenant_id) DO NOTHING;

-- ---------- 2. 修正对账 ----------

CREATE OR REPLACE FUNCTION platform_usage_reconcile(p_repair boolean)
RETURNS TABLE (
    slug             text,
    storage_recorded bigint,
    storage_actual   bigint,
    storage_drift    bigint,
    users_recorded   int,
    users_actual     int,
    users_drift      int
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
BEGIN
    IF p_repair THEN
        -- 先补齐缺失行，再按事实值改写。
        -- 顺序不能反：少了这一步，缺失的租户会被后面的 UPDATE 跳过，
        -- 表现为"点了修正，但那个租户的用量还是空的"。
        INSERT INTO tenant_usage (tenant_id)
        SELECT t.id FROM tenant t
        ON CONFLICT (tenant_id) DO NOTHING;

        UPDATE tenant_usage us
           SET storage_bytes = COALESCE((
                   SELECT sum(n.size_bytes) FROM node n
                    WHERE n.tenant_id = us.tenant_id AND n.kind = 'file' AND n.deleted_at IS NULL), 0),
               active_users = COALESCE((
                   SELECT count(*) FROM app_user u
                    WHERE u.tenant_id = us.tenant_id AND u.deleted_at IS NULL AND u.status <> 'suspended'), 0),
               updated_at = now();
    END IF;

    RETURN QUERY
    SELECT t.slug,
           COALESCE(us.storage_bytes, 0),
           COALESCE((SELECT sum(n.size_bytes) FROM node n
                      WHERE n.tenant_id = t.id AND n.kind = 'file' AND n.deleted_at IS NULL), 0)::bigint,
           COALESCE((SELECT sum(n.size_bytes) FROM node n
                      WHERE n.tenant_id = t.id AND n.kind = 'file' AND n.deleted_at IS NULL), 0)::bigint
             - COALESCE(us.storage_bytes, 0),
           COALESCE(us.active_users, 0),
           COALESCE((SELECT count(*) FROM app_user u
                      WHERE u.tenant_id = t.id AND u.deleted_at IS NULL AND u.status <> 'suspended'), 0)::int,
           COALESCE((SELECT count(*) FROM app_user u
                      WHERE u.tenant_id = t.id AND u.deleted_at IS NULL AND u.status <> 'suspended'), 0)::int
             - COALESCE(us.active_users, 0)
      FROM tenant t
      -- LEFT JOIN 而不是 JOIN：缺账本行的租户必须出现在报表里（并在修正时被补上），
      -- 否则"没有偏差"这句话就是假的。
      LEFT JOIN tenant_usage us ON us.tenant_id = t.id
     WHERE t.deleted_at IS NULL
     ORDER BY t.slug;
END $$;

REVOKE ALL ON FUNCTION platform_usage_reconcile(boolean) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION platform_usage_reconcile(boolean) TO docvault_app;

COMMENT ON FUNCTION platform_usage_reconcile(boolean) IS
    '对账：LEFT JOIN 账本，缺行也会列出；repair=true 时先补行再按事实值改写';
