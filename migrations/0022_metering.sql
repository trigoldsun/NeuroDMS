-- 计量：事件账本、日聚合、触发器维护的瞬时量、对账（M3-2 / M3-3）
--
-- 为什么这套设计能说"计量 100% 准确"：
--
-- 1) 可累加量（转码秒数、API 调用、分享访问）走 usage_event 账本。
--    每条事件带 dedupe_key，唯一约束保证"重试不会记两次"。
--    日聚合由 AFTER INSERT 触发器维护，不需要额外任务，也不会漏。
--
-- 2) 瞬时量（存储字节、在册用户数）走 BEFORE 触发器直接更新 tenant_usage，
--    与业务写入**同一事务**提交。业务成功账就变，业务回滚账就回滚，
--    不存在"记了但没写进去"或"写了但没记"。
--
-- 3) 仍然保留对账：触发器可能被绕过（运维手工 SQL、恢复备份、历史数据）。
--    platform_usage_reconcile 用 node/app_user 的事实值重算，偏差即为漂移。
--    "准确"不是靠相信触发器，而是靠**可复核**。

-- ---------- 1. 事件账本 ----------

CREATE TABLE IF NOT EXISTS usage_event (
    id          bigserial PRIMARY KEY,
    tenant_id   uuid NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
    metric      text NOT NULL,
    quantity    bigint NOT NULL CHECK (quantity >= 0),
    -- 幂等键：同一业务动作重试时必须用同一个 key。
    -- 例如转码任务用 job_id、分享访问用 visit_id。
    dedupe_key  text NOT NULL,
    occurred_at timestamptz NOT NULL DEFAULT now(),
    meta        jsonb NOT NULL DEFAULT '{}'::jsonb,
    CONSTRAINT usage_event_metric_chk CHECK (metric IN (
        'api_calls', 'transcode_seconds', 'share_views', 'preview_renders', 'egress_bytes'
    ))
);

-- 幂等就是这条唯一约束
CREATE UNIQUE INDEX IF NOT EXISTS uq_usage_event_dedupe
    ON usage_event (tenant_id, dedupe_key);
CREATE INDEX IF NOT EXISTS idx_usage_event_tenant_time
    ON usage_event (tenant_id, occurred_at DESC);

ALTER TABLE usage_event ENABLE ROW LEVEL SECURITY;
ALTER TABLE usage_event FORCE ROW LEVEL SECURITY;
CREATE POLICY usage_event_isolation ON usage_event
    USING (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);

-- 只给 SELECT/INSERT：账本一旦写入不可改、不可删（应用角色没有那个权限）
GRANT SELECT, INSERT ON usage_event TO docvault_app;
GRANT USAGE, SELECT ON SEQUENCE usage_event_id_seq TO docvault_app;

-- ---------- 2. 日聚合 ----------

CREATE TABLE IF NOT EXISTS usage_daily (
    tenant_id uuid NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
    day       date NOT NULL,
    metric    text NOT NULL,
    quantity  bigint NOT NULL DEFAULT 0 CHECK (quantity >= 0),
    PRIMARY KEY (tenant_id, day, metric)
);

ALTER TABLE usage_daily ENABLE ROW LEVEL SECURITY;
ALTER TABLE usage_daily FORCE ROW LEVEL SECURITY;
CREATE POLICY usage_daily_isolation ON usage_daily
    USING (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);

-- 只读：聚合只由下面的触发器函数写，应用层改不了对账数据
GRANT SELECT ON usage_daily TO docvault_app;

-- ---------- 3. 事件 → 日聚合 ----------

-- SECURITY DEFINER 的理由：应用角色只有 usage_daily 的 SELECT，
-- 而聚合写入必须发生。把写权限收进这个函数，等于把"只有这条路径能改账"变成权限事实。
CREATE OR REPLACE FUNCTION usage_event_rollup()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
BEGIN
    INSERT INTO usage_daily (tenant_id, day, metric, quantity)
    VALUES (NEW.tenant_id, NEW.occurred_at::date, NEW.metric, NEW.quantity)
    ON CONFLICT (tenant_id, day, metric)
    DO UPDATE SET quantity = usage_daily.quantity + EXCLUDED.quantity;
    RETURN NULL;
END $$;

DROP TRIGGER IF EXISTS trg_usage_event_rollup ON usage_event;
CREATE TRIGGER trg_usage_event_rollup
    AFTER INSERT ON usage_event
    FOR EACH ROW EXECUTE FUNCTION usage_event_rollup();

-- ---------- 4. 瞬时量：node → storage_bytes，并在此处强制存储配额 ----------

-- 是否计入用量：只有"未删除的文件"占配额。
-- 软删除的文件在保留期内仍然占磁盘，但按产品口径不占客户配额——
-- 这是刻意的选择：否则客户"删了还是超限"，无法自助恢复。
CREATE OR REPLACE FUNCTION node_counts_for_usage(p_kind text, p_deleted timestamptz, p_size bigint)
RETURNS bigint
LANGUAGE sql IMMUTABLE
AS $$
    SELECT CASE WHEN p_kind = 'file' AND p_deleted IS NULL THEN COALESCE(p_size, 0) ELSE 0 END
$$;

CREATE OR REPLACE FUNCTION node_usage_sync()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_old   bigint := 0;
    v_new   bigint := 0;
    v_delta bigint;
    v_used  bigint;
    v_max   bigint;
    v_exceed text;
    v_tenant uuid;
BEGIN
    -- DELETE 时 NEW 为 NULL：必须显式取 OLD.tenant_id，
    -- 否则 "INSERT INTO tenant_usage(tenant_id) VALUES (NEW.tenant_id)"
    -- 会在删除时炸掉（表现为"删用户/删文件失败"，而原因写得很难懂）。
    IF TG_OP = 'DELETE' THEN
        v_tenant := OLD.tenant_id;
    ELSE
        v_tenant := NEW.tenant_id;
    END IF;

    IF TG_OP <> 'INSERT' THEN
        v_old := node_counts_for_usage(OLD.kind, OLD.deleted_at, OLD.size_bytes);
    END IF;
    IF TG_OP <> 'DELETE' THEN
        v_new := node_counts_for_usage(NEW.kind, NEW.deleted_at, NEW.size_bytes);
    END IF;

    v_delta := v_new - v_old;
    IF v_delta = 0 THEN
        -- 改名字、改密级等不涉及用量。
        --
        -- 注意：BEFORE 触发器必须返回记录本身，返回 NULL 等于**取消这次写入**
        -- 且不报错。这里曾经写成 RETURN NULL，结果是"重命名成功、内容不见了"，
        -- 而且日志里什么都没有。这是 BEFORE 触发器最经典的坑。
        IF TG_OP = 'DELETE' THEN
            RETURN OLD;
        END IF;
        RETURN NEW;
    END IF;

    -- 行锁是"准确"的关键：两个并发上传如果各自读到旧值再相加，
    -- 后提交的会覆盖前者（lost update），账立刻少算一份。
    -- 这里按租户串行化用量更新，代价是同一租户的上传排队——
    -- 上传本身是 I/O 密集，这点排队远不是瓶颈。
    INSERT INTO tenant_usage (tenant_id) VALUES (v_tenant)
    ON CONFLICT (tenant_id) DO NOTHING;

    SELECT storage_bytes INTO v_used
      FROM tenant_usage WHERE tenant_id = v_tenant FOR UPDATE;

    IF v_delta > 0 THEN
        SELECT q.max_storage_bytes, q.on_exceed INTO v_max, v_exceed
          FROM tenant_quota q WHERE q.tenant_id = v_tenant;
        -- 只有 reject 在这里硬拦；readonly/warn 由应用层按策略处理（见 quota 包），
        -- 因为"降级为只读"要连带影响后续所有写请求，属于会话级决策。
        IF v_max IS NOT NULL AND v_exceed = 'reject' AND v_used + v_delta > v_max THEN
            RAISE EXCEPTION 'quota:storage' USING ERRCODE = 'DV403';
        END IF;
    END IF;

    UPDATE tenant_usage
       -- GREATEST(...,0)：账本一旦与事实脱节（历史数据、人工修数），
       -- 减法可能算出负数，而 CHECK 约束会让**删除操作本身失败**。
       -- 这里宁可把账截到 0（对账会把它修回来），也不能让客户删不掉文件。
       SET storage_bytes = GREATEST(v_used + v_delta, 0), updated_at = now()
     WHERE tenant_id = v_tenant;

    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    END IF;
    RETURN NEW;
END $$;

DROP TRIGGER IF EXISTS trg_node_usage ON node;
CREATE TRIGGER trg_node_usage
    BEFORE INSERT OR UPDATE OF kind, deleted_at, size_bytes OR DELETE ON node
    FOR EACH ROW EXECUTE FUNCTION node_usage_sync();

-- ---------- 5. 瞬时量：app_user → active_users，并强制用户数配额 ----------

-- 计数口径与"能不能登录"一致：未删除、且不是 suspended。
-- 若口径与登录判定不一致，客户会看到"用户数没满但加不了人"。
CREATE OR REPLACE FUNCTION user_counts_for_usage(p_deleted timestamptz, p_status text)
RETURNS int
LANGUAGE sql IMMUTABLE
AS $$
    SELECT CASE WHEN p_deleted IS NULL AND p_status <> 'suspended' THEN 1 ELSE 0 END
$$;

CREATE OR REPLACE FUNCTION user_usage_sync()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_old int := 0;
    v_new int := 0;
    v_delta int;
    v_used int;
    v_max  int;
    v_exceed text;
    v_tenant uuid;
BEGIN
    IF TG_OP = 'DELETE' THEN
        v_tenant := OLD.tenant_id;
    ELSE
        v_tenant := NEW.tenant_id;
    END IF;

    IF TG_OP <> 'INSERT' THEN
        v_old := user_counts_for_usage(OLD.deleted_at, OLD.status);
    END IF;
    IF TG_OP <> 'DELETE' THEN
        v_new := user_counts_for_usage(NEW.deleted_at, NEW.status);
    END IF;

    v_delta := v_new - v_old;
    IF v_delta = 0 THEN
        IF TG_OP = 'DELETE' THEN
            RETURN OLD;
        END IF;
        RETURN NEW;
    END IF;

    INSERT INTO tenant_usage (tenant_id) VALUES (v_tenant)
    ON CONFLICT (tenant_id) DO NOTHING;

    SELECT active_users INTO v_used
      FROM tenant_usage WHERE tenant_id = v_tenant FOR UPDATE;

    IF v_delta > 0 THEN
        SELECT q.max_users, q.on_exceed INTO v_max, v_exceed
          FROM tenant_quota q WHERE q.tenant_id = v_tenant;
        IF v_max IS NOT NULL AND v_exceed = 'reject' AND v_used + v_delta > v_max THEN
            RAISE EXCEPTION 'quota:users' USING ERRCODE = 'DV403';
        END IF;
    END IF;

    UPDATE tenant_usage
       SET active_users = GREATEST(v_used + v_delta, 0), updated_at = now()
     WHERE tenant_id = v_tenant;

    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    END IF;
    RETURN NEW;
END $$;

DROP TRIGGER IF EXISTS trg_user_usage ON app_user;
CREATE TRIGGER trg_user_usage
    BEFORE INSERT OR UPDATE OF status, deleted_at OR DELETE ON app_user
    FOR EACH ROW EXECUTE FUNCTION user_usage_sync();

-- ---------- 6. 记录用量（应用唯一入口，幂等） ----------

-- 返回"这条事件是否真的记上了"：false 表示 dedupe_key 已存在（重试）。
-- 调用方据此决定是否重复执行副作用。
CREATE OR REPLACE FUNCTION usage_record(
    p_tenant  uuid,
    p_metric  text,
    p_qty     bigint,
    p_dedupe  text,
    p_meta    jsonb DEFAULT '{}'::jsonb
) RETURNS boolean
LANGUAGE plpgsql
AS $$
DECLARE
    v_id bigint;
BEGIN
    INSERT INTO usage_event (tenant_id, metric, quantity, dedupe_key, meta)
    VALUES (p_tenant, p_metric, GREATEST(p_qty, 0), p_dedupe, COALESCE(p_meta, '{}'::jsonb))
    ON CONFLICT (tenant_id, dedupe_key) DO NOTHING
    RETURNING id INTO v_id;
    RETURN v_id IS NOT NULL;
END $$;

GRANT EXECUTE ON FUNCTION usage_record(uuid, text, bigint, text, jsonb) TO docvault_app;

-- ---------- 7. 平台侧：用量读取与对账 ----------

CREATE OR REPLACE FUNCTION platform_tenant_usage(
    p_slug text,
    p_from date,
    p_to   date
) RETURNS TABLE (day date, metric text, quantity bigint)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_id uuid;
BEGIN
    SELECT t.id INTO v_id FROM tenant t WHERE t.slug = p_slug AND t.deleted_at IS NULL;
    IF v_id IS NULL THEN
        RAISE EXCEPTION 'tenant not found' USING ERRCODE = 'DV404';
    END IF;
    RETURN QUERY
    SELECT d.day, d.metric, d.quantity
      FROM usage_daily d
     WHERE d.tenant_id = v_id AND d.day BETWEEN p_from AND p_to
     ORDER BY d.day, d.metric;
END $$;

-- 对账：拿"事实"（node/app_user 的真实聚合）比对"账"（tenant_usage）。
--
-- p_repair 为真时把账改成事实值，并留下一行 usage_reconcile 审计用的调整记录
-- （写入 usage_event 的 metric 受限，因此这里只改 tenant_usage，调整痕迹由调用方审计）。
CREATE OR REPLACE FUNCTION platform_usage_reconcile(p_repair boolean)
RETURNS TABLE (
    slug            text,
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
           us.storage_bytes,
           COALESCE((SELECT sum(n.size_bytes) FROM node n
                      WHERE n.tenant_id = t.id AND n.kind = 'file' AND n.deleted_at IS NULL), 0)::bigint,
           COALESCE((SELECT sum(n.size_bytes) FROM node n
                      WHERE n.tenant_id = t.id AND n.kind = 'file' AND n.deleted_at IS NULL), 0)::bigint
             - us.storage_bytes,
           us.active_users,
           COALESCE((SELECT count(*) FROM app_user u
                      WHERE u.tenant_id = t.id AND u.deleted_at IS NULL AND u.status <> 'suspended'), 0)::int,
           COALESCE((SELECT count(*) FROM app_user u
                      WHERE u.tenant_id = t.id AND u.deleted_at IS NULL AND u.status <> 'suspended'), 0)::int
             - us.active_users
      FROM tenant t
      JOIN tenant_usage us ON us.tenant_id = t.id
     WHERE t.deleted_at IS NULL
     ORDER BY t.slug;
END $$;

REVOKE ALL ON FUNCTION platform_tenant_usage(text, date, date) FROM PUBLIC;
REVOKE ALL ON FUNCTION platform_usage_reconcile(boolean) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION platform_tenant_usage(text, date, date) TO docvault_app;
GRANT EXECUTE ON FUNCTION platform_usage_reconcile(boolean) TO docvault_app;

COMMENT ON FUNCTION node_usage_sync() IS
    '存储用量与配额：BEFORE 触发器，与文件写入同事务；按租户行锁保证并发不丢更新';
COMMENT ON FUNCTION platform_usage_reconcile(boolean) IS
    '对账：用 node/app_user 事实值比对账本，可选择性修正';
