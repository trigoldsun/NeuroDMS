-- 空间所有权移交
--
-- 为什么需要"请求"这张表，而不是所有移交都立即生效：
-- 系统管理员把别人的空间移交给自己，是**利益冲突**动作——他完全可以用
-- 这个入口把任何一个员工的空间收进自己名下，然后读里面的文件。
-- 所以这一种组合不能自己说了算，必须由原所有者点确认。
--
-- 其余组合（所有者自己移交、管理员转给第三方）没有利益冲突，立即生效，
-- 但仍然落一条记录：出了争议要能回答"谁在什么时候把哪个空间给了谁"。
--
-- 三种 mode：
--   owner        所有者本人发起（立即生效）
--   admin        管理员转给第三方（立即生效）
--   admin_to_self 管理员转给自己（需原所有者确认）
CREATE TABLE IF NOT EXISTS space_transfer (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id    uuid NOT NULL REFERENCES tenant(id),
    space_id     uuid NOT NULL REFERENCES space(id) ON DELETE CASCADE,
    from_user_id uuid NOT NULL REFERENCES app_user(id),
    to_user_id   uuid NOT NULL REFERENCES app_user(id),
    initiated_by uuid NOT NULL REFERENCES app_user(id),
    mode         text NOT NULL CHECK (mode IN ('owner', 'admin', 'admin_to_self')),
    status       text NOT NULL DEFAULT 'pending'
                 CHECK (status IN ('pending', 'approved', 'rejected', 'cancelled', 'expired')),
    reason       text NOT NULL DEFAULT '',
    created_at   timestamptz NOT NULL DEFAULT now(),
    -- 7 天：足够覆盖休假与出差，又不至于让一条悬挂请求永远挡住后续移交
    expires_at   timestamptz NOT NULL DEFAULT now() + interval '7 days',
    decided_at   timestamptz,
    decided_by   uuid
);

-- 同一空间同时只允许一条待确认请求。
-- 用部分唯一索引而不是应用层判断：两个管理员同时点"移交"，应用层先查后插必然漏一个。
CREATE UNIQUE INDEX IF NOT EXISTS uq_space_transfer_pending
    ON space_transfer (space_id) WHERE status = 'pending';

-- 所有者看"等我确认的请求"，管理员看"我发起的请求"
CREATE INDEX IF NOT EXISTS ix_space_transfer_from
    ON space_transfer (tenant_id, from_user_id, status);

-- 过期清理：与上传会话清理同一批任务扫
CREATE INDEX IF NOT EXISTS ix_space_transfer_expires
    ON space_transfer (expires_at) WHERE status = 'pending';

ALTER TABLE space_transfer ENABLE ROW LEVEL SECURITY;
ALTER TABLE space_transfer FORCE ROW LEVEL SECURITY;
CREATE POLICY space_transfer_isolation ON space_transfer
    USING (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);

GRANT SELECT, INSERT, UPDATE ON space_transfer TO docvault_app;
