-- 分片上传会话（M2-E / AC-78）
--
-- 为什么必须有服务端会话而不是"前端切块 + 一次 complete"：
--   1. 断点续传需要知道哪些分片已经收到；
--   2. complete 必须幂等——网络重试、用户重复点击都会重复调用，
--      没有"已完成"状态就只能靠唯一约束撞运气，结果是重复产生版本；
--   3. 秒传（AC-67）必须由服务端比对内容哈希，
--      绝不能信客户端声明的 size/sha256（否则可以"声明很小的 size 换取秒传"）。

CREATE TABLE IF NOT EXISTS upload_session (
    id             uuid PRIMARY KEY,
    tenant_id      uuid NOT NULL REFERENCES tenant(id),
    space_id       uuid NOT NULL REFERENCES space(id),
    parent_id      uuid,
    name           text NOT NULL CHECK (length(name) BETWEEN 1 AND 255),
    -- 客户端声明的总大小与哈希：仅用于**校验**，不作为事实写入
    declared_size  bigint NOT NULL CHECK (declared_size >= 0),
    declared_sha256 bytea,
    received_bytes bigint NOT NULL DEFAULT 0,
    status         text NOT NULL DEFAULT 'open' CHECK (status IN ('open','completed','aborted')),
    -- complete 的结果（幂等返回用）
    node_id        uuid,
    version_id     uuid,
    deduped        boolean NOT NULL DEFAULT false,
    created_by     uuid NOT NULL REFERENCES app_user(id),
    created_at     timestamptz NOT NULL DEFAULT now(),
    updated_at     timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ix_upload_session_owner
    ON upload_session(tenant_id, created_by, created_at DESC);

ALTER TABLE upload_session ENABLE ROW LEVEL SECURITY;
ALTER TABLE upload_session FORCE ROW LEVEL SECURITY;
CREATE POLICY upload_session_isolation ON upload_session
    USING (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);

CREATE TABLE IF NOT EXISTS upload_part (
    tenant_id  uuid NOT NULL REFERENCES tenant(id),
    session_id uuid NOT NULL REFERENCES upload_session(id) ON DELETE CASCADE,
    part_no    int NOT NULL CHECK (part_no >= 1),
    size_bytes bigint NOT NULL CHECK (size_bytes >= 0),
    sha256     bytea,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (session_id, part_no)
);

ALTER TABLE upload_part ENABLE ROW LEVEL SECURITY;
ALTER TABLE upload_part FORCE ROW LEVEL SECURITY;
-- 刻意**不**用"子查询 upload_session"来判租户：
-- 策略里的跨表子查询会再次触发对方的 RLS，既慢又容易写出递归，
-- 直接用本表的 tenant_id 最简单，也不会因为策略变化而漏。
CREATE POLICY upload_part_isolation ON upload_part
    USING (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON upload_session, upload_part TO docvault_app;
