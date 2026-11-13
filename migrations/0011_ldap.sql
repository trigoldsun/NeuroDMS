-- LDAP/AD 目录接入（M1-3c）
--
-- 设计取向：目录是"账号与组织的真源"，但**权限不是**。
-- 同步只负责把人、部门、组搬进来；谁能看哪个文件仍由本地 ACE 决定。
-- 这样即使目录被改（例如有人把自己加进 Domain Admins），也不会自动获得文档权限。

ALTER TABLE app_user
    -- 目录侧唯一标识（AD 用 objectGUID，OpenLDAP 用 entryUUID 或 DN）
    ADD COLUMN external_id text,
    -- 最近一次从目录同步的时间；为空表示本地账号
    ADD COLUMN synced_at timestamptz,
    -- 目录里设为 disabled 的账号：保留主键与历史审计，只停用（不物理删除）
    ADD COLUMN directory_disabled boolean NOT NULL DEFAULT false;

CREATE UNIQUE INDEX uq_user_external
    ON app_user(tenant_id, source, external_id)
    WHERE external_id IS NOT NULL AND deleted_at IS NULL;

-- 同步水位：记录每次同步的增量起点，便于排障与"这次同步了什么"
CREATE TABLE directory_sync (
    id             uuid PRIMARY KEY,
    tenant_id      uuid NOT NULL REFERENCES tenant(id),
    started_at     timestamptz NOT NULL DEFAULT now(),
    finished_at    timestamptz,
    status         text NOT NULL DEFAULT 'running'
        CHECK (status IN ('running','ok','failed')),
    -- 水位：AD 用 uSNChanged 最大值，OpenLDAP 用 modifyTimestamp
    watermark      text,
    users_seen     int NOT NULL DEFAULT 0,
    users_created  int NOT NULL DEFAULT 0,
    users_updated  int NOT NULL DEFAULT 0,
    users_disabled int NOT NULL DEFAULT 0,
    users_restored int NOT NULL DEFAULT 0,
    groups_synced  int NOT NULL DEFAULT 0,
    members_linked int NOT NULL DEFAULT 0,
    error          text
);
CREATE INDEX ix_sync_tenant ON directory_sync(tenant_id, started_at DESC);

ALTER TABLE directory_sync ENABLE ROW LEVEL SECURITY;
ALTER TABLE directory_sync FORCE ROW LEVEL SECURITY;
CREATE POLICY directory_sync_isolation ON directory_sync
    USING (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON directory_sync TO docvault_app;
