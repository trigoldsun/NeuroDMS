-- 用户组（M1-4 补齐）
--
-- 之前只在设计文档（FSD §2.1）里定义了组，但漏写进迁移，
-- 导致权限判定读取组成员时报 "relation group_member does not exist"。
-- 组是 7 类授权主体之一，缺失会让"按组授权"不可用。

CREATE TABLE user_group (
    id         uuid PRIMARY KEY,
    tenant_id  uuid NOT NULL REFERENCES tenant(id),
    name       text NOT NULL,
    kind       text NOT NULL DEFAULT 'static' CHECK (kind IN ('static','dynamic','ldap')),
    rule       jsonb,
    ldap_dn    text,
    created_at timestamptz NOT NULL DEFAULT now(),
    deleted_at timestamptz
);
CREATE UNIQUE INDEX uq_group_tenant_name ON user_group(tenant_id, lower(name)) WHERE deleted_at IS NULL;

ALTER TABLE user_group ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_group FORCE ROW LEVEL SECURITY;
CREATE POLICY user_group_isolation ON user_group
    USING (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);

CREATE TABLE group_member (
    tenant_id  uuid NOT NULL REFERENCES tenant(id),
    group_id   uuid NOT NULL REFERENCES user_group(id),
    user_id    uuid NOT NULL REFERENCES app_user(id),
    source     text NOT NULL DEFAULT 'manual' CHECK (source IN ('manual','ldap','rule')),
    added_at   timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (group_id, user_id)
);
CREATE INDEX ix_group_member_user ON group_member(tenant_id, user_id);

ALTER TABLE group_member ENABLE ROW LEVEL SECURITY;
ALTER TABLE group_member FORCE ROW LEVEL SECURITY;
CREATE POLICY group_member_isolation ON group_member
    USING (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON user_group, group_member TO docvault_app;
