-- 访问控制条目与角色分配（M1-4）
--
-- ACE 用位图落库：一行即可判定一个对象上的全部权限，
-- 避免"每个权限项一行"导致判定时需要扫几十行。
-- 位定义必须与 internal/authz/bit.go 保持一致。

CREATE TABLE user_role (
    tenant_id uuid NOT NULL REFERENCES tenant(id),
    user_id   uuid NOT NULL REFERENCES app_user(id),
    role_id   uuid NOT NULL REFERENCES role(id),
    granted_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, role_id)
);
CREATE INDEX ix_user_role_role ON user_role(tenant_id, role_id);

ALTER TABLE user_role ENABLE ROW LEVEL SECURITY;
ALTER TABLE user_role FORCE ROW LEVEL SECURITY;
CREATE POLICY user_role_isolation ON user_role
    USING (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);

CREATE TABLE ace (
    id           uuid PRIMARY KEY,
    tenant_id    uuid NOT NULL REFERENCES tenant(id),
    object_type  text NOT NULL CHECK (object_type IN ('space','node')),
    object_id    uuid NOT NULL,
    subject_type text NOT NULL CHECK (subject_type IN ('user','dept','role','group','external','anonymous')),
    subject_id   uuid,
    allow_bits   bigint NOT NULL DEFAULT 0,
    deny_bits    bigint NOT NULL DEFAULT 0,
    conditions   jsonb NOT NULL DEFAULT '[]',
    preset       text,
    expires_at   timestamptz,
    granted_by   uuid,
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now()
);

-- 同一对象上同一主体只有一条 ACE：改权限是 UPDATE 而不是堆叠多行，
-- 否则"多行取并集"会让撤销变得不可靠。
CREATE UNIQUE INDEX uq_ace_object_subject ON ace (
    tenant_id, object_type, object_id, subject_type,
    COALESCE(subject_id, '00000000-0000-0000-0000-000000000000'::uuid)
);
CREATE INDEX ix_ace_lookup ON ace(tenant_id, object_type, object_id);
CREATE INDEX ix_ace_subject ON ace(tenant_id, subject_type, subject_id);

ALTER TABLE ace ENABLE ROW LEVEL SECURITY;
ALTER TABLE ace FORCE ROW LEVEL SECURITY;
CREATE POLICY ace_isolation ON ace
    USING (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON ace, user_role TO docvault_app;
