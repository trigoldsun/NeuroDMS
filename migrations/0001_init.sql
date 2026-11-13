-- DocVault 初始结构（M1-2）
--
-- 设计要点：
--  1. 所有业务表带 tenant_id，并启用行级安全（RLS）；这是"双层隔离"的第二层。
--  2. 应用运行时以 SET ROLE docvault_app 执行，该角色非超级用户、无 BYPASSRLS，
--     因此 RLS 对应用真正生效（超级用户会绕过 RLS，不能用来做应用连接）。
--  3. current_setting('app.tenant_id', true) 在未设置时返回 NULL，
--     比较结果为 NULL → 不匹配任何行 → 天然 fail-closed（忘记设置上下文等于看不到数据）。

CREATE EXTENSION IF NOT EXISTS ltree;

-- ---------- 租户 ----------

CREATE TABLE tenant (
    id          uuid PRIMARY KEY,
    slug        text NOT NULL UNIQUE,
    name        text NOT NULL,
    status      text NOT NULL DEFAULT 'active' CHECK (status IN ('active','suspended','deleted')),
    created_at  timestamptz NOT NULL DEFAULT now(),
    deleted_at  timestamptz
);

ALTER TABLE tenant ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant FORCE ROW LEVEL SECURITY;

-- 租户表用 id 自身做隔离：只能看到当前上下文的这一行
CREATE POLICY tenant_isolation ON tenant
    USING (id = nullif(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (id = nullif(current_setting('app.tenant_id', true), '')::uuid);

-- ---------- 部门（组织树） ----------

CREATE TABLE dept (
    id          uuid PRIMARY KEY,
    tenant_id   uuid NOT NULL REFERENCES tenant(id),
    parent_id   uuid REFERENCES dept(id),
    path        ltree NOT NULL,
    name        text NOT NULL,
    ldap_dn     text,
    sort        int NOT NULL DEFAULT 0,
    created_at  timestamptz NOT NULL DEFAULT now(),
    deleted_at  timestamptz
);

CREATE INDEX ix_dept_path ON dept USING gist(path);
CREATE UNIQUE INDEX uq_dept_tenant_path ON dept(tenant_id, path) WHERE deleted_at IS NULL;

ALTER TABLE dept ENABLE ROW LEVEL SECURITY;
ALTER TABLE dept FORCE ROW LEVEL SECURITY;

CREATE POLICY dept_isolation ON dept
    USING (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);

-- ---------- 角色 ----------

CREATE TABLE role (
    id          uuid PRIMARY KEY,
    tenant_id   uuid NOT NULL REFERENCES tenant(id),
    code        text NOT NULL,
    name        text NOT NULL,
    is_system   boolean NOT NULL DEFAULT false,
    data_scope  text NOT NULL DEFAULT 'self' CHECK (data_scope IN ('self','dept','dept_sub','custom','all')),
    perms       text[] NOT NULL DEFAULT '{}',
    created_at  timestamptz NOT NULL DEFAULT now(),
    deleted_at  timestamptz
);

CREATE UNIQUE INDEX uq_role_tenant_code ON role(tenant_id, code) WHERE deleted_at IS NULL;

ALTER TABLE role ENABLE ROW LEVEL SECURITY;
ALTER TABLE role FORCE ROW LEVEL SECURITY;

CREATE POLICY role_isolation ON role
    USING (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);

-- ---------- 用户 ----------

CREATE TABLE app_user (
    id                 uuid PRIMARY KEY,
    tenant_id          uuid NOT NULL REFERENCES tenant(id),
    principal_type     text NOT NULL DEFAULT 'internal' CHECK (principal_type IN ('internal','external','system')),
    source             text NOT NULL DEFAULT 'local' CHECK (source IN ('local','ldap','oidc','invite')),
    username           text NOT NULL,
    email              text,
    display_name       text NOT NULL,
    password_hash      text,
    dept_id            uuid REFERENCES dept(id),
    classification     smallint NOT NULL DEFAULT 0 CHECK (classification BETWEEN 0 AND 6),
    ceiling            smallint NOT NULL DEFAULT 4 CHECK (ceiling BETWEEN 0 AND 6),
    mfa_required       boolean NOT NULL DEFAULT false,
    status             text NOT NULL DEFAULT 'active' CHECK (status IN ('invited','active','suspended','deleted')),
    session_epoch      int NOT NULL DEFAULT 1,
    last_login_at      timestamptz,
    expires_at         timestamptz,
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now(),
    deleted_at         timestamptz
);

CREATE UNIQUE INDEX uq_user_tenant_username ON app_user(tenant_id, lower(username)) WHERE deleted_at IS NULL;
CREATE UNIQUE INDEX uq_user_tenant_email ON app_user(tenant_id, lower(email)) WHERE deleted_at IS NULL AND email IS NOT NULL;
CREATE INDEX ix_user_dept ON app_user(tenant_id, dept_id) WHERE deleted_at IS NULL;

ALTER TABLE app_user ENABLE ROW LEVEL SECURITY;
ALTER TABLE app_user FORCE ROW LEVEL SECURITY;

CREATE POLICY app_user_isolation ON app_user
    USING (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);

-- ---------- 应用角色 ----------
-- 非超级用户、非表所有者、无 BYPASSRLS：RLS 对它真实生效。
-- 运行时通过 SET LOCAL ROLE docvault_app 切换，迁移仍由超级用户执行。

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'docvault_app') THEN
        CREATE ROLE docvault_app NOLOGIN NOSUPERUSER NOBYPASSRLS;
    END IF;
END
$$;

GRANT USAGE ON SCHEMA public TO docvault_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO docvault_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO docvault_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO docvault_app;
