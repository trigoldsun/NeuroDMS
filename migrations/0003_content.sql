-- 内容模型（M1-4）
--
-- 三层结构：
--   node（逻辑对象：目录/文件，带权限与标签）
--     └─ version（内容快照：版本号、大小、摘要、状态）
--          └─ blob（内容寻址：同一份内容全局只存一次）
--
-- 这样做的收益：多版本、跨目录副本、多租户重复上传都只占一份存储；
-- 回收站只是标记，版本回滚只是换指针。

CREATE TABLE space (
    id             uuid PRIMARY KEY,
    tenant_id      uuid NOT NULL REFERENCES tenant(id),
    kind           text NOT NULL CHECK (kind IN ('personal','dept','project','knowledge','archive')),
    name           text NOT NULL,
    owner_id       uuid NOT NULL REFERENCES app_user(id),
    dept_id        uuid REFERENCES dept(id),
    default_preset text NOT NULL DEFAULT 'viewer',
    classification smallint NOT NULL DEFAULT 0 CHECK (classification BETWEEN 0 AND 6),
    quota_bytes    bigint,
    used_bytes     bigint NOT NULL DEFAULT 0,
    inherit_broken boolean NOT NULL DEFAULT false,
    created_at     timestamptz NOT NULL DEFAULT now(),
    deleted_at     timestamptz
);
CREATE INDEX ix_space_owner ON space(tenant_id, owner_id) WHERE deleted_at IS NULL;

ALTER TABLE space ENABLE ROW LEVEL SECURITY;
ALTER TABLE space FORCE ROW LEVEL SECURITY;
CREATE POLICY space_isolation ON space
    USING (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);

CREATE TABLE blob (
    id              uuid PRIMARY KEY,
    tenant_id       uuid NOT NULL REFERENCES tenant(id),
    size_bytes      bigint NOT NULL CHECK (size_bytes >= 0),
    sha256          bytea NOT NULL,
    storage_backend text NOT NULL DEFAULT 'local',
    storage_key     text NOT NULL,
    ref_count       int NOT NULL DEFAULT 0,
    created_at      timestamptz NOT NULL DEFAULT now(),
    -- 内容寻址：同租户内同内容只存一次
    UNIQUE (tenant_id, sha256, size_bytes)
);

ALTER TABLE blob ENABLE ROW LEVEL SECURITY;
ALTER TABLE blob FORCE ROW LEVEL SECURITY;
CREATE POLICY blob_isolation ON blob
    USING (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);

CREATE TABLE node (
    id                  uuid PRIMARY KEY,
    tenant_id           uuid NOT NULL REFERENCES tenant(id),
    space_id            uuid NOT NULL REFERENCES space(id),
    parent_id           uuid REFERENCES node(id),
    kind                text NOT NULL CHECK (kind IN ('folder','file')),
    name                text NOT NULL CHECK (length(name) BETWEEN 1 AND 255),
    depth               int NOT NULL DEFAULT 0,
    size_bytes          bigint NOT NULL DEFAULT 0,
    mime                text,
    ext                 text,
    classification      smallint NOT NULL DEFAULT 0 CHECK (classification BETWEEN 0 AND 6),
    owner_id            uuid NOT NULL REFERENCES app_user(id),
    current_version_id  uuid,
    effective_version_id uuid,
    inherit_broken      boolean NOT NULL DEFAULT false,
    locked              boolean NOT NULL DEFAULT false,
    deleted_at          timestamptz,
    created_at          timestamptz NOT NULL DEFAULT now(),
    updated_at          timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ix_node_parent ON node(tenant_id, space_id, parent_id) WHERE deleted_at IS NULL;
CREATE INDEX ix_node_owner ON node(tenant_id, owner_id) WHERE deleted_at IS NULL;
-- 同一目录下不重名（文件与目录分开约束，避免"文件夹与同名文件冲突"）
CREATE UNIQUE INDEX uq_node_sibling_folder ON node(space_id, parent_id, lower(name))
    WHERE deleted_at IS NULL AND kind = 'folder';
CREATE UNIQUE INDEX uq_node_sibling_file ON node(space_id, parent_id, lower(name))
    WHERE deleted_at IS NULL AND kind = 'file';

ALTER TABLE node ENABLE ROW LEVEL SECURITY;
ALTER TABLE node FORCE ROW LEVEL SECURITY;
CREATE POLICY node_isolation ON node
    USING (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);

CREATE TABLE version (
    id          uuid PRIMARY KEY,
    tenant_id   uuid NOT NULL REFERENCES tenant(id),
    node_id     uuid NOT NULL REFERENCES node(id),
    version_no  int NOT NULL CHECK (version_no > 0),
    blob_id     uuid NOT NULL REFERENCES blob(id),
    size_bytes  bigint NOT NULL,
    sha256      bytea NOT NULL,
    state       text NOT NULL DEFAULT 'draft'
                CHECK (state IN ('draft','reviewing','effective','superseded','void')),
    created_by  uuid NOT NULL REFERENCES app_user(id),
    note        text,
    created_at  timestamptz NOT NULL DEFAULT now(),
    -- 并发安全的根基：版本号唯一，冲突时由数据库而不是应用来裁决
    UNIQUE (node_id, version_no)
);
CREATE INDEX ix_version_node ON version(node_id, version_no DESC);

ALTER TABLE version ENABLE ROW LEVEL SECURITY;
ALTER TABLE version FORCE ROW LEVEL SECURITY;
CREATE POLICY version_isolation ON version
    USING (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON space, node, version, blob TO docvault_app;
