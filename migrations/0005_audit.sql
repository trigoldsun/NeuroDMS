-- 审计链（M1-8a）
--
-- 目标不是"记日志"，而是"记到能被第三方验证没被改过"：
--   1. 每条事件带前序哈希，形成按租户的链；
--   2. 应用角色只有 INSERT 与 SELECT，没有 UPDATE/DELETE —— 从权限层断掉篡改可能；
--   3. 再加触发器兜底（即使误授权也会被拦），形成双保险。

CREATE TABLE audit_event (
    id          uuid PRIMARY KEY,
    tenant_id   uuid NOT NULL REFERENCES tenant(id),
    seq         bigint NOT NULL CHECK (seq > 0),
    actor_id    uuid,
    actor_type  text NOT NULL DEFAULT 'user' CHECK (actor_type IN ('user','external','system','anonymous')),
    action      text NOT NULL,
    object_type text,
    object_id   uuid,
    result      text NOT NULL CHECK (result IN ('ok','denied','error')),
    detail      jsonb NOT NULL DEFAULT '{}',
    ip          inet,
    request_id  text,
    prev_hash   bytea,
    hash        bytea NOT NULL,
    created_at  timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, seq)
);
CREATE INDEX ix_audit_tenant_time ON audit_event(tenant_id, created_at DESC);
CREATE INDEX ix_audit_actor ON audit_event(tenant_id, actor_id, created_at DESC);
CREATE INDEX ix_audit_object ON audit_event(tenant_id, object_id, created_at DESC) WHERE object_id IS NOT NULL;

ALTER TABLE audit_event ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_event FORCE ROW LEVEL SECURITY;
CREATE POLICY audit_event_isolation ON audit_event
    USING (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);

-- 只追加：任何 UPDATE/DELETE 一律静默无效（而不是报错，避免影响正常业务路径）
CREATE RULE audit_event_no_update AS ON UPDATE TO audit_event DO INSTEAD NOTHING;
CREATE RULE audit_event_no_delete AS ON DELETE TO audit_event DO INSTEAD NOTHING;

-- 权限层：应用角色只能写和读
REVOKE ALL ON audit_event FROM docvault_app;
GRANT SELECT, INSERT ON audit_event TO docvault_app;

-- 日结锚点：把一天的事件摘要钉住，用于证明"历史未被整体重写"
CREATE TABLE audit_daily_root (
    tenant_id   uuid NOT NULL REFERENCES tenant(id),
    day         date NOT NULL,
    first_seq   bigint NOT NULL,
    last_seq    bigint NOT NULL,
    event_count int NOT NULL,
    root_hash   bytea NOT NULL,
    prev_root   bytea,
    created_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, day)
);

ALTER TABLE audit_daily_root ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_daily_root FORCE ROW LEVEL SECURITY;
CREATE POLICY audit_root_isolation ON audit_daily_root
    USING (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);

REVOKE ALL ON audit_daily_root FROM docvault_app;
GRANT SELECT, INSERT ON audit_daily_root TO docvault_app;
