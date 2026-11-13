-- 安全分享（M1-5）
--
-- 关键设计：链接 token 只用于"换取短期票据"，字节流只认票据。
-- 一次性链接靠单条原子 UPDATE 保证并发下只有一个请求能消费成功，
-- 而不是"先查 used_count 再更新"（那样两个并发请求都会通过）。

CREATE TABLE share (
    id               uuid PRIMARY KEY,
    tenant_id        uuid NOT NULL REFERENCES tenant(id),
    object_type      text NOT NULL CHECK (object_type IN ('node','space')),
    object_id        uuid NOT NULL,
    creator_id       uuid NOT NULL REFERENCES app_user(id),
    kind             text NOT NULL DEFAULT 'link' CHECK (kind IN ('internal','link')),

    -- 仅 link 类型有 token：只存 SHA-256，明文只在创建响应中出现一次
    token_hash       bytea,
    token_hint       text,
    password_hash    text,

    max_uses         int CHECK (max_uses IS NULL OR max_uses > 0),
    used_count       int NOT NULL DEFAULT 0 CHECK (used_count >= 0),
    first_used_at    timestamptz,
    expires_at       timestamptz,
    expire_mode      text CHECK (expire_mode IN ('absolute','relative','after_first_open')),

    allow_download   boolean NOT NULL DEFAULT false,
    watermark        boolean NOT NULL DEFAULT true,
    require_verify   boolean NOT NULL DEFAULT false,
    access_scope     text NOT NULL DEFAULT 'public' CHECK (access_scope IN ('public','whitelist')),

    -- 创建时的策略快照：后续改策略不追溯已发出的链接
    policy_snapshot  jsonb NOT NULL DEFAULT '{}',
    revoked_at       timestamptz,
    revoked_by       uuid,
    created_at       timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX uq_share_token ON share(token_hash) WHERE token_hash IS NOT NULL;
CREATE INDEX ix_share_object ON share(tenant_id, object_type, object_id);
CREATE INDEX ix_share_expiry ON share(expires_at) WHERE revoked_at IS NULL;

ALTER TABLE share ENABLE ROW LEVEL SECURITY;
ALTER TABLE share FORCE ROW LEVEL SECURITY;
CREATE POLICY share_isolation ON share
    USING (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);

-- 访问流水：消费与访问分开记录，便于区分"链接被打开"和"文件被下载"
CREATE TABLE share_visit (
    id         uuid PRIMARY KEY,
    tenant_id  uuid NOT NULL REFERENCES tenant(id),
    share_id   uuid NOT NULL REFERENCES share(id),
    action     text NOT NULL CHECK (action IN ('open','redeem','preview','download','denied')),
    result     text NOT NULL,
    ip         inet,
    user_agent text,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ix_visit_share ON share_visit(share_id, created_at DESC);

ALTER TABLE share_visit ENABLE ROW LEVEL SECURITY;
ALTER TABLE share_visit FORCE ROW LEVEL SECURITY;
CREATE POLICY share_visit_isolation ON share_visit
    USING (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON share, share_visit TO docvault_app;
