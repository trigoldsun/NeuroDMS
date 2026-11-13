-- 认证与会话（M1-3）
--
-- 设计要点：
--  1. 口令只存 Argon2id 的编码串，不存明文、不可逆。
--  2. 刷新令牌只存 SHA-256 摘要：库被读走也无法直接冒用。
--  3. 刷新令牌单次使用 + 旋转：旧令牌用掉即失效，被窃取后一旦被真实用户使用就会暴露。
--  4. 会话带 epoch：改密/停用把 app_user.session_epoch 自增，旧令牌在校验时即被判废。
--  5. 登录失败计数与锁定放在用户行上，避免"分布式计数不准"。

ALTER TABLE app_user ADD COLUMN failed_attempts int NOT NULL DEFAULT 0;
ALTER TABLE app_user ADD COLUMN locked_until timestamptz;

CREATE TABLE session (
    id             uuid PRIMARY KEY,
    tenant_id      uuid NOT NULL REFERENCES tenant(id),
    user_id        uuid NOT NULL REFERENCES app_user(id),
    refresh_hash   bytea NOT NULL,
    epoch          int NOT NULL,
    user_agent     text,
    ip             inet,
    created_at     timestamptz NOT NULL DEFAULT now(),
    last_seen_at   timestamptz NOT NULL DEFAULT now(),
    expires_at     timestamptz NOT NULL,
    revoked_at     timestamptz
);

-- 同一租户同一用户可多设备；刷新令牌摘要全局唯一，避免碰撞导致误判
CREATE UNIQUE INDEX uq_session_refresh ON session(refresh_hash);
CREATE INDEX ix_session_user ON session(tenant_id, user_id) WHERE revoked_at IS NULL;
CREATE INDEX ix_session_expiry ON session(expires_at);

ALTER TABLE session ENABLE ROW LEVEL SECURITY;
ALTER TABLE session FORCE ROW LEVEL SECURITY;

CREATE POLICY session_isolation ON session
    USING (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON session TO docvault_app;
