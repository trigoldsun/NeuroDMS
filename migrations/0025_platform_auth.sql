-- 平台运营账号（M3-6）
--
-- 为什么单开一套账号，而不是给 app_user 加个 is_platform 标记：
--   1) app_user 受 RLS 保护，平台账号天然不属于任何租户，塞进去会让
--      tenant_id 变成"可以填任意值或空"的字段，隔离模型的例外从此扩散；
--   2) 平台账号一旦泄露，影响面是全体租户。它必须是独立表、独立口令策略、
--      独立会话，且能在不改租户数据的前提下整体吊销。
--
-- 令牌用不透明随机串（不签 JWT）：
--   平台会话数量极少，查一次库的成本可以忽略；换来的是"能立刻吊销"。
--   JWT 的无状态在这里只有坏处——停用一个平台账号不该等令牌过期。

CREATE TABLE IF NOT EXISTS platform_user (
    id            uuid PRIMARY KEY,
    email         text NOT NULL,
    display_name  text NOT NULL DEFAULT '',
    password_hash text NOT NULL,
    -- ops：可执行变更；readonly：只能看（合规/支持人员常用）
    role          text NOT NULL DEFAULT 'ops' CHECK (role IN ('ops', 'readonly')),
    status        text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended')),
    created_at    timestamptz NOT NULL DEFAULT now(),
    last_login_at timestamptz,
    CONSTRAINT platform_user_email_chk CHECK (email = lower(email) AND position('@' in email) > 1)
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_platform_user_email ON platform_user (email);

CREATE TABLE IF NOT EXISTS platform_session (
    id         uuid PRIMARY KEY,
    user_id    uuid NOT NULL REFERENCES platform_user(id) ON DELETE CASCADE,
    -- 只存摘要：库被读走也不能拿去登录
    token_hash bytea NOT NULL,
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    revoked_at timestamptz,
    ip         text NOT NULL DEFAULT '',
    user_agent text NOT NULL DEFAULT ''
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_platform_session_hash ON platform_session (token_hash);
CREATE INDEX IF NOT EXISTS idx_platform_session_user ON platform_session (user_id);

-- 平台审计：跨租户操作单独成表，与租户审计链分离（PRD-TEN-12）。
--
-- 为什么不写进租户审计：平台操作常常发生在"还没确定是哪个租户"的时候
-- （例如开通、列表），强行塞进某个租户的链里会让链的语义变脏。
CREATE TABLE IF NOT EXISTS platform_audit (
    id         bigserial PRIMARY KEY,
    actor      text NOT NULL,
    action     text NOT NULL,
    target     text NOT NULL DEFAULT '',
    result     text NOT NULL DEFAULT 'ok',
    detail     jsonb NOT NULL DEFAULT '{}'::jsonb,
    ip         text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_platform_audit_time ON platform_audit (created_at DESC);

-- 平台操作与租户数据一样重要：只追加，不给应用角色改删权限
GRANT SELECT, INSERT ON platform_audit TO docvault_app;
GRANT USAGE, SELECT ON SEQUENCE platform_audit_id_seq TO docvault_app;

-- 平台账号与会话只允许应用角色通过受控路径访问。
-- 注意：这两张表没有 tenant_id，因此不参与 RLS 自检；
-- 它们的隔离靠"没有任何租户上下文能读到"——应用代码里只有 platformauth 包会碰。
GRANT SELECT, INSERT, UPDATE, DELETE ON platform_user, platform_session TO docvault_app;
