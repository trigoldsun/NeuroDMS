-- 通知外发（M1-7c）
--
-- 为什么用 outbox 而不是"请求里直接发信"：
--   1. SMTP/Graph 是外部依赖，超时会把用户请求拖死；
--   2. 发信失败必须能重试，而 HTTP 请求生命周期内没有重试的机会；
--   3. "用户点了发送但没发出"这种事必须可查、可补发。
-- 代价是"提交成功但还没发出"的窗口，因此状态机必须显式（pending/sending/sent/failed/dead）。

CREATE TABLE notification (
    id            uuid PRIMARY KEY,
    tenant_id     uuid NOT NULL REFERENCES tenant(id),
    channel       text NOT NULL CHECK (channel IN ('smtp','graph')),
    to_addr       text NOT NULL,
    subject       text NOT NULL,
    body_text     text NOT NULL,
    body_html     text,

    -- 业务关联：便于"这封邀请函是哪个分享发的"这类追问
    purpose       text NOT NULL DEFAULT 'generic',
    ref_id        uuid,

    status        text NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending','sending','sent','failed','dead')),
    attempts      int NOT NULL DEFAULT 0,
    last_error    text,
    next_attempt_at timestamptz NOT NULL DEFAULT now(),
    sent_at       timestamptz,
    created_at    timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ix_notification_due ON notification(next_attempt_at)
    WHERE status IN ('pending','failed');
CREATE INDEX ix_notification_tenant ON notification(tenant_id, created_at DESC);

ALTER TABLE notification ENABLE ROW LEVEL SECURITY;
ALTER TABLE notification FORCE ROW LEVEL SECURITY;
CREATE POLICY notification_isolation ON notification
    USING (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON notification TO docvault_app;

-- 一次性验证码（外用户双因子 / 邮件验证）
--
-- 只存摘要：库被读走也无法用来通过验证。
-- consumed_at 非空即视为已用，配合 check 时的原子 UPDATE 保证"一码一次"。
CREATE TABLE otp_code (
    id          uuid PRIMARY KEY,
    tenant_id   uuid NOT NULL REFERENCES tenant(id),
    subject     text NOT NULL,          -- 邮箱或手机号（归一化后）
    purpose     text NOT NULL,          -- 如 share_verify / login_2fa
    code_hash   bytea NOT NULL,
    expires_at  timestamptz NOT NULL,
    attempts    int NOT NULL DEFAULT 0,
    consumed_at timestamptz,
    created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ix_otp_lookup ON otp_code(tenant_id, subject, purpose, created_at DESC);

ALTER TABLE otp_code ENABLE ROW LEVEL SECURITY;
ALTER TABLE otp_code FORCE ROW LEVEL SECURITY;
CREATE POLICY otp_isolation ON otp_code
    USING (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON otp_code TO docvault_app;
