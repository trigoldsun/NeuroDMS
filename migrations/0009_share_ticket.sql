-- 两段式票据 + 分享策略增强（M1-6a）
--
-- 为什么必须两段：
--   链接 token 是长期凭证（默认 7 天），它出现在地址栏、聊天记录、浏览器历史、Referer 里。
--   如果字节流也用它，一次下载就会把长期凭证泄漏到日志与第三方统计里。
--   因此：token 只换一张 5 分钟票据，票据只用于取字节。
--
-- 票据是有状态的（存库）：撤销分享时要能立刻让已发出的票据全部失效，
-- 无状态票据做不到这一点，只能等过期——这正好是"可收回"主张的薄弱处。

ALTER TABLE share
    -- 来源 IP 白名单：空数组表示不限制；非空时必须是其中之一
    ADD COLUMN ip_allowlist cidr[] NOT NULL DEFAULT '{}',
    -- 外发审批：开启后链接在审批通过前不可用
    ADD COLUMN require_approval boolean NOT NULL DEFAULT false,
    ADD COLUMN approval_status  text NOT NULL DEFAULT 'not_required'
        CHECK (approval_status IN ('not_required','pending','approved','rejected')),
    ADD COLUMN approved_by     uuid,
    ADD COLUMN approved_at     timestamptz;

CREATE INDEX ix_share_pending_approval ON share(tenant_id, approval_status)
    WHERE approval_status = 'pending';

CREATE TABLE share_ticket (
    id          uuid PRIMARY KEY,
    tenant_id   uuid NOT NULL REFERENCES tenant(id),
    share_id    uuid NOT NULL REFERENCES share(id) ON DELETE CASCADE,
    -- 只存摘要：库被读走也无法直接使用票据
    ticket_hash bytea NOT NULL,
    -- 绑定的来源网段（/24 或 /64）：防票据被复制到别的网络使用
    ip_prefix   cidr,
    expires_at  timestamptz NOT NULL,
    revoked_at  timestamptz,
    created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX uq_ticket_hash ON share_ticket(ticket_hash);
CREATE INDEX ix_ticket_share ON share_ticket(share_id, expires_at DESC);
CREATE INDEX ix_ticket_expiry ON share_ticket(expires_at) WHERE revoked_at IS NULL;

ALTER TABLE share_ticket ENABLE ROW LEVEL SECURITY;
ALTER TABLE share_ticket FORCE ROW LEVEL SECURITY;
CREATE POLICY share_ticket_isolation ON share_ticket
    USING (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON share_ticket TO docvault_app;
