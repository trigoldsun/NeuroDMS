-- 分享的邮箱验证与白名单（M2 / AC-50、AC-51）
--
-- 背景：share.access_scope 与 require_verify 从 M1 起就在表里，但**没有实现**：
-- require_verify 只被写进策略快照，兑换时从未校验——属于"看起来有、实际不存在"的
-- 安全开关。本迁移补上它需要的结构化状态。
--
-- 设计取舍：验证态用"表"而不是"签名凭证"。
-- 签名凭证无状态、更轻，但它无法回答"谁在什么时候验证了哪个链接"
-- （这正是泄露事件里最需要的那条线索）。多一张表换来可审计，值得。

ALTER TABLE share ADD COLUMN IF NOT EXISTS email_whitelist text[] NOT NULL DEFAULT '{}';

COMMENT ON COLUMN share.email_whitelist IS
    '允许申请的邮箱或域名（@example.com 形式）；空表示不限';

CREATE TABLE IF NOT EXISTS share_verify (
    id          uuid PRIMARY KEY,
    tenant_id   uuid NOT NULL REFERENCES tenant(id),
    share_id    uuid NOT NULL REFERENCES share(id),
    email       text NOT NULL,
    verified_at timestamptz NOT NULL DEFAULT now(),
    -- 验证通过后只允许在短时间内兑换，避免"验证一次、链接长期被人代打开"
    expires_at  timestamptz NOT NULL,
    consumed_at timestamptz,
    ip          inet
);
CREATE INDEX IF NOT EXISTS ix_share_verify_lookup
    ON share_verify(share_id, lower(email)) WHERE consumed_at IS NULL;

ALTER TABLE share_verify ENABLE ROW LEVEL SECURITY;
ALTER TABLE share_verify FORCE ROW LEVEL SECURITY;
CREATE POLICY share_verify_isolation ON share_verify
    USING (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);

GRANT SELECT, INSERT, UPDATE, DELETE ON share_verify TO docvault_app;
