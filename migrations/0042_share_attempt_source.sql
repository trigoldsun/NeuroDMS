-- 分享口令锁定：按（链接 × 来源网段）计数
--
-- 现状缺陷：失败次数记在 share.failed_attempts 上，是"每条链接一份"，
-- 不区分来源。后果很直接——**任何人拿到链接，输错 6 次就能把这条链接锁 30 分钟，
-- 不需要知道口令**。对"发给客户的交付链接"，这是一次零成本的拒绝服务。
--
-- 改成按来源网段计数（与票据 IP 绑定同一套 /24、/64 归一化），
-- 单个来源的爆破仍然被拦住，但攻击者锁不住别人的链接。
--
-- share.failed_attempts 保留，降级为**全局兜底**：阈值抬高（60），
-- 只用于拦住"换 IP 分布式爆破"这种单来源计数看不出来的情况。
CREATE TABLE IF NOT EXISTS share_attempt (
    tenant_id       uuid NOT NULL REFERENCES tenant(id),
    share_id        uuid NOT NULL REFERENCES share(id) ON DELETE CASCADE,
    -- 与 share_ticket.ip_prefix 同一套归一化：IPv4 /24、IPv6 /64
    ip_prefix       cidr NOT NULL,
    failed_attempts int NOT NULL DEFAULT 0,
    locked_until    timestamptz,
    updated_at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (share_id, ip_prefix)
);

-- 清理用：按时间扫过期行（与上传会话清理同一批任务执行）
CREATE INDEX IF NOT EXISTS ix_share_attempt_updated ON share_attempt(updated_at);

ALTER TABLE share_attempt ENABLE ROW LEVEL SECURITY;
ALTER TABLE share_attempt FORCE ROW LEVEL SECURITY;
CREATE POLICY share_attempt_isolation ON share_attempt
    USING (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);
