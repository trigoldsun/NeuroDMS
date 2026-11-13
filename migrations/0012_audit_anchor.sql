-- 审计日结锚点（M1-8c）
--
-- 为什么需要锚点：哈希链只能证明"第 N 条与第 N-1 条衔接"，
-- 如果攻击者把整条链连同链头一起重写，链本身是自洽的，校验会通过。
-- 日结锚点把"某一天结束时链长什么样"固定下来并签名，
-- 事后重写历史就必须同时伪造锚点（且签名密钥不在库里）。
CREATE TABLE audit_anchor (
    id          uuid PRIMARY KEY,
    tenant_id   uuid NOT NULL REFERENCES tenant(id),
    -- 结算日期（UTC）
    day         date NOT NULL,
    seq_from    bigint NOT NULL,
    seq_to      bigint NOT NULL,
    event_count int NOT NULL,
    -- 当日所有事件哈希的 Merkle 根：可对单条事件做存在性证明
    merkle_root bytea NOT NULL,
    -- 当日最后一条事件的链哈希
    chain_head  bytea NOT NULL,
    -- 对 (tenant, day, seq_from, seq_to, count, merkle_root, chain_head) 的 HMAC
    signature   bytea NOT NULL,
    algorithm   text NOT NULL DEFAULT 'hmac-sha256',
    created_at  timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, day)
);
CREATE INDEX ix_anchor_tenant_day ON audit_anchor(tenant_id, day DESC);

ALTER TABLE audit_anchor ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_anchor FORCE ROW LEVEL SECURITY;
CREATE POLICY audit_anchor_isolation ON audit_anchor
    USING (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);

GRANT SELECT, INSERT ON audit_anchor TO docvault_app;
