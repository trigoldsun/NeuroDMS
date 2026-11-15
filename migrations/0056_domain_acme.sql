-- 0056_domain_acme.sql
--
-- 域名自助 + ACME 自动签发（docs/47 §4.6）。
--
-- 两个新增点：
--  1. cert_source：这张证书是**客户手工上传**的，还是**本系统自动签发**的。
--     决定两件事——手工证书优先（客户明确上传的意图强于自动续期），
--     以及自动续期只处理 source='acme' 的行（不去动客户自己的证书）。
--  2. acme_*：DNS-01 手动模式是**两阶段**的（先拿到 TXT 记录 → 客户去加 →
--     再回来完成）。中间要跨请求保存订单与授权地址，否则第二次请求就得从头再来，
--     而每次都重新下单会把 Let's Encrypt 的 pending authz 配额吃光。
--
-- 为什么 acme_state 用 '' 而不是 NULL：三态里"没有进行中的签发"是常态，
-- 用空串能让 `acme_state = ''` 这种查询写成普通的等值判断，不必到处 COALESCE。

BEGIN;

ALTER TABLE tenant_domain
    ADD COLUMN IF NOT EXISTS cert_source text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS acme_state text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS acme_order_url text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS acme_auth_url text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS acme_dns_name text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS acme_dns_value text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS acme_started_at timestamptz,
    ADD COLUMN IF NOT EXISTS acme_last_attempt_at timestamptz,
    ADD COLUMN IF NOT EXISTS acme_last_error text NOT NULL DEFAULT '';

-- 取值域用 DO 块加约束：直接 ADD CONSTRAINT 在重复执行时会报错，
-- 而迁移框架允许"已应用则跳过"，两者叠加会让回滚重放变脆。
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'tenant_domain_cert_source_chk'
    ) THEN
        ALTER TABLE tenant_domain
            ADD CONSTRAINT tenant_domain_cert_source_chk
            CHECK (cert_source IN ('', 'manual', 'acme'));
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'tenant_domain_acme_state_chk'
    ) THEN
        ALTER TABLE tenant_domain
            ADD CONSTRAINT tenant_domain_acme_state_chk
            CHECK (acme_state IN ('', 'pending'));
    END IF;
END
$$;

COMMENT ON COLUMN tenant_domain.cert_source IS
    'manual=客户上传（自动续期不碰）；acme=本系统签发；空=没有证书';
COMMENT ON COLUMN tenant_domain.acme_state IS
    'pending=DNS-01 等待客户添加 TXT；空=没有进行中的签发';

-- ACME 账户私钥：必须持久化。
--
-- 为什么不能每次启动新生成：ACME 账户身份就是这把私钥，换一把等于新建一个账户，
-- Let's Encrypt 对"同一 IP 每 3 小时新建账户"有配额（默认 10 个）。
-- 客户重启几次服务就可能把自己锁在配额外，症状是"突然签不出证书"。
--
-- 与租户数据隔离：ACME 账户属于**本实例**，不属于任何租户，所以单独一张表，
-- 且不挂 RLS（它只有一行、只由服务端读写，放 RLS 里反而要额外的 bypass 例外）。
CREATE TABLE IF NOT EXISTS acme_account (
    id            smallint PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    email         text NOT NULL DEFAULT '',
    directory_url text NOT NULL,
    key_enc       bytea NOT NULL,
    kid           text NOT NULL DEFAULT '',
    created_at    timestamptz NOT NULL DEFAULT now(),
    updated_at    timestamptz NOT NULL DEFAULT now()
);

COMMENT ON TABLE acme_account IS 'ACME 账户（单行）：私钥加密保存，directory_url 区分测试/生产';

-- 续期扫描要按"快到期且由我方签发"筛，给个部分索引即可；
-- 全表扫描在租户域名数上百时也不慢，但这个查询每天跑，没必要每次都扫。
CREATE INDEX IF NOT EXISTS idx_tenant_domain_renew
    ON tenant_domain (cert_not_after)
    WHERE cert_source = 'acme' AND verified_at IS NOT NULL;

COMMIT;
