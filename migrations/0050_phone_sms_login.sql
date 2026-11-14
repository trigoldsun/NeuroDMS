-- 手机号与短信验证码登录（docs/41、docs/42）
--
-- 只加列/加表，不改既有约束：旧镜像回滚后仍可运行（新列被忽略）。
-- 短信通道凭据本期走环境变量（DOCVAULT_SMS_*），租户自助配置留到下一迭代，
-- 因此这里不建 sms_config，避免出现"表在但没人写"的半成品。

ALTER TABLE app_user ADD COLUMN IF NOT EXISTS phone text;
ALTER TABLE app_user ADD COLUMN IF NOT EXISTS phone_verified_at timestamptz;

-- 形态约束：只接受规范化的 +86 大陆号码。
-- 应用层也会规范化，这里是最后一道——脏数据一旦进库，
-- 唯一索引与按号登录都会变得不可信。
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'ck_user_phone_e164') THEN
    ALTER TABLE app_user ADD CONSTRAINT ck_user_phone_e164
      CHECK (phone IS NULL OR phone ~ '^\+86[1-9][0-9]{10}$');
  END IF;
END $$;

-- 租户内唯一：同一号码在同一租户只能属于一个账号。
-- 唯一索引同时承担"按号找账号"的查询。
CREATE UNIQUE INDEX IF NOT EXISTS uq_user_tenant_phone
  ON app_user(tenant_id, phone)
  WHERE deleted_at IS NULL AND phone IS NOT NULL;

-- 验证码发送与校验失败日志：频控依据 + 事后取证。
-- 不存明文号码：手机号空间只有 10^10，裸哈希可被彩虹表反查，用 HMAC。
CREATE TABLE IF NOT EXISTS sms_send_log (
    id bigserial PRIMARY KEY,
    tenant_id uuid NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
    phone_hash text NOT NULL,
    ip text,
    -- sent | not_registered | rate_limited | provider_error | verify_failed | verify_ok
    result text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ix_sms_log_phone ON sms_send_log(tenant_id, phone_hash, created_at DESC);
CREATE INDEX IF NOT EXISTS ix_sms_log_ip ON sms_send_log(tenant_id, ip, created_at DESC);
CREATE INDEX IF NOT EXISTS ix_sms_log_created ON sms_send_log(created_at DESC);

-- 频控日志同样受租户隔离约束：虽然目前只有超管连接会读写它，
-- 但"表里有 tenant_id 却不设 RLS"会让自检直接失败，也会在将来
-- 换成非超管连接时变成一个跨租户可读的洞。
ALTER TABLE sms_send_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE sms_send_log FORCE ROW LEVEL SECURITY;
CREATE POLICY sms_send_log_isolation ON sms_send_log
    USING (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);
