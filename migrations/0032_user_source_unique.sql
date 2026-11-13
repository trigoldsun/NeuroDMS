-- 允许同一租户下"本地账号"与"域账号"同名共存
--
-- 背景：原唯一键是 (tenant_id, lower(username))，一个租户里
-- "zhangsan" 只能存在一个。而现实中非常常见：
--   - 管理员先用本地账号建了自己的号，后来接了 AD；
--   - 域里叫 zhangsan 的人，与本地的 zhangsan 是同一个人，也可能是两个人。
-- 旧约束下，域同步遇到同名只能整条跳过（见 0031），于是这个人**永远无法用域身份登录**；
-- 这不是"边界情况"，几乎每个先本地后接域的组织都会撞上。
--
-- 改为 (tenant_id, source, lower(username))：
--   - 同一来源内仍然唯一（本地不能重名、域内也不能重名）；
--   - 不同来源可以同名，登录时由用户显式选择用哪种身份，不再互相挤占。
--
-- 注意：唯一性只在 source 维度拆开，租户内隔离不变；RLS 策略不受影响。

DROP INDEX IF EXISTS uq_user_tenant_username;

CREATE UNIQUE INDEX IF NOT EXISTS uq_user_tenant_source_username
    ON app_user (tenant_id, source, lower(username))
    WHERE deleted_at IS NULL;

-- 登录既可能按"指定来源"精确查找，也可能按"不限来源"（自动）查找，
-- 两种情况都以 (tenant_id, lower(username)) 为前缀，补一个非唯一索引兜住自动模式。
CREATE INDEX IF NOT EXISTS ix_user_tenant_username
    ON app_user (tenant_id, lower(username))
    WHERE deleted_at IS NULL;

COMMENT ON INDEX uq_user_tenant_source_username IS
    '同租户同来源内用户名唯一；本地与域可同名（登录时由用户选择身份）';
