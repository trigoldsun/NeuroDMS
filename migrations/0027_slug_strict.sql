-- 收紧 slug 规则：不允许以连字符结尾（M3-1 修订）
--
-- 为什么要单独一个迁移：0021 里的 CHECK 是宽松版 `^[a-z0-9][a-z0-9-]{1,40}$`，
-- 它接受 "acme-"。数据库与 Go 校验必须**同一套规则**，否则会出现
-- "接口拒绝了、但直接写库能过"这种两边不一致的状态——
-- 那种不一致会在数据迁移和域名绑定时才暴露。
--
-- 格式：2-40 位，小写字母/数字/连字符，首尾必须是字母或数字。

ALTER TABLE tenant DROP CONSTRAINT IF EXISTS tenant_slug_chk;
ALTER TABLE tenant ADD CONSTRAINT tenant_slug_chk
    CHECK (slug ~ '^[a-z0-9][a-z0-9-]{0,38}[a-z0-9]$');
