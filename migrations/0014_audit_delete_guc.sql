-- 让"审计只追加"从**硬 DDL 开关**变成**会话级开关**。
--
-- 背景：测试清理需要删除测试租户的审计事件，而 audit_event 上的
-- `DO INSTEAD NOTHING` 规则会让 DELETE 静默变成 0 行，随后删租户被外键挡住。
-- 早先的做法是 `ALTER TABLE ... DISABLE RULE`，但那是表级 DDL：
--   1. 需要 ACCESS EXCLUSIVE 锁，多个测试包并行跑时会互相等待甚至超时；
--   2. 一旦超时就静默留下残留租户（库里曾堆到 478 个）。
--
-- 改为规则里读一个会话级 GUC：
--   - 默认（未设置）：仍然完全禁止删除，生产行为不变；
--   - 只有显式 `SET LOCAL docvault.allow_audit_delete = 'on'` 的会话（测试清理）才能删。
--
-- 为什么安全：这个 GUC 只能由数据库账号设置，而业务运行时的角色是 docvault_app，
-- 它对 audit_event 只有 SELECT/INSERT 权限（见 0005），连 DELETE 都发不出去。
DROP RULE IF EXISTS audit_event_no_delete ON audit_event;

CREATE RULE audit_event_no_delete AS
    ON DELETE TO audit_event
    WHERE current_setting('docvault.allow_audit_delete', true) IS DISTINCT FROM 'on'
    DO INSTEAD NOTHING;

COMMENT ON RULE audit_event_no_delete ON audit_event IS
    '审计事件只追加：会话未显式设置 docvault.allow_audit_delete=on 时，DELETE 一律无效';
