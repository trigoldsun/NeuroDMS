-- 平台运营的跨租户只读入口（M2-B / AC-14）
--
-- 背景：tenant 与 audit_event 都启用了 FORCE RLS，应用连接（docvault_app）
-- 在未设置 app.tenant_id 时看不到任何行——这是隔离的基础，不能为了"平台后台"
-- 就整体放开。
--
-- 取舍：跨租户能力必须存在（合规审计、故障排查都需要），但只能以**最小面**存在。
-- 因此这里不用"给应用 BYPASSRLS"，而是提供两个 SECURITY DEFINER 函数：
--   1) platform_resolve_tenant(slug)  —— 只把 slug 换成 id，不返回任何业务字段
--   2) platform_stats()               —— 只返回汇总计数，不返回明细
-- 明细（审计事件）仍然走正常的租户上下文读取，RLS 一直有效。
--
-- 这样即使平台令牌泄露，攻击面也只是"知道有几个租户、每个租户多少文件"，
-- 而不是"直接读走所有租户的审计与文件"。

CREATE OR REPLACE FUNCTION platform_resolve_tenant(p_slug text)
RETURNS uuid
LANGUAGE sql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
    SELECT id FROM tenant
     WHERE slug = p_slug AND status <> 'deleted' AND deleted_at IS NULL
$$;

CREATE OR REPLACE FUNCTION platform_stats()
RETURNS TABLE (
    tenants    bigint,
    users      bigint,
    spaces     bigint,
    files      bigint,
    used_bytes bigint
)
LANGUAGE sql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
    SELECT
      (SELECT count(*) FROM tenant WHERE status <> 'deleted' AND deleted_at IS NULL),
      (SELECT count(*) FROM app_user WHERE deleted_at IS NULL),
      (SELECT count(*) FROM space WHERE deleted_at IS NULL),
      (SELECT count(*) FROM node WHERE deleted_at IS NULL AND kind = 'file'),
      (SELECT COALESCE(sum(size_bytes), 0) FROM node WHERE deleted_at IS NULL AND kind = 'file')
$$;

-- 只授给应用角色；PUBLIC 一律收回（默认 PUBLIC 可执行，必须显式撤销）
REVOKE ALL ON FUNCTION platform_resolve_tenant(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION platform_stats() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION platform_resolve_tenant(text) TO docvault_app;
GRANT EXECUTE ON FUNCTION platform_stats() TO docvault_app;

-- 让"每次平台访问都留痕"可被审计查询命中
COMMENT ON FUNCTION platform_stats() IS '平台运营：跨租户汇总计数（只读，不返回明细）';
