-- 清理解锁后过期很久的口令尝试记录
--
-- share_attempt 的每一行是（链接 × 来源网段），只在"口令输错"时产生。
-- 量不大，但没有上限：一条长期有效的外链被爬虫反复试探，行数会一直涨。
-- 锁定过期后这些行就只剩统计价值，留 30 天足够排查，之后删掉。
--
-- 为什么用 SECURITY DEFINER：要跨租户清理，应用角色受 RLS 限制只能看自己租户。
-- 与 platform_prune_upload_sessions 同一套模式，且不碰文件系统。
BEGIN;

CREATE OR REPLACE FUNCTION platform_prune_share_attempts(p_older interval)
RETURNS bigint
LANGUAGE sql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
    WITH del AS (
        DELETE FROM share_attempt
         WHERE updated_at < now() - p_older
           -- 仍在锁定中的行不能删：删了等于把锁定提前解除
           AND (locked_until IS NULL OR locked_until < now())
        RETURNING 1
    )
    SELECT count(*) FROM del;
$$;

REVOKE ALL ON FUNCTION platform_prune_share_attempts(interval) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION platform_prune_share_attempts(interval) TO docvault_app;

COMMENT ON FUNCTION platform_prune_share_attempts(interval)
    IS '删除超过指定时长且已解锁的分享口令尝试记录；返回删除行数';
