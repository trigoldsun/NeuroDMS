-- 0039：清理过期上传会话
--
-- 背景：断点续传的复用时窗是 24 小时（应用层 resumeWindow），
-- 超过之后这些会话永远不会再被复用，但分片文件仍占着磁盘。
-- 上传中途关页面、切网、放弃重传都会留下这种"孤儿会话"，
-- 没有人会主动回来删它们——只能靠定时清理。
--
-- 分成 SQL + Go 两步：SQL 删行（跨租户，SECURITY DEFINER），
-- Go 拿返回的 id 删磁盘目录。不在 SQL 里碰文件系统——数据库函数删本地文件
-- 会让"换一台数据库"或"用托管 PG"直接失效。

BEGIN;

CREATE OR REPLACE FUNCTION platform_prune_upload_sessions(p_older interval)
RETURNS TABLE (sid uuid, tid uuid)
LANGUAGE sql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
    WITH del AS (
        DELETE FROM upload_session
         WHERE status = 'open'
           AND updated_at < now() - p_older
        RETURNING id, tenant_id
    )
    SELECT id, tenant_id FROM del;
$$;

REVOKE ALL ON FUNCTION platform_prune_upload_sessions(interval) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION platform_prune_upload_sessions(interval) TO docvault_app;

COMMENT ON FUNCTION platform_prune_upload_sessions(interval)
    IS '删除超过指定时长仍未完成的上传会话（upload_part 级联删除）；返回 id 供调用方清理磁盘分片';

-- 清理走 updated_at（每次写分片都会更新），比 created_at 准确：
-- 一个传了一整天的大文件不该因为"创建得早"被清掉。
CREATE INDEX IF NOT EXISTS ix_upload_session_stale
    ON upload_session (updated_at)
    WHERE status = 'open';

COMMIT;
