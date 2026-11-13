-- 清理函数必须显式打开审计表的删除开关
--
-- 0028 建的函数调用后 deleted 恒为 0：audit_event 上有一条重写规则
--   audit_event_no_delete: ON DELETE ... DO INSTEAD NOTHING
-- 除非会话内 docvault.allow_audit_delete='on'，否则 DELETE 被静默改写为"什么也不做"。
-- 这道防线本身是对的（应用角色连 DELETE 权限都没有，双保险），
-- 但保留期清理是唯一需要合法删除的路径，必须在这里显式开门。
--
-- 用 set_config(..., true)（事务级局部设置）：
--   * 作用域只到本事务结束，不会影响同连接后续的业务事务；
--   * 与删除在同一事务，函数返回后设置即失效。
-- 该 GUC 只在此 SECURITY DEFINER 函数里设置；应用角色没有 DELETE 权限，
-- 即使自己 set 了这个值也删不掉任何行。

CREATE OR REPLACE FUNCTION audit_purge(p_tenant uuid, p_retention_days int)
RETURNS TABLE(deleted bigint, through_seq bigint)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v_days    int;
    v_cutoff  date;
    v_through bigint;
    v_deleted bigint;
BEGIN
    v_days := greatest(30, least(3650, coalesce(nullif(p_retention_days, 0), 730)));
    v_cutoff := (now() AT TIME ZONE 'UTC')::date - v_days;

    SELECT max(a.seq_to) INTO v_through
      FROM audit_anchor a
     WHERE a.tenant_id = p_tenant AND a.day < v_cutoff;

    IF v_through IS NULL THEN
        RETURN QUERY SELECT 0::bigint, 0::bigint;
        RETURN;
    END IF;

    -- 仅本事务内放开删除（见文件头说明）
    PERFORM set_config('docvault.allow_audit_delete', 'on', true);

    DELETE FROM audit_event e
     WHERE e.tenant_id = p_tenant AND e.seq <= v_through;
    GET DIAGNOSTICS v_deleted = ROW_COUNT;

    PERFORM set_config('docvault.allow_audit_delete', 'off', true);

    RETURN QUERY SELECT v_deleted, v_through;
END;
$$;

REVOKE ALL ON FUNCTION audit_purge(uuid, int) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION audit_purge(uuid, int) TO docvault_app;
