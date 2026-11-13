-- 保留期清理：受限删除函数（审计表仍是 append-only）
--
-- 背景：审计表对应用角色只授了 INSERT/SELECT（见 0011 的 REVOKE），
-- 这是刻意的防篡改设计——应用进程即便被攻破，也删不掉历史日志。
-- 但保留期到期需要真的删除明细，所以清理必须走一个**受限**通道。
--
-- 这里用 SECURITY DEFINER 函数而不是给 docvault_app 授予 DELETE：
--   * 删除上限由函数自己推导（保留期夹在 30..3650 天，且只删已被日结锚点
--     覆盖的前缀），调用方只能传"租户 + 保留天数"，无法指定删到哪一条；
--   * 函数在调用方事务内执行，业务侧回滚时删除也一起回滚。
--
-- 删掉的是明细，不是证据：每一天仍留有 audit_anchor（Merkle 根 + 链头 + 签名），
-- 因此"那段时间存在过且当时未被改写"依然可证。

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
    -- 0 / 脏值 → 2 年；越界夹到 30..3650
    v_days := greatest(30, least(3650, coalesce(nullif(p_retention_days, 0), 730)));
    v_cutoff := (now() AT TIME ZONE 'UTC')::date - v_days;

    -- 只删"整天都早于保留期"的锚点所覆盖的前缀。
    -- 没有锚点覆盖时一律不删：宁可多占磁盘，也不制造无法解释的空白。
    SELECT max(a.seq_to) INTO v_through
      FROM audit_anchor a
     WHERE a.tenant_id = p_tenant AND a.day < v_cutoff;

    IF v_through IS NULL THEN
        RETURN QUERY SELECT 0::bigint, 0::bigint;
        RETURN;
    END IF;

    DELETE FROM audit_event e
     WHERE e.tenant_id = p_tenant AND e.seq <= v_through;
    GET DIAGNOSTICS v_deleted = ROW_COUNT;

    RETURN QUERY SELECT v_deleted, v_through;
END;
$$;

REVOKE ALL ON FUNCTION audit_purge(uuid, int) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION audit_purge(uuid, int) TO docvault_app;
