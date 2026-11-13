SET docvault.allow_audit_delete = 'on';

DO $$
DECLARE
    t     text;
    junk  uuid[];
BEGIN
    SELECT array_agg(id) INTO junk FROM tenant WHERE slug LIKE 't-%' OR slug LIKE 'http-%' OR slug LIKE 'other-%' OR slug LIKE 'm3-%';
    IF junk IS NULL THEN
        RAISE NOTICE '没有需要清理的测试租户';
        RETURN;
    END IF;

    -- 只删存在的表：迁移前后表集合不同，硬写表名会让清理脚本自己失败
    FOREACH t IN ARRAY ARRAY[
        'share_visit','share_ticket','share_verify','share',
        'upload_part','upload_session','classification_change','node_label','label_policy',
        'ace','version','blob','node','space','classification_label',
        'session','user_role','role','group_member','user_group',
        'otp_code','notification','directory_sync',
        'usage_event','usage_daily','tenant_domain','tenant_feature',
        'tenant_quota','tenant_usage','tenant_config',
        'audit_anchor','audit_event'
    ] LOOP
        IF to_regclass(t) IS NOT NULL THEN
            EXECUTE format('DELETE FROM %I WHERE tenant_id = ANY($1)', t) USING junk;
        END IF;
    END LOOP;

    DELETE FROM app_user WHERE tenant_id = ANY(junk);
    DELETE FROM dept WHERE tenant_id = ANY(junk);
    DELETE FROM tenant WHERE id = ANY(junk);
END $$;

SELECT count(*) AS tenants_left FROM tenant;
