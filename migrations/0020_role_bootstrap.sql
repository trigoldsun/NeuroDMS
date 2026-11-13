-- 为存量租户补齐系统角色与初始管理员（M2 修正）
--
-- 背景：rbac.Bootstrap 只在"创建演示租户"时被调用，早于 M2 就存在的租户
-- 不会有任何 user_role 记录，表现为"管理台一律 403 需要管理角色"——
-- 功能做完了却进不去，是升级路径上最容易被漏掉的一类问题。
--
-- 本迁移是幂等的：
--   * 角色行按 (tenant_id, code) 补齐，已存在则跳过；
--   * 仅在租户**完全没有** sysadmin 时，把最早创建的用户补为 sysadmin。
--     已经有管理员的租户不会被动到（避免意外提权）。

DO $$
DECLARE
    t   record;
    uid uuid;
BEGIN
    INSERT INTO role (id, tenant_id, code, name, is_system, data_scope, perms)
    SELECT gen_random_uuid(), tt.id, r.code, r.name, true, 'all', '{}'
      FROM tenant tt
      CROSS JOIN (VALUES
            ('sysadmin', '系统管理员'),
            ('secadmin',  '安全管理员'),
            ('auditor',   '审计管理员')
      ) AS r(code, name)
    ON CONFLICT (tenant_id, code) WHERE deleted_at IS NULL DO NOTHING;

    FOR t IN SELECT id FROM tenant WHERE deleted_at IS NULL LOOP
        IF NOT EXISTS (
            SELECT 1 FROM user_role ur
              JOIN role ro ON ro.id = ur.role_id
             WHERE ro.tenant_id = t.id AND ro.code = 'sysadmin' AND ro.deleted_at IS NULL
        ) THEN
            SELECT u.id INTO uid
              FROM app_user u
             WHERE u.tenant_id = t.id AND u.deleted_at IS NULL
             ORDER BY u.created_at, u.id
             LIMIT 1;

            IF uid IS NOT NULL THEN
                INSERT INTO user_role (tenant_id, user_id, role_id)
                SELECT t.id, uid, ro.id
                  FROM role ro
                 WHERE ro.tenant_id = t.id AND ro.code = 'sysadmin'
                ON CONFLICT (user_id, role_id) DO NOTHING;
            END IF;
        END IF;
        uid := NULL;
    END LOOP;
END $$;
