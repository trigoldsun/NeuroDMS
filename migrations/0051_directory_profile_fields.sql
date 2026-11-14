-- 认证源自动登记：职位、直线上级，以及手机号的来源标记。
--
-- 背景：这些字段本来就存在于域控/Entra 里（title / manager / mobile），
-- 之前只同步了邮箱与部门，导致"域账号进来了，但手机号还得管理员一个个手填"。
-- 手机号在小程序登录里是凭据，手填错一位就等于把账号交给号码的主人，
-- 因此权威来源应当是认证源本身。

-- 职位（AD: title，Entra: jobTitle）
ALTER TABLE app_user ADD COLUMN IF NOT EXISTS title text;

-- 直线上级：指向同租户的另一个 app_user。
--
-- 为什么存本地 id 而不是目录里的 DN：
-- 展示与"按上级筛选"都要落到人能点的对象上；DN 在账号改名/挪 OU 后会变，
-- 存 DN 会让这条关系在某次同步后突然断掉。
--
-- 这里只加外键，不加"同租户"约束（FK 表达不了复合条件）——
-- 同租户由同步代码保证：解析 manager 时只在同一 tenant 内查 external_id。
ALTER TABLE app_user ADD COLUMN IF NOT EXISTS manager_id uuid;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'fk_user_manager'
  ) THEN
    ALTER TABLE app_user
      ADD CONSTRAINT fk_user_manager
      FOREIGN KEY (manager_id) REFERENCES app_user(id) ON DELETE SET NULL;
  END IF;
END $$;

-- 手机号来源：manual（管理员手填）/ self（本人在账号页绑定）/ directory（认证源同步）。
--
-- 这一列不是为了好看：不同来源的可信度不同，排障时要能回答
-- "这个号码是用户自己填的，还是域控里本来就有的"。
-- 目录来源的号码视为已验证（组织背书），其余来源必须走一次验证码。
ALTER TABLE app_user ADD COLUMN IF NOT EXISTS phone_source text;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'ck_user_phone_source'
  ) THEN
    ALTER TABLE app_user
      ADD CONSTRAINT ck_user_phone_source
      CHECK (phone_source IS NULL OR phone_source IN ('manual', 'self', 'directory'));
  END IF;
END $$;

-- 存量数据：此前只有"管理员录入/自助绑定"两条路径，统一记为 manual。
UPDATE app_user SET phone_source = 'manual'
 WHERE phone IS NOT NULL AND phone <> '' AND phone_source IS NULL;

-- 号码形态兜底（0050 已加过；重复执行时跳过，方便本迁移单独重跑）
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'ck_user_phone_e164') THEN
    ALTER TABLE app_user ADD CONSTRAINT ck_user_phone_e164
      CHECK (phone IS NULL OR phone ~ '^\+86[1-9][0-9]{10}$');
  END IF;
END $$;

-- "我的下属"是成员页与审批链会用到的查询，按 (租户, 上级) 建索引。
CREATE INDEX IF NOT EXISTS ix_user_manager
  ON app_user(tenant_id, manager_id)
  WHERE manager_id IS NOT NULL AND deleted_at IS NULL;

-- 同步运行记录增加"直线上级已解析数"。
--
-- 不加这一列的话，"为什么上级这一栏是空的"只能靠猜：
-- 上级账号被 excludeAccounts 排除、或不在同一批次里，都会导致解析失败，
-- 而这些都发生在同一次运行内部，事后无从回溯。
ALTER TABLE directory_sync ADD COLUMN IF NOT EXISTS managers_linked integer NOT NULL DEFAULT 0;
