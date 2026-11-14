-- 密级 → 是否需要"空间所有者二次确认"（可配置）
--
-- 背景：原规则是写死的——外发 5/6 级文件时，若第一层审批人不是空间所有者，
-- 还要再加一层所有者确认。这个阈值在代码里是常量 ownerApprovalMinClass = 5。
--
-- 为什么必须变成配置：
--   不同租户的密级体系语义差别很大。有的租户把 4 级当"绝密"用（0-3 全部是日常），
--   有的租户 5 级只是"内部机密"、6 级才是核心。写死 5 的结果是：
--   前者 4 级文件被管理员批给自己人就能外发，后者 5 级外发被卡住却无法解释。
--   安全管理员应当能在密级定义页逐级勾选，而不是等研发改一个常量再发版。
--
-- 缺省值与旧行为完全一致（5、6 级打开），因此升级瞬间线上行为不变。
-- classification_label 是"读时补齐"的（见 internal/classification.Levels），
-- 存量租户大多没有行，所以这里不需要为每个租户插 7 行；
-- Go 侧对缺失行按 DefaultOwnerApprovalFrom（=5）兜底。
--
-- 用 DO 块保证幂等：迁移只会在首次应用时回填，重复执行不会把管理员
-- 后来关掉的开关又打开。

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
         WHERE table_schema = current_schema()
           AND table_name = 'classification_label'
           AND column_name = 'owner_approval'
    ) THEN
        ALTER TABLE classification_label
            ADD COLUMN owner_approval boolean NOT NULL DEFAULT false;

        -- 与旧硬编码规则对齐：5/6 级需要所有者确认
        UPDATE classification_label SET owner_approval = (level >= 5);
    END IF;
END $$;

COMMENT ON COLUMN classification_label.owner_approval IS
    '该密级对外分享时是否需要文件所在空间所有者二次确认（老分享按创建时的指派快照，不受后续修改影响）';
