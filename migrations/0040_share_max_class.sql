-- 外链的密级上界（MAC 在外发通道上的落点）
--
-- 背景：密级门（sub.Class < obj.Class → 拒绝）只在**站内**判定。
-- 外链访客没有账号、没有密级，于是"空间级外链"可以把空间里任何密级的文件
-- 交给匿名访问者——包括发起人自己也看不到的那些。这与
-- "ACL 全开也不能突破密级"的设计前提冲突。
--
-- 做法：创建分享时把发起人的密级冻结成 max_class，取内容时校验
-- node.classification <= max_class。用快照而不是实时查发起人：
-- 发起人后来被降级时，已发出的链接必须跟着收紧（而不是继续按旧权限放行，
-- 也不是按"当前密级"悄悄放宽）。
ALTER TABLE share
    ADD COLUMN IF NOT EXISTS max_class smallint NOT NULL DEFAULT 0;

-- 存量回填：按发起人当前密级取上界。
-- 已经是 0（默认值）且发起人密级为 0 的行不受影响。
UPDATE share s
   SET max_class = COALESCE((SELECT u.classification FROM app_user u WHERE u.id = s.creator_id), 0)
 WHERE s.max_class = 0;

-- 取值域护栏：密级只允许 0..6，与 app_user.classification 保持一致。
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'share_max_class_range'
    ) THEN
        ALTER TABLE share
            ADD CONSTRAINT share_max_class_range CHECK (max_class BETWEEN 0 AND 6);
    END IF;
END $$;
