-- 继承断点与继承快照（M2-A）
--
-- 背景：node.inherit_broken 从 M1 起就在表里，但判定从未读它——
-- 也就是"界面上能点断开继承，实际什么也没发生"。这类"字段有、语义无"
-- 的假功能比没做更危险：审计会误判为已受控。
--
-- 本迁移只补两块必需的结构，判定语义在 internal/ace 里实现：
--
-- 1) origin 标记：区分"直接授予"与"从祖先复制而来的快照"。
--    断开继承时必须把祖先 ACE 复制一份到本对象，否则对象会瞬间失去全部访问；
--    但复制出来的条目**不允许单独删除**，只能通过"恢复继承"整体移除。
--    这是防止"断开继承 = 绕过上层 deny"提权路径的关键约束。
--
-- 2) origin_object_id：记录快照来源，让解释接口能说清"这条权限是跟着谁来的"。

ALTER TABLE ace
    ADD COLUMN IF NOT EXISTS origin text NOT NULL DEFAULT 'direct',
    ADD COLUMN IF NOT EXISTS origin_object_type text,
    ADD COLUMN IF NOT EXISTS origin_object_id uuid;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'ace_origin_check'
    ) THEN
        ALTER TABLE ace ADD CONSTRAINT ace_origin_check
            CHECK (origin IN ('direct', 'inherited'));
    END IF;
END $$;

-- 恢复继承时按 (对象, origin) 批量清理
CREATE INDEX IF NOT EXISTS ix_ace_origin ON ace(tenant_id, object_type, object_id, origin)
    WHERE origin = 'inherited';

COMMENT ON COLUMN ace.origin IS 'direct=直接授予；inherited=断开继承时从祖先复制的快照，只能随恢复继承整体移除';
