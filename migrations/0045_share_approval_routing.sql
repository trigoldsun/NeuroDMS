-- 外发审批：指定审批人 + 高密级双层审批
--
-- 背景：原先审批权是"对象上有 manage_acl 且非发起人"即可，任何人都能批，
-- 但没有指派关系。结果有两个问题：
--   1) 发起人不知道会由谁批，只能等；
--   2) 高密级（5/6 级）外发时，若审批人不是空间所有者，
--      空间所有者实际上被绕过了。
--
-- 本迁移只加"指派关系"与"分层状态"，不改动既有 pending 记录的语义：
-- approver_id 为空的旧记录仍然按"任何合格审批人"处理（stage=first）。

ALTER TABLE share
    -- 第一层：发起人指定的审批人
    ADD COLUMN approver_id       uuid REFERENCES app_user(id),
    -- 第二层：5/6 级外发时，若第一层审批人不是空间所有者，指定的所有者
    ADD COLUMN owner_approver_id uuid REFERENCES app_user(id),
    ADD COLUMN approval_stage    text NOT NULL DEFAULT 'none'
        CHECK (approval_stage IN ('none', 'first', 'owner', 'done')),
    ADD COLUMN first_approved_by uuid REFERENCES app_user(id),
    ADD COLUMN first_approved_at timestamptz,
    ADD COLUMN owner_approved_by uuid REFERENCES app_user(id),
    ADD COLUMN owner_approved_at timestamptz;

-- 存量 pending 记录统一视为第一层：它们没有指派审批人，
-- 由现有的 manage_acl 判定决定谁能批。
UPDATE share
   SET approval_stage = 'first'
 WHERE approval_status = 'pending'
   AND approval_stage = 'none';

CREATE INDEX ix_share_pending_approver
    ON share(tenant_id, approver_id)
 WHERE approval_status = 'pending' AND approver_id IS NOT NULL;

CREATE INDEX ix_share_pending_owner_approver
    ON share(tenant_id, owner_approver_id)
 WHERE approval_status = 'pending' AND owner_approver_id IS NOT NULL;
