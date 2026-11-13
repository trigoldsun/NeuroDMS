-- 密级体系（M2-C）
--
-- 现状问题（本迁移要解决的根因）：
--   node.classification 与 space.classification 从 M1 起就存在，
--   authz 引擎也实现了密级门（sub.Class < obj.Class → 拒绝），
--   但 HTTP 路径的 check() 从未把对象密级传进判定——即 Class 恒为 0。
--   结果是"引擎有密级、线上无密级"，比完全没做更危险：审计会认为已受控。
--
-- 本迁移提供密级体系需要的数据结构：
--   1) classification_label  密级显示名（等级与顺序**固定不可改**，只允许改名称）
--   2) node_label            对象标签
--   3) label_policy          标签 → 最低密级（标签只能"收紧"，不能放宽权限）
--   4) classification_change 定密/降密申请与审批
--   5) tenant.share_approval_min_class  达到该密级的分享强制走审批

-- ---------- 1. 密级显示名 ----------
--
-- level 是语义（0 最低），不允许改；可改的只有展示名与说明。
-- 这一条直接对应 AC-40："在线降系统密级"在结构上不可能发生——
-- 因为没有任何接口能把某个 level 的语义调低。
CREATE TABLE IF NOT EXISTS classification_label (
    tenant_id   uuid NOT NULL REFERENCES tenant(id),
    level       smallint NOT NULL CHECK (level BETWEEN 0 AND 6),
    name        text NOT NULL CHECK (length(name) BETWEEN 1 AND 32),
    description text NOT NULL DEFAULT '',
    updated_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, level)
);

ALTER TABLE classification_label ENABLE ROW LEVEL SECURITY;
ALTER TABLE classification_label FORCE ROW LEVEL SECURITY;
CREATE POLICY classification_label_isolation ON classification_label
    USING (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);

-- ---------- 2. 对象标签与标签策略 ----------

CREATE TABLE IF NOT EXISTS node_label (
    tenant_id uuid NOT NULL REFERENCES tenant(id),
    node_id   uuid NOT NULL REFERENCES node(id),
    label     text NOT NULL CHECK (length(label) BETWEEN 1 AND 64),
    PRIMARY KEY (node_id, label)
);
CREATE INDEX IF NOT EXISTS ix_node_label_label ON node_label(tenant_id, label);

ALTER TABLE node_label ENABLE ROW LEVEL SECURITY;
ALTER TABLE node_label FORCE ROW LEVEL SECURITY;
CREATE POLICY node_label_isolation ON node_label
    USING (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);

-- 标签策略只有"最低密级"一个维度。
-- 没有"最低权限位"这类字段是刻意的：标签一旦能给权限，就等于开了第二条授权通道，
-- 而这条通道不经过 ACE、不受封顶约束、不进授权审计（AC-35 要防的正是这个）。
CREATE TABLE IF NOT EXISTS label_policy (
    tenant_id uuid NOT NULL REFERENCES tenant(id),
    label     text NOT NULL CHECK (length(label) BETWEEN 1 AND 64),
    min_level smallint NOT NULL CHECK (min_level BETWEEN 0 AND 6),
    PRIMARY KEY (tenant_id, label)
);

ALTER TABLE label_policy ENABLE ROW LEVEL SECURITY;
ALTER TABLE label_policy FORCE ROW LEVEL SECURITY;
CREATE POLICY label_policy_isolation ON label_policy
    USING (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);

-- ---------- 3. 定密/降密申请 ----------
--
-- 为什么"降密"必须走审批：降密 = 扩大知悉范围。
-- 定密可以自助（不超过本人密级），降密不能——否则任何拿到文件的人
-- 都能把密级调到 0，再分享出去，密级体系形同虚设。
CREATE TABLE IF NOT EXISTS classification_change (
    id            uuid PRIMARY KEY,
    tenant_id     uuid NOT NULL REFERENCES tenant(id),
    node_id       uuid NOT NULL REFERENCES node(id),
    from_level    smallint NOT NULL CHECK (from_level BETWEEN 0 AND 6),
    to_level      smallint NOT NULL CHECK (to_level BETWEEN 0 AND 6),
    reason        text NOT NULL CHECK (length(reason) BETWEEN 4 AND 1000),
    status        text NOT NULL DEFAULT 'pending'
                  CHECK (status IN ('pending','approved','rejected','canceled')),
    requested_by  uuid NOT NULL REFERENCES app_user(id),
    decided_by    uuid REFERENCES app_user(id),
    decided_at    timestamptz,
    decision_note text,
    created_at    timestamptz NOT NULL DEFAULT now(),
    -- 同一对象同时只允许一条待审申请，避免重复审批把密级来回改
    CONSTRAINT uq_class_change_pending EXCLUDE USING btree (node_id WITH =)
        WHERE (status = 'pending')
);

CREATE INDEX IF NOT EXISTS ix_class_change_node ON classification_change(tenant_id, node_id, created_at DESC);

ALTER TABLE classification_change ENABLE ROW LEVEL SECURITY;
ALTER TABLE classification_change FORCE ROW LEVEL SECURITY;
CREATE POLICY classification_change_isolation ON classification_change
    USING (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);

-- ---------- 4. 分享审批阈值 ----------
--
-- 达到该密级的对象，外发链接一律进 pending（不受创建者角色影响）。
-- 不做"安全管理员可豁免"是有意的：自审自批是审批流程最常见的失效方式。
ALTER TABLE tenant ADD COLUMN IF NOT EXISTS share_approval_min_class smallint NOT NULL DEFAULT 3
    CHECK (share_approval_min_class BETWEEN 0 AND 6);

GRANT SELECT, INSERT, UPDATE, DELETE ON
    classification_label, node_label, label_policy, classification_change TO docvault_app;
