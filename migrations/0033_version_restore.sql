-- 0033_version_restore.sql
--
-- 版本管理与历史回退（docs/21）。
--
-- 这次迁移解决的是一个"接口存在但语义没接上"的问题：
--   node.current_version_id（最新上传）与 node.effective_version_id（设为生效）
--   是两个独立指针，而所有读取路径都按 version_no DESC 取最新，
--   所以"设为生效版"之后，用户下载到的仍然是新版本。
--
-- 本迁移做三件事：
--   1. 给 version 增加来源标记（upload / edit / restore）与回退来源版本号；
--   2. 用触发器把 state 收敛为唯一事实源（新插入的版本即当前版本）；
--   3. 建立编辑会话表，供回退与在线编辑互斥使用。
--
-- 注意：本迁移**不**维护 blob.ref_count。该字段的应用层递增会在存储治理
-- （docs/20 §4）统一改为触发器维护并做一次全量重算，此时若再补一次增量，
-- 重算前后都会重复计数。回退复用已有 blob，不新增内容，不碰它更安全。

BEGIN;

-- ---------- 1. 版本来源 ----------

ALTER TABLE version ADD COLUMN IF NOT EXISTS origin text NOT NULL DEFAULT 'upload';
ALTER TABLE version DROP CONSTRAINT IF EXISTS version_origin_chk;
ALTER TABLE version ADD CONSTRAINT version_origin_chk
    CHECK (origin IN ('upload', 'edit', 'restore'));

-- 回退来源的版本号。只存数字、不设外键：
-- 源版本行会被"保留最近 N 个"清理掉，届时仍需能说出"从第几版恢复"。
ALTER TABLE version ADD COLUMN IF NOT EXISTS restored_from_no int;

COMMENT ON COLUMN version.origin IS '版本来源：upload 上传 / edit 在线编辑保存 / restore 回退';
COMMENT ON COLUMN version.restored_from_no IS '回退来源的版本号；非回退版本为 NULL';

-- ---------- 2. state 收敛为唯一事实源 ----------

-- 新插入的版本即"当前版本"：同节点其余 effective 降为 superseded。
-- 放在 BEFORE INSERT 而不是应用层，是因为版本插入有三条路径
-- （上传、分片秒传、在线编辑保存）外加回退，漏一条就会同时存在两个 effective。
CREATE OR REPLACE FUNCTION version_mark_effective()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
BEGIN
    UPDATE version
       SET state = 'superseded'
     WHERE node_id = NEW.node_id
       AND id <> NEW.id
       AND state = 'effective';
    NEW.state := 'effective';
    RETURN NEW;
END $$;

DROP TRIGGER IF EXISTS trg_version_effective ON version;
CREATE TRIGGER trg_version_effective
    BEFORE INSERT ON version
    FOR EACH ROW EXECUTE FUNCTION version_mark_effective();

-- 存量修正：以 node.current_version_id 为准重建 state。
-- 先降后升，避免中间态出现两个 effective（虽然触发器只对新行生效）。
UPDATE version v
   SET state = 'superseded'
  FROM node n
 WHERE n.id = v.node_id
   AND v.state = 'effective'
   AND v.id IS DISTINCT FROM n.current_version_id;

UPDATE version v
   SET state = 'effective'
  FROM node n
 WHERE n.id = v.node_id
   AND n.current_version_id = v.id
   AND v.state <> 'void';

-- 一个节点最多一个 effective（兜底约束，防止有路径绕过触发器直接 UPDATE）
CREATE UNIQUE INDEX IF NOT EXISTS uq_version_effective
    ON version(node_id) WHERE state = 'effective';

-- ---------- 3. 编辑会话（回退互斥） ----------

-- 用途：判断"是否有人正在 OnlyOffice 里编辑这个文件"。
-- 现有 node.locked 字段从未被写过，属于死字段，不能作为依据。
CREATE TABLE IF NOT EXISTS doc_session (
    -- 两个外键都带 CASCADE：测试夹具按"子表→父表"清理，
    -- 少一个 CASCADE 就会在删 tenant 时被这张表挡住。
    tenant_id    uuid NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
    node_id      uuid NOT NULL REFERENCES node(id) ON DELETE CASCADE,
    session_key  text NOT NULL,
    user_id      uuid REFERENCES app_user(id) ON DELETE SET NULL,
    started_at   timestamptz NOT NULL DEFAULT now(),
    last_seen_at timestamptz NOT NULL DEFAULT now(),
    invalidated_at timestamptz,
    PRIMARY KEY (node_id, session_key)
);

-- 活跃会话查询走这条部分索引；过期由读取时按 last_seen_at 惰性判定，
-- 不依赖后台清理任务（任务停了也不能让回退被永久阻塞）。
CREATE INDEX IF NOT EXISTS ix_doc_session_alive
    ON doc_session(tenant_id, node_id, last_seen_at)
    WHERE invalidated_at IS NULL;

GRANT SELECT, INSERT, UPDATE, DELETE ON doc_session TO docvault_app;

ALTER TABLE doc_session ENABLE ROW LEVEL SECURITY;
ALTER TABLE doc_session FORCE ROW LEVEL SECURITY;
CREATE POLICY doc_session_isolation ON doc_session
    USING (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);

COMMIT;
