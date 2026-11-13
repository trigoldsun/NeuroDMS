-- 0034_version_retention.sql
--
-- 版本保留清理的前置条件（docs/20 §4、docs/21 §6）。
--
-- 背景：blob.ref_count 之前只有应用层 +1，从来没有 -1。
-- 只要开始"删旧版本"，计数就必须由数据库维护，否则每删一次版本，
-- 引用数就与实际差一次，将来做 blob GC 时会把仍在使用的文件删掉。
--
-- 本迁移做两件事：
--   1. 按 version 表全量重算一次 ref_count（把历史偏差清零）；
--   2. 由 version 的 INSERT/DELETE 触发器维护增量。
--
-- 注意：应用层的两处 +1（putBlob 的 ON CONFLICT、分片秒传的 UPDATE）
-- 必须在同一发版中删除，否则会与触发器叠加成双倍计数。

BEGIN;

-- ---------- 1. 全量重算 ----------

UPDATE blob b
   SET ref_count = (SELECT count(*) FROM version v WHERE v.blob_id = b.id);

-- ---------- 2. 触发器维护 ----------

CREATE OR REPLACE FUNCTION version_blob_refcount()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        UPDATE blob SET ref_count = ref_count + 1 WHERE id = NEW.blob_id;
    ELSIF TG_OP = 'DELETE' THEN
        -- GREATEST 兜底：历史数据或人工修数可能让计数已经偏小，
        -- 减到负数会让后续判断（=0 可回收）永远不成立。
        UPDATE blob SET ref_count = GREATEST(ref_count - 1, 0) WHERE id = OLD.blob_id;
    END IF;
    RETURN NULL;
END $$;

DROP TRIGGER IF EXISTS trg_version_refcount ON version;
CREATE TRIGGER trg_version_refcount
    AFTER INSERT OR DELETE ON version
    FOR EACH ROW EXECUTE FUNCTION version_blob_refcount();

COMMIT;
