-- 0037：断点续传
--
-- 现状（0018）：分片上传的表和接口都有，但**续不上**——
--   1. 每次 POST /v1/uploads 都新建会话，已收分片成了孤儿；
--   2. 没有查询"哪些分片已收到"的接口；
--   3. 前端也不记 uploadId，刷新后无从恢复。
-- 于是"断点续传"只有分片的外形，没有续传的语义：网络断了就得从第一片重传。
--
-- 本迁移补两件事：
--   · part_size 固化到会话上。分片边界是会话的属性，不是客户端当下的选择：
--     前端把分片大小从 8MB 调成 5MB 后，旧会话的 part 1 是 8MB、新的是 5MB，
--     接着传就会拼出一份错位的内容——而且要到 complete 校验哈希时才报错，
--     中间白传几十片。存下来，复用时强制使用会话既有的边界。
--   · 复用查询的索引。按 (owner, sha256, size) 找未完成会话，命中即续传。

BEGIN;

ALTER TABLE upload_session
    ADD COLUMN IF NOT EXISTS part_size bigint NOT NULL DEFAULT 2097152;

-- 下界 1MB：再小就是拿分片当请求洪水；上界 64MB：再大就把"单片失败重传"的代价做没了
ALTER TABLE upload_session
    DROP CONSTRAINT IF EXISTS upload_session_part_size_chk;
ALTER TABLE upload_session
    ADD CONSTRAINT upload_session_part_size_chk CHECK (part_size BETWEEN 1048576 AND 67108864);

COMMENT ON COLUMN upload_session.part_size IS
    '分片边界（字节）。会话创建时固化，续传必须沿用；客户端改分片大小不改变已开会话';

-- 复用查询：同一用户、同一内容、同一声明大小的未完成会话
CREATE INDEX IF NOT EXISTS ix_upload_session_resume
    ON upload_session (tenant_id, created_by, declared_sha256, declared_size, space_id)
    WHERE status = 'open' AND declared_sha256 IS NOT NULL;

-- 已收分片按会话取号，续传时前端要这个列表
CREATE INDEX IF NOT EXISTS ix_upload_part_session
    ON upload_part (session_id, part_no);

COMMIT;
