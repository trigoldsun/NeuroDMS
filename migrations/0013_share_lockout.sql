-- 分享口令的错误计数与锁定。
--
-- 为什么必须落库而不是放内存：
--   1. 多实例部署时，内存计数等于给攻击者 N 倍尝试次数；
--   2. 进程重启会让计数清零，爆破成本骤降。
--
-- 锁定策略：连续 6 次口令错误 → 锁 30 分钟。
-- 注意"输错不消耗使用次数"仍然成立（used_count 只在成功兑换时 +1），
-- 否则一次性链接输错一次就废了，这是可用性事故而非安全收益。
ALTER TABLE share
    ADD COLUMN IF NOT EXISTS failed_attempts int NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS locked_until    timestamptz;

COMMENT ON COLUMN share.failed_attempts IS '连续口令错误次数，成功后清零';
COMMENT ON COLUMN share.locked_until IS '口令锁定截止时间；NULL 表示未锁定';
