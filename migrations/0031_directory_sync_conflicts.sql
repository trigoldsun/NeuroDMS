-- 记录"同名冲突"
--
-- 现场真实情况：租户里已有同名本地账号（常见于管理员自己先用本地账号建过号）。
-- 早先的实现直接让 INSERT 失败，导致整次同步回滚——一个人同名，全员都进不来。
-- 现在改为跳过并计数，但**必须让管理员看见**：
-- 否则只会发现"目录里 52 个人，系统里 51 个"，不知道少的是谁、为什么少。

ALTER TABLE directory_sync
    ADD COLUMN conflicts int NOT NULL DEFAULT 0,
    ADD COLUMN conflict_users text[] NOT NULL DEFAULT '{}';

COMMENT ON COLUMN directory_sync.conflicts IS '与本地同名账号冲突、被跳过的数量';
COMMENT ON COLUMN directory_sync.conflict_users IS '冲突账号名样本（最多 10 个）';
