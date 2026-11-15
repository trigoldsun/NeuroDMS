-- 0055_sms_log_provider.sql
--
-- 给短信发送日志补上"走了哪家通道"（代码审查 docs/50 B-01）。
--
-- 为什么重要：租户可以自带厂商账号，也可以随时切换。
-- 只有时间/结果时，"这条短信为什么没收到"只能靠猜；
-- 有了 provider，支持人员能直接回答"当时走的是腾讯云还是阿里云"。
--
-- 存量行填 ''（未知），不编造一个默认通道：历史短信可能来自平台通道，
-- 也可能来自当时的租户配置，事后无法还原。

BEGIN;

ALTER TABLE sms_send_log ADD COLUMN IF NOT EXISTS provider text NOT NULL DEFAULT '';

COMMENT ON COLUMN sms_send_log.provider IS '发送时使用的通道编码（aliyun/tencent/huawei/ctyun/mock）；空表示历史数据';

COMMIT;
