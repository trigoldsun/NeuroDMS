-- 0057_license.sql
--
-- 本地部署版许可证（docs/47 §4.5）。
--
-- 三张"单行表"而不是配置文件：
--   app_instance —— 实例指纹。许可证绑定它，防止一份许可证复制到十台机器。
--   instance_license —— 许可证原文与验签结果。放库里才能跟着 pg_dump 一起备份，
--                       也不会因为"容器里 /data 被清掉"而突然变成未授权。
--
-- 为什么不存"是否已开通"这种结论：结论会随着密钥轮换、时钟变化而失效。
-- 只存原文，每次启动重新验签 —— 验签是纯计算，比维护一份状态便宜。

BEGIN;

CREATE TABLE IF NOT EXISTS app_instance (
    id          smallint PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    instance_id uuid NOT NULL DEFAULT gen_random_uuid(),
    created_at  timestamptz NOT NULL DEFAULT now()
);

INSERT INTO app_instance (id) VALUES (1) ON CONFLICT (id) DO NOTHING;

COMMENT ON TABLE app_instance IS '实例指纹（单行）：许可证绑定此值';

CREATE TABLE IF NOT EXISTS instance_license (
    id           smallint PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    -- blob 是 "base64url(payload).base64url(sig)"，原样保存。
    -- 只存解析后的字段会让"重新验签"变成"重新拼装"，一旦拼错就再也验不过。
    blob         text NOT NULL,
    license_id   text NOT NULL DEFAULT '',
    customer     text NOT NULL DEFAULT '',
    edition      text NOT NULL DEFAULT '',
    capabilities jsonb NOT NULL DEFAULT '[]'::jsonb,
    seats        integer NOT NULL DEFAULT 0,
    expires_at   timestamptz,
    instance_id  text NOT NULL DEFAULT '',
    applied_at   timestamptz NOT NULL DEFAULT now(),
    applied_by   text NOT NULL DEFAULT ''
);

COMMENT ON TABLE instance_license IS '本地版许可证（单行）：原文 + 解析后的摘要';

COMMIT;
