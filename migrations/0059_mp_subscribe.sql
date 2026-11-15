-- 0059_mp_subscribe.sql
--
-- 小程序「审批提醒」（微信订阅消息）。
--
-- 为什么需要落库，而不是"有授权就发"：
--   微信的订阅消息是**一次性**的——用户每点一次授权，服务端才可以发一条。
--   不记账就会出现"用户只授权一次、系统连发十条"，微信侧直接报 43101
--   （用户拒绝/未授权），而且我们无从知道该不该再发。
--
-- 两列分开存的两条理由：
--   1. openid 只与"这个账号绑没绑微信"有关，与模板无关；
--   2. remaining 按模板计数（企业可以给不同审批场景配不同模板）。
-- 把两者合一张表会让"换模板"变成"重新绑微信"。
--
-- 存量行为不变：新表为空，所有账号 mp_openid 为 NULL，等于功能默认关闭。
-- 未配置 DOCVAULT_WX_* 时服务层直接 Enabled()=false，连查询都不会发生。

BEGIN;

-- 微信 openid：登录后由客户端 wx.login 换 code，服务端用 appsecret 换 openid。
-- 只存 openid，不存 session_key —— 后者能解密用户数据，本项目用不到，
-- 存了只是给泄漏多一个后果。
ALTER TABLE app_user ADD COLUMN IF NOT EXISTS mp_openid    text;
ALTER TABLE app_user ADD COLUMN IF NOT EXISTS mp_openid_at timestamptz;

COMMENT ON COLUMN app_user.mp_openid IS '微信小程序 openid（订阅消息收件人）；NULL 表示未绑定';

CREATE TABLE IF NOT EXISTS mp_subscription (
    tenant_id   uuid        NOT NULL REFERENCES tenant(id) ON DELETE CASCADE,
    user_id     uuid        NOT NULL REFERENCES app_user(id) ON DELETE CASCADE,
    template_id text        NOT NULL,
    -- 一次性订阅的"余额"：用户授权几次就能发几条，发一条减一
    remaining   int         NOT NULL DEFAULT 0 CHECK (remaining >= 0),
    updated_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, user_id, template_id)
);

COMMENT ON TABLE mp_subscription IS '小程序订阅消息授权余额（一次性订阅，按模板计数）';

ALTER TABLE mp_subscription ENABLE ROW LEVEL SECURITY;
ALTER TABLE mp_subscription FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS mp_subscription_isolation ON mp_subscription;
CREATE POLICY mp_subscription_isolation ON mp_subscription
    USING (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = nullif(current_setting('app.tenant_id', true), '')::uuid);

COMMIT;
