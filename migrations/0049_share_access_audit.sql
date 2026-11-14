-- 外发访问留痕的补全：打印事件 + 隐私政策链接
--
-- 背景：外部访客的「打开 / 预览 / 下载」早已写入 share_visit 与审计链，
-- 但有三处缺口——
--   1. 打印没有事件（前端动作，服务端收不到）；
--   2. share_visit 没有任何读取接口，分享人看不到"我的链接被谁看过"；
--   3. 邮件里没有隐私说明，而 IP 属于个人信息，采集必须告知。
--
-- 本迁移只做数据结构与读取所需的索引；接口与界面随后上线。

-- ---------- 1. 允许记录 print ----------
DO $$
DECLARE
    cname text;
BEGIN
    SELECT conname INTO cname
      FROM pg_constraint
     WHERE conrelid = 'share_visit'::regclass
       AND contype = 'c'
       AND pg_get_constraintdef(oid) LIKE '%action%';
    IF cname IS NOT NULL THEN
        EXECUTE format('ALTER TABLE share_visit DROP CONSTRAINT %I', cname);
    END IF;

    ALTER TABLE share_visit
        ADD CONSTRAINT share_visit_action_check
        CHECK (action IN ('open', 'redeem', 'preview', 'download', 'denied', 'print'));
END $$;

-- 分享人查看"我这条链接最近被访问过什么"：按分享 + 时间倒序取一页
CREATE INDEX IF NOT EXISTS ix_visit_share_recent ON share_visit(share_id, created_at DESC);
-- 列表页要按创建者过滤并统计，避免全表扫
CREATE INDEX IF NOT EXISTS ix_share_creator ON share(tenant_id, creator_id, created_at DESC);

-- ---------- 2. 隐私政策链接（品牌的一部分，公开可读） ----------
--
-- 放在 tenant_config 而不是邮件配置：它同时要出现在分享页与登录页，
-- 是"对外的法律文本入口"，与发件邮箱无关。
ALTER TABLE tenant_config
    ADD COLUMN IF NOT EXISTS privacy_url text NOT NULL DEFAULT '';

-- 返回列只在末尾追加（旧镜像回滚时新列会被忽略，不会炸）
DROP FUNCTION IF EXISTS public_branding(text);
CREATE FUNCTION public_branding(p_slug text)
RETURNS TABLE (
    slug          text,
    name          text,
    status        text,
    product_name  text,
    primary_color text,
    accent_color  text,
    logo          bytea,
    logo_mime     text,
    footer_text   text,
    updated_at    timestamptz,
    privacy_url   text
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
BEGIN
    RETURN QUERY
    SELECT t.slug, t.name, t.status,
           COALESCE(c.product_name, '文档中心'),
           COALESCE(c.primary_color, '#12724a'),
           COALESCE(c.accent_color, '#0b5fa5'),
           c.logo, COALESCE(c.logo_mime, ''),
           COALESCE(c.footer_text, ''),
           COALESCE(c.updated_at, t.created_at),
           COALESCE(c.privacy_url, '')
      FROM tenant t
      LEFT JOIN tenant_config c ON c.tenant_id = t.id
     WHERE t.slug = p_slug AND t.deleted_at IS NULL;
END $$;

REVOKE ALL ON FUNCTION public_branding(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public_branding(text) TO docvault_app;

COMMENT ON COLUMN tenant_config.privacy_url IS
    '隐私政策链接；为空时用平台默认页。外发邮件正文底部与分享页会引用它';
