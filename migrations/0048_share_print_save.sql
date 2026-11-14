-- 外发分享的「允许打印 / 允许保存」控制
--
-- 背景（真实缺陷）：只设置了 allow_download=false 的分享，访客打开后仍能下载。
-- 根因不在下载接口（那个已按 allow_download 拦了 403），而在**呈现方式**：
-- PDF 被塞进 <iframe src=...>，浏览器自带的 PDF 阅读器工具栏里就有「下载 / 打印」
-- 两个按钮，等于给了一个绕过开关的正门。
--
-- 因此把"能不能留副本"拆成三个独立的策略位：
--   allow_download  能否取回**原始文件**（原格式，可再编辑）
--   allow_save      能否保存**在线副本**（PDF/图片等呈现件）
--   allow_print     能否打印
--
-- 语义约束：下载原件本身就是保存，因此 allow_save=false 时 allow_download 必须为 false，
-- 否则开关自相矛盾（用 CHECK 约束在库里挡住，不只靠界面）。
--
-- 存量链接的回填：allow_print = allow_save = allow_download。
-- 理由：老链接的历史行为是"只读分享也能通过 PDF 工具栏下载/打印"，
-- 这次修复要把那个口子关掉；回填成 follow allow_download 既关闭了口子，
-- 也不会给"本来就允许下载"的链接新增限制。

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM information_schema.columns
         WHERE table_schema = current_schema()
           AND table_name = 'share'
           AND column_name = 'allow_print'
    ) THEN
        ALTER TABLE share ADD COLUMN allow_print boolean NOT NULL DEFAULT true;
        ALTER TABLE share ADD COLUMN allow_save  boolean NOT NULL DEFAULT true;

        UPDATE share SET allow_print = allow_download, allow_save = allow_download;

        ALTER TABLE share
            ADD CONSTRAINT share_save_implies_no_download
            CHECK (allow_save OR NOT allow_download);
    END IF;
END $$;

COMMENT ON COLUMN share.allow_print IS '访客能否打印（关闭后查看器不提供打印入口，并拦截 Ctrl+P）';
COMMENT ON COLUMN share.allow_save  IS '访客能否保存在线副本（关闭后不提供另存/下载入口；为 false 时 allow_download 必须为 false）';
