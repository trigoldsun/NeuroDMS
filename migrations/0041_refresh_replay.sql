-- 刷新令牌重放检测
--
-- 现状：Refresh 会把旧令牌旋转掉，但**无法区分"旧令牌被重放"与"随手编的垃圾串"**，
-- 两者都只是 ErrSessionInvalid。后果是：攻击者窃取刷新令牌后抢先使用，合法用户
-- 只会看到"登录已过期"，系统没有任何告警、也不吊销那条已被接管的会话——
-- 等于把一次凭证泄露伪装成一次正常过期。
--
-- 做法：记住上一个摘要与旋转时刻。
--   - 用**当前**摘要来刷新 → 正常旋转；
--   - 用**上一个**摘要来刷新且间隔在宽限窗口内 → 判为多标签页/重试并发，不吊销；
--   - 用上一个摘要但已超出窗口 → 判为重放，吊销整条会话并审计。
ALTER TABLE session
    ADD COLUMN IF NOT EXISTS prev_refresh_hash bytea,
    ADD COLUMN IF NOT EXISTS refresh_rotated_at timestamptz;

-- 只索引非空值：绝大多数行是"刚登录、还没刷新过"，不占索引体积。
CREATE INDEX IF NOT EXISTS ix_session_prev_refresh
    ON session(prev_refresh_hash)
    WHERE prev_refresh_hash IS NOT NULL;
