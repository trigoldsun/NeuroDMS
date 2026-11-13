-- 修正 ceiling 默认值（M1-4 修正）
--
-- 背景：ceiling 的语义是"最多能授出多高的档位"，只作用于授权路径。
-- 默认值 4（编辑者）会导致空间所有者无法授出"管理者"甚至"所有者"，
-- 而交接所有权是正常业务动作，不是越权。
--
-- 新语义：
--   默认 6（所有者）—— 用户的授权上限默认跟随其身份，由安全管理员按需下调；
--   真正防止提权的机制是"必须先对对象有 manage_acl" + "目标档位 ≤ 自身 ceiling"。

ALTER TABLE app_user ALTER COLUMN ceiling SET DEFAULT 6;

-- 本项目尚未有生产数据，这里把历史默认值统一修正；
-- 若有真实客户环境，应改为逐用户评估后下发，不做批量提升。
UPDATE app_user SET ceiling = 6 WHERE ceiling = 4;
