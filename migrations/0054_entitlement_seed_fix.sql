-- 0054_entitlement_seed_fix.sql
--
-- 修正 0052 种子里一处"声明了但不存在"的开关（代码审查发现）。
--
-- `branding.custom_domain` 被标成 tenant_settable=true，但租户侧根本没有
-- 对应的策略字段（Policy 里只有 folderUpload / smsLogin）。运营台若按这一列
-- 渲染"允许租户自管"，会显示一个点不动的开关——这正是文档里反复强调要避免的
-- "假开关"。在真正做出域名自管开关之前，先把声明改成事实。
--
-- 注意：只改声明，不改任何判定；已有租户能力不受影响。

BEGIN;

UPDATE entitlement_def
   SET tenant_settable = false,
       updated_at = now()
 WHERE code = 'branding.custom_domain'
   AND tenant_settable;

COMMIT;
