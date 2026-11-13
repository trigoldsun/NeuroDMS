# 19 · SaaS 版 · 订阅计量与用量明细 · 架构设计

版本：v1.0.0
日期：2026-11-10
状态：**设计稿，待评审**。无代码改动。
上位规范：`17-档位授权与容量计费-架构设计-v1.4.md`（档位矩阵、密级、容量公式、定价、不变量均以 17 为准）
定位：SaaS 是**与本地版并列的第二套产品**，独立仓库（当前仓库即 SaaS），多租户、平台改档、blob 去重计量。

---

## 1. 与本地版的差异

| 维度 | SaaS | 本地版（见 18） |
|---|---|---|
| 授权 | 平台改档，实时生效 | 离线许可证，签发时快照 |
| 计量 | blob 去重（含版本、回收站） | 当前有效文件字节 |
| 明细 | 三层视图（当前/版本/回收站/待回收） | 仅当前文件按空间分布 |
| 计费 | 月付或年付（付 10 用 12） | 仅年付 |
| 参数 | 运营台实时可配，新激活生效 | 签发时固化 |

---

## 2. 多租户与改档

租户的档位、席位由平台侧记录，实时生效：

```sql
-- 租户订阅：当前生效的一条
tenant_subscription(
  tenant_id     uuid primary key references tenant(id),
  edition       text not null check (edition in ('basic','professional','business')),
  seats         int not null check (seats > 0),
  billing_cycle text not null check (billing_cycle in ('monthly','annual')),
  started_at    timestamptz not null default now(),
  current_period_end timestamptz not null,
  status        text not null default 'active'
                check (status in ('active','past_due','canceled')),
  updated_at    timestamptz not null default now()
);

-- 变更历史：只追加
tenant_subscription_change(
  id bigserial primary key,
  tenant_id uuid not null references tenant(id),
  from_edition text, to_edition text,
  from_seats int, to_seats int,
  effective_at timestamptz not null,
  reason text,
  operator text not null,
  created_at timestamptz not null default now()
);
```

改档规则：

| 动作 | 生效 | 计费 |
|---|---|---|
| 升档（basic → professional） | 立即 | 按日折算补差 |
| 升席 | 立即 | 按日折算补差 |
| 降档 | **下一个计费周期** | 当期不退款 |
| 减席 | **仅续费时** | 当期不退款 |

降档前必须先过密级兼容性校验（17 §3）；不通过则整体拒绝，返回对象清单。

`tenant_quota.max_storage_bytes` 与 `max_users` 由 `tenant_subscription` 派生写入，**不手工维护**，改档事务内同步更新。

---

## 3. 计量：blob 去重

### 3.1 口径

```
已用(bytes) = SUM(blob.size_bytes) WHERE tenant_id = ?
```

`blob` 是内容寻址表（`UNIQUE(tenant_id, sha256, size_bytes)`），同租户同内容只存一份。该口径自动实现：版本历史计入、回收站计入、同内容不重复计费。

### 3.2 触发器（替换现有 `node_usage_sync`）

```sql
-- blob 行增删驱动账本；node 的软删除不再影响账本
CREATE OR REPLACE FUNCTION blob_usage_sync() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$
DECLARE v_used bigint; v_max bigint; v_exceed text; v_tenant uuid; v_delta bigint;
BEGIN
    v_tenant := COALESCE(NEW.tenant_id, OLD.tenant_id);
    v_delta  := CASE TG_OP WHEN 'INSERT' THEN NEW.size_bytes ELSE -OLD.size_bytes END;

    INSERT INTO tenant_usage (tenant_id) VALUES (v_tenant) ON CONFLICT DO NOTHING;
    SELECT storage_bytes INTO v_used FROM tenant_usage WHERE tenant_id = v_tenant FOR UPDATE;

    IF v_delta > 0 THEN
        SELECT q.max_storage_bytes, q.on_exceed INTO v_max, v_exceed
          FROM tenant_quota q WHERE q.tenant_id = v_tenant;
        IF v_max IS NOT NULL AND v_exceed = 'reject' AND v_used + v_delta > v_max THEN
            RAISE EXCEPTION 'quota:storage' USING ERRCODE = 'DV403';
        END IF;
    END IF;

    UPDATE tenant_usage SET storage_bytes = GREATEST(v_used + v_delta, 0), updated_at = now()
     WHERE tenant_id = v_tenant;
    RETURN NULL;   -- AFTER 触发器
END $$;

CREATE TRIGGER trg_blob_usage AFTER INSERT OR DELETE ON blob
  FOR EACH ROW EXECUTE FUNCTION blob_usage_sync();
```

同时**移除** `trg_node_usage` 对 `deleted_at` 的响应（保留 `kind/size_bytes` 变更仍不触发账本）。

### 3.3 `ref_count` 维护（关键前置）

现有 `blob.ref_count` 必须由触发器维护，不能依赖应用代码，否则漏写一次账本永久失真：

```sql
CREATE OR REPLACE FUNCTION version_blob_refcount() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        UPDATE blob SET ref_count = ref_count + 1 WHERE id = NEW.blob_id;
    ELSIF TG_OP = 'DELETE' THEN
        UPDATE blob SET ref_count = ref_count - 1 WHERE id = OLD.blob_id;
    END IF;
    RETURN NULL;
END $$;

CREATE TRIGGER trg_version_refcount AFTER INSERT OR DELETE ON version
  FOR EACH ROW EXECUTE FUNCTION version_blob_refcount();
```

上线前必须先跑一次 `ref_count` 全量重算（`UPDATE blob SET ref_count = (SELECT count(*) FROM version v WHERE v.blob_id = blob.id)`），再挂触发器。

### 3.4 回收与释放

```
到期（purge_after）→ DELETE version → ref_count 归零 → 标记 gc_pending
   → 10 分钟后删 blob 行（账本释放）→ 删物理文件
```

回收站保留期按档位：**基础 7 天、专业 30 天、商业 1–90 天（租户可配，默认 30）**，从删除时刻写入 `node.purge_after`，降档不追溯已删除对象。

完整的两级 GC（租户级删行 / 物理级删文件）、`gc_pending` 防秒传竞态、`ref_count` 修复顺序，见 `20-存储空间治理-回收站保留与GC-架构设计-v1.0.md`。本节只保留结论：

- 物理文件删除必须在 blob 行删除之后，失败不回滚账本；
- 保留期内对象计入"回收站"类容量，到期才释放；
- 不允许配置 0 天；立即释放走"清空回收站"显式动作。

### 3.5 对账

每日 02:00 执行：

1. `SUM(blob.size_bytes)` vs `tenant_usage.storage_bytes`，偏差 >1% → 告警并自动修正（写修正审计，含前后值）；
2. 对象存储实际文件清单 vs `blob.storage_key`，存在孤儿文件 → 告警（只报告，不自动删）；
3. 输出《租户用量日报》，含越线租户清单。

---

## 4. 用量明细

### 4.1 可见范围与入口

租户拥有者（owner）与租户管理员（admin）可见。系统管理员不看租户业务明细，只看汇总。

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/v1/tenant/usage` | 已用、上限、百分比、状态、剩余宽限天数 |
| GET | `/v1/tenant/usage/breakdown` | 分类明细（见 4.3） |
| POST | `/v1/tenant/usage/refresh` | 触发异步重算（限频：每租户每小时 1 次） |
| GET | `/v1/tenant/usage/breakdown.csv` | 导出 CSV |

### 4.2 数据来源

实时 `SUM(blob.size_bytes)` 很轻（索引扫描），但**归属分类**需要 join `version` / `node`，百万级文件会拖慢。因此：

- 总量：实时算，页面直接显示；
- 分类：按小时快照落 `storage_breakdown_hourly`，页面显示"统计时间：YYYY-MM-DD HH:00"，并提供手动刷新（异步任务，完成后轮询结果）。

### 4.3 分类规则（互斥完备）

| 优先级 | 分类 | 判定 |
|---:|---|---|
| 1 | 当前文件 | 被任一未删除 node 的 `current_version_id` 引用 |
| 2 | 回收站 | 未被第 1 类引用，但被任一 `deleted_at IS NOT NULL` 的 node 引用 |
| 3 | 版本历史 | 未被前两类引用，仅被非当前版本引用 |
| 4 | 待回收 | 无任何引用（GC 队列中） |

**硬约束**：`当前文件 + 回收站 + 版本历史 + 待回收 = 总量`，差额恒为 0。这是对账单测的断言，也是客户信任的基础。

第二层（仅对"当前文件"部分成立）：按空间 / 按类型（office/pdf/图片/音视频/压缩包/其他）/ 按密级 / 按上传人 / 按最近访问时间（30/90/365 天未访问）。跨空间引用的 blob 归到"引用它的未删除 node 中最早创建的那个"。

界面必须写明："第二层只统计当前文件，且跨空间文件的归属为单一空间"，否则客户会拿各空间之和去对总量。

### 4.4 客户自助降容量的三个入口

明细页直接给出可操作项，否则客户看到"回收站占 300GB"也不知道怎么办：

1. **清空回收站**（立即释放，二次确认）；
2. **版本保留策略**：设置每个文件保留最近 N 个版本（基础 3 / 专业 10 / 商业 50，商业可调 10–50），超出部分由系统清理并释放；
3. **申请扩容**：跳转加席/升档报价页（不提供纯容量加购，见 17 §10）。

---

## 5. 账单

计费项只有一项：**席位费**。无容量费、无平台费、无最低消费。

```
月付：当期费用 = 月费(edition, seats)
年付：当期费用 = 月费(edition, seats) × 10      # 付 10 用 12
```

出账流程：

1. 每月 1 日 00:10 生成上月账单快照（档位、席位、单价、各阶梯段人数与金额、合计），存 `invoice_line`；
2. 快照一旦生成不可改，调整走"补差单"（`invoice_adjustment`，带原因与审批人）；
3. 账单与 `tenant_subscription_change` 交叉校验：期内升档/升席的按日折算必须能在流水中逐笔对上。

日折算规则：`补差 = (新月费 - 旧月费) × 剩余天数 / 当期总天数`。年付客户升档时，剩余天数按**剩余月份 × 30** 计算，避免 2 月/31 天口径争议。

欠费：`past_due` 状态 → 30 天宽限（正常可用 + 每日提示）→ 转 `readonly`，数据保留 90 天 → 之后按合同处理，**永不自动删除**。

---

## 6. 平台运营台

### 6.1 档位参数页

读写 `edition_params`（17 §8.2）。保存前校验：

- `max_seats >= min_seats`、`tier_floor ∈ (0,1]`、`annual_months ∈ [1,12]`、`storage_gb_per_seat > 0`；
- 变更后立即预览"新报价表"（用 `capacityBytes()` 与定价引擎现算），避免手滑把专业版配成 1 元/席；
- 双人复核：参数变更需第二个运营账号确认后才生效（`pending_approval` 状态）。

### 6.2 存量同步

改参数**不影响存量租户**。需要同步时：

1. 点"同步到存量" → 先跑 dry-run，输出影响清单（租户、旧容量、新容量、是否会越线、账单变化）；
2. 运营逐个或批量确认 → 生成新的订阅变更记录 + 审计；
3. 会越线的租户必须单独处理（扩容或给宽限），不允许批量同步把客户推进 `readonly`。

### 6.3 单租户覆盖

用于大客户定制（例外容量、例外单价）。写 `tenant_entitlement`（带 `reason`、`expires_at`、`granted_by`），优先级：全局熔断 > 单租户覆盖 > 档位参数。覆盖到期自动失效，失效前 30 天提醒运营。

### 6.4 运营看板

- 租户总数 / 各档位分布 / MRR / 席位总数 / 存储总量；
- 越线租户列表（warning / grace / readonly），含越线天数与增长趋势；
- 存储成本估算（按对象存储单价 × 实际占用），与收入对比看毛利率；
- 近 90 天"容量增长最快 Top 20"，提前发现异常上传（如客户拿系统当网盘）。

---

## 7. 存储成本控制

商业版 100 席 = 5TB、500 席 = 25TB。收入 19,216 / 80,573 元/年，折合约 3.8 / 3.2 元/GB/年。对象存储标准型约 1.4 元/GB/年，全热存毛利仍健康，但需要两条防线：

1. **异常上传识别**：单租户单日上传 > 上限 10% → 告警（可能是把系统当备份盘）；
2. **冷热分层（P4 可选）**：90 天未访问的对象转低频/归档，预览时预热。归档取回有延迟，必须先确认 OnlyOffice 预览链路能否接受，不能直接打开自动分层。

---

## 8. 数据模型（新增表）

```sql
-- 分类快照（长表，dim 区分维度）
storage_breakdown_hourly(
  tenant_id  uuid not null references tenant(id),
  hour       timestamptz not null,
  dim        text not null,   -- total|current|trash|version|pending|space|mime|class|owner
  key        text not null default '',   -- 空间 id / 类型 / 密级 / 用户 id；total 类为空串
  bytes      bigint not null check (bytes >= 0),
  primary key (tenant_id, hour, dim, key)
);
create index ix_breakdown_hour on storage_breakdown_hourly(hour);
-- 按月分区，保留 90 天
```

```sql
invoice(
  id bigserial primary key,
  tenant_id uuid not null references tenant(id),
  period_start date not null, period_end date not null,
  edition text not null, seats int not null,
  billing_cycle text not null,
  amount numeric(12,2) not null,
  status text not null default 'issued',   -- issued|paid|void
  issued_at timestamptz not null default now()
);
invoice_line(
  id bigserial primary key,
  invoice_id bigint not null references invoice(id),
  tier_no int, seats_in_tier int, unit_price numeric(10,4), amount numeric(12,2),
  note text
);
```

---

## 9. 接口汇总

| 方法 | 路径 | 权限 | 说明 |
|---|---|---|---|
| GET | `/v1/tenant/usage` | owner/admin | 已用、上限、状态、宽限剩余 |
| GET | `/v1/tenant/usage/breakdown` | owner/admin | 分类明细 |
| POST | `/v1/tenant/usage/refresh` | owner | 触发重算（限频） |
| GET | `/v1/tenant/usage/breakdown.csv` | owner/admin | 导出 |
| GET | `/v1/platform/editions` | 平台读 | 三档参数与报价预览 |
| PATCH | `/v1/platform/editions/{edition}` | 平台写（双人复核） | 改参数 |
| POST | `/v1/platform/editions/{edition}/sync-preview` | 平台写 | dry-run 影响清单 |
| POST | `/v1/platform/editions/{edition}/sync-apply` | 平台写 | 执行同步（逐租户确认） |
| PATCH | `/v1/platform/tenants/{slug}/edition` | 平台写 | 改档（过兼容性校验） |
| PATCH | `/v1/platform/tenants/{slug}/seats` | 平台写 | 加席（合同期内不可减） |
| GET | `/v1/platform/tenants/{slug}/usage` | 平台读 | 单租户用量与趋势 |
| GET | `/v1/platform/usage/overview` | 平台读 | 全局看板 |

错误契约：`409 EDITION_DOWNGRADE_BLOCKED`（附对象清单）、`409 SEATS_REDUCE_NOT_ALLOWED`、`429 REFRESH_TOO_FREQUENT`、`403 FEATURE_NOT_ENABLED`、`503 ENTITLEMENT_UNAVAILABLE`。

---

## 10. 审计

`subscription.change`（档位/席位，含前后值、折算金额）、`edition.params_change`（含前后值、复核人）、`edition.sync_apply`（批量，逐租户一条）、`entitlement.grant`、`storage.usage_corrected`（对账修正）、`invoice.adjust`。全部写哈希链审计表。

---

## 11. 不变量

1. 明细分类之和 = 计费总量，差额恒为 0。
2. 账本只由 `blob` 行增减驱动，`node` 的软删除不影响账本。
3. `ref_count` 由触发器维护，不依赖应用代码。
4. 超限永不删数据，最严 `readonly`；客户始终能下载与清空回收站。
5. 减席仅在续费生效，合同期内只升不降。
6. 降档在下一周期生效，且必须先过密级兼容性校验。
7. 参数变更不追溯存量，同步必须 dry-run + 逐租户确认。
8. 账单快照生成后不可改，调整走补差单。
9. 授权/订阅读取失败 → 503，不允许 fail-open。

---

## 12. 落地阶段

| 阶段 | 内容 | 验收 |
|---|---|---|
| **S0** | `tenant_subscription` + 容量派生 + 改档接口 | 改档后 `tenant_quota` 同步，容量正确 |
| **S1** | `ref_count` 全量重算 + 触发器 + 账本切 blob 口径 | 账本 = `SUM(blob.size_bytes)`，偏差 0 |
| **S2** | 口径切换影响评估 + 越线租户处理 | 无租户因切换被误置只读 |
| **S3** | 明细页（三层 + 第二层）+ 快照任务 + CSV | 分类之和 = 总量；页面数据延迟 ≤ 1 小时 |
| **S4** | 超限状态机 + 通知（90%/越线/宽限到期） | 越线 30 天准确进只读，清理后自动恢复 |
| **S5** | 运营台参数页 + 双人复核 + 存量同步 dry-run | 批量同步不会把客户推进只读 |
| **S6** | 账单生成 + 补差 + 对账 | 升档折算与流水逐笔对得上 |

**S1 的前置动作**（不可省）：先重算 `blob.ref_count`，再改账本口径；顺序反了会导致账本在切换瞬间大幅漂移且无法解释。

---

## 13. 待确认

1. 欠费 `readonly` 后数据保留 90 天，之后是否允许删除（当前设计：永不自动删除）。
2. 年付客户剩余天数按"剩余月份 × 30"折算，是否与财务口径一致。
3. 商业版默认回收站保留期取 30 天（本稿）还是 90 天（见 20 §10）。
4. 版本保留数按档位（基础 3 / 专业 10 / 商业 50）是否认可（见 21 §6）。
