#!/usr/bin/env bash
# AC 门禁：把《越权与安全用例集》的每条用例追溯到真实测试，并实际跑一遍。
#
# 为什么需要这个脚本：
#   测试存在 ≠ 用例被覆盖。没有映射表，"我们测了 88 条"就只是一句话；
#   有了它，缺一条就红，谁都能复核。
#
# 三道检查：
#   1. 94 条 AC（78 条 M1/M2 + 10 条 M3 + 6 条账号管理）一条不能少（漏写即失败）
#   2. 标 ✅ 的必须有测试名，且函数真实存在
#   3. 标 ◐ / ⬜ 的必须写明归属里程碑（M2），不允许"无主缺口"
#   4. 有 DSN 时，把 ✅ 的测试全部真跑一遍（存在但跑不过同样失败）
#
# 用法：bash scripts/ac-gate.sh
#   DOCVAULT_TEST_DSN 未设置时只做静态校验（会明确提示"未执行"）。

set -u
cd "$(dirname "$0")/.." || exit 1

export GOPROXY="${GOPROXY:-https://goproxy.cn,direct}"
MATRIX="docs/07-越权用例覆盖矩阵-v1.0.md"

if [ ! -f "$MATRIX" ]; then
  echo "找不到覆盖矩阵: $MATRIX"
  exit 1
fi

echo "== AC 门禁：静态校验 =="
STATIC=$(python - "$MATRIX" <<'PY'
import re, sys, subprocess, os

path = sys.argv[1]
rows = {}
for line in open(path, encoding='utf-8'):
    line = line.strip()
    m = re.match(r'^\|\s*(AC-\d{2})\s*\|(.*)\|\s*$', line)
    if not m:
        continue
    cid, rest = m.group(1), m.group(2)
    # 按 | 切分剩余列（最后一列可能为空）
    cols = [c.strip() for c in rest.split('|')]
    if len(cols) < 3:
        print(f"BADCOL {cid} 列数不足")
        continue
    status, tests, note = cols[-3], cols[-2], cols[-1]
    rows[cid] = (status, tests, note)

# 1) 数量与连续性
expected = {f"AC-{i:02d}" for i in range(1, 95)}
missing = sorted(expected - set(rows))
extra = sorted(set(rows) - expected)
if missing:
    print("MISSING " + ",".join(missing))
if extra:
    print("EXTRA " + ",".join(extra))

# 2) 状态合法性 + 测试存在性
covered, partial, gap = [], [], []
all_tests = []
for cid in sorted(rows):
    status, tests, note = rows[cid]
    if status.startswith('✅'):
        if not tests:
            print(f"NOTEST {cid} 标为已覆盖但没有测试")
            continue
        for t in [x.strip() for x in tests.split(',') if x.strip()]:
            if not re.match(r'^Test[A-Za-z0-9_]+$', t):
                print(f"BADNAME {cid} 非法测试名 {t}")
                continue
            all_tests.append(t)
        covered.append(cid)
    elif status.startswith('◐'):
        if 'M2' not in note:
            print(f"NOMILESTONE {cid} 部分覆盖但未写归属里程碑")
        partial.append(cid)
    elif status.startswith('⬜'):
        if 'M2' not in note:
            print(f"NOMILESTONE {cid} 缺口但未写归属里程碑")
        gap.append(cid)
    else:
        print(f"BADSTATUS {cid} 未知状态 {status}")

print(f"COUNT covered={len(covered)} partial={len(partial)} gap={len(gap)} total={len(rows)}")
if all_tests:
    print("TESTS " + ",".join(sorted(set(all_tests))))
PY
)
STATUS=$?
if [ $STATUS -ne 0 ]; then
  echo "$STATIC"
  echo "矩阵解析失败"
  exit 1
fi

echo "$STATIC" | grep -E "^(MISSING|EXTRA|BADCOL|NOTEST|BADNAME|NOMILESTONE|BADSTATUS)" && {
  echo "静态校验未通过"
  exit 1
}

SUMMARY=$(echo "$STATIC" | grep "^COUNT")
TESTS=$(echo "$STATIC" | grep "^TESTS" | sed 's/^TESTS //')
echo "$SUMMARY"

# 3) 测试函数是否真实存在
if [ -n "$TESTS" ]; then
  echo "== AC 门禁：测试函数存在性 =="
  NOTFOUND=""
  IFS=',' read -ra NAMES <<< "$TESTS"
  for n in "${NAMES[@]}"; do
    if ! grep -rq "^func ${n}(" --include='*_test.go' . ; then
      NOTFOUND="$NOTFOUND $n"
    fi
  done
  if [ -n "$NOTFOUND" ]; then
    echo "以下测试名在代码中不存在:$NOTFOUND"
    exit 1
  fi
  echo "全部 ${#NAMES[@]} 个测试函数存在"
fi

# 4) 实际执行（需要数据库）
if [ -z "${DOCVAULT_TEST_DSN:-}" ]; then
  echo "== AC 门禁：已跳过执行（未设置 DOCVAULT_TEST_DSN）=="
  echo "注意：本次只做了静态校验，**不能**据此宣称用例通过。"
  exit 0
fi

echo "== AC 门禁：执行已覆盖用例 =="
PATTERN="^($(echo "$TESTS" | tr ',' '|'))$"
if go test ./... -run "$PATTERN" -count=1 > /tmp/ac-gate.log 2>&1; then
  echo "全部通过"
  grep -E "^ok " /tmp/ac-gate.log | sed 's/^/  /'
else
  echo "存在失败用例："
  grep -E "^(FAIL|--- FAIL|    )" /tmp/ac-gate.log | head -40
  exit 1
fi
