#!/usr/bin/env bash
# DocVault 提交前检查（不依赖 make，Windows Git Bash / Linux / macOS 通用）
set -uo pipefail

cd "$(dirname "$0")/.." || exit 1

# 官方代理在本网络不可用，统一走镜像；仅影响分发通道，不影响依赖内容（由 go.sum 保证）
export GOPROXY="${GOPROXY:-https://goproxy.cn,direct}"

# 尝试定位 gcc：winget 安装的 WinLibs 不在默认 PATH 里
if ! command -v gcc >/dev/null 2>&1 && [ -n "${LOCALAPPDATA:-}" ]; then
  for d in "$LOCALAPPDATA"/Microsoft/WinGet/Packages/*WinLibs*/mingw64/bin; do
    if [ -x "$d/gcc.exe" ]; then
      export PATH="$d:$PATH"
      break
    fi
  done
fi

fail=0

echo "== gofmt =="
unformatted=$(gofmt -l ./cmd ./internal 2>/dev/null)
if [ -n "$unformatted" ]; then
  echo "以下文件未格式化："
  echo "$unformatted"
  echo "修复：gofmt -w ./cmd ./internal"
  fail=1
else
  echo "OK"
fi

echo "== go vet =="
if go vet ./... ; then echo "OK"; else fail=1; fi

echo "== go test =="
if go test ./... -count=1 ; then echo "OK"; else fail=1; fi

echo "== 覆盖率（核心包）=="
go test ./internal/authz/ -cover -count=1

if [ -n "${DOCVAULT_TEST_DSN:-}" ]; then
  echo "== 数据库集成测试 =="
  if go test ./internal/db/ -count=1 ; then echo "OK"; else fail=1; fi
else
  echo "== 数据库集成测试：已跳过（未设置 DOCVAULT_TEST_DSN）=="
fi

echo "== go test -race =="
if command -v gcc >/dev/null 2>&1; then
  if CGO_ENABLED=1 go test ./... -race -count=1 ; then echo "OK"; else fail=1; fi
else
  echo "已跳过（未找到 gcc）：竞态检测缺位，不得视为通过"
fi

echo "== 前后端接口一致性 =="
if command -v node >/dev/null 2>&1; then
  if node scripts/check-api-consistency.mjs; then echo "OK"; else fail=1; fi
else
  echo "已跳过（未找到 node）：前端调了不存在的接口不会在这里被拦住"
fi

echo "== 交互约定（状态必须进地址）=="
if command -v node >/dev/null 2>&1; then
  if node scripts/check-ui-routes.mjs; then echo "OK"; else fail=1; fi
else
  echo "已跳过（未找到 node）：页签/详情不进地址不会在这里被拦住"
fi

echo "== AC 门禁（越权用例追溯）=="
if bash scripts/ac-gate.sh > /tmp/ac-gate-check.log 2>&1; then
  grep -E "^COUNT" /tmp/ac-gate-check.log
  echo "OK"
else
  tail -20 /tmp/ac-gate-check.log
  fail=1
fi

if [ "$fail" -ne 0 ]; then
  echo
  echo "检查未通过"
  exit 1
fi

echo
echo "全部通过"
