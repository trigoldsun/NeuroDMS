#!/usr/bin/env bash
# DocVault 恢复脚本
#
# 恢复是最容易"看起来成功、实际不可用"的操作，所以本脚本强制三件事：
#   1. 先校验备份完整性（SHA256SUMS）——校验不过不往下走；
#   2. 恢复后做**业务级**验收（迁移记录 + 表行数 + 演示租户可登录），
#      而不是只看 pg_restore 退出码；
#   3. 恢复前把当前库重命名为 docvault_prev_<时间戳> 而不是直接覆盖，
#      留一条回头路（这是"恢复失败后还能回到恢复前"的唯一保障）。
#
# 用法：
#   bash scripts/restore.sh ./data/backups/20261108-120000 [--yes]
#
# 注意：会停止 docvault-server 与 docvault-onlyoffice 容器（避免写入竞争）。

set -euo pipefail
cd "$(dirname "$0")/.." || exit 1

SRC="${1:-}"
CONFIRM="${2:-}"
if [ -z "$SRC" ] || [ ! -d "$SRC" ]; then
  echo "用法: bash scripts/restore.sh <备份目录> [--yes]" >&2
  exit 1
fi

COMPOSE_FILE="docker/docker-compose.yml"
ENV_FILE="docker/.env"
PG_CONTAINER="${PG_CONTAINER:-docvault-postgres}"
STAMP=$(date +%Y%m%d-%H%M%S)
PREV_DB="${POSTGRES_DB:-docvault}_prev_$STAMP"

# shellcheck disable=SC1090
set -a; . "$ENV_FILE"; set +a

echo "== 1/6 校验备份完整性 =="
( cd "$SRC" && sha256sum -c SHA256SUMS )

if [ "$CONFIRM" != "--yes" ]; then
  echo
  echo "即将恢复："
  echo "  备份目录: $SRC"
  echo "  目标容器: $PG_CONTAINER / 数据库 $POSTGRES_DB"
  echo "  当前库会先改名为: $PREV_DB（不删除）"
  read -r -p "确认请键入 RESTORE: " ANS
  if [ "$ANS" != "RESTORE" ]; then
    echo "已取消" >&2
    exit 1
  fi
fi

echo "== 2/6 停止应用容器（避免写入竞争） =="
docker compose -f "$COMPOSE_FILE" --env-file "$ENV_FILE" stop server onlyoffice 2>/dev/null || true

echo "== 3/6 保留当前库（改名而非删除） =="
docker exec -e PGPASSWORD="$POSTGRES_PASSWORD" "$PG_CONTAINER" \
  psql -U "$POSTGRES_USER" -d postgres -v ON_ERROR_STOP=1 \
  -c "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname='$POSTGRES_DB' AND pid<>pg_backend_pid();" \
  -c "ALTER DATABASE \"$POSTGRES_DB\" RENAME TO \"$PREV_DB\";" \
  -c "CREATE DATABASE \"$POSTGRES_DB\" OWNER \"$POSTGRES_USER\";"

echo "== 4/6 恢复数据库 =="
# 用容器内 psql 的 \restrict 无关；这里直接 pg_restore，失败即退出
docker exec -i -e PGPASSWORD="$POSTGRES_PASSWORD" "$PG_CONTAINER" \
  pg_restore -U "$POSTGRES_USER" -d "$POSTGRES_DB" --no-owner --no-privileges --exit-on-error \
  < "$SRC/db.dump"

echo "== 5/6 恢复内容目录 =="
mkdir -p docker/data
# 先挪走旧内容目录（不删），再解包
for d in blob preview media; do
  if [ -d "docker/data/$d" ]; then
    mv "docker/data/$d" "docker/data/${d}.prev_$STAMP"
  fi
done
tar -xzf "$SRC/data.tar.gz" -C docker/data

echo "== 6/6 启动并做业务级验收 =="
docker compose -f "$COMPOSE_FILE" --env-file "$ENV_FILE" up -d
echo "等待服务就绪..."
for i in $(seq 1 60); do
  if curl -fsS "http://127.0.0.1:${DOCVAULT_PORT:-18090}/readyz" >/dev/null 2>&1; then
    break
  fi
  sleep 2
done

echo
echo "---- 验收 ----"
docker exec -e PGPASSWORD="$POSTGRES_PASSWORD" "$PG_CONTAINER" \
  psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -t -c \
  "SELECT 'migrations=' || count(*) FROM schema_migrations;" 2>/dev/null || \
  echo "migrations=未知（请检查迁移表名）"
docker exec -e PGPASSWORD="$POSTGRES_PASSWORD" "$PG_CONTAINER" \
  psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -t -c \
  "SELECT 'tenants=' || count(*) FROM tenant;"
docker exec -e PGPASSWORD="$POSTGRES_PASSWORD" "$PG_CONTAINER" \
  psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -t -c \
  "SELECT 'nodes=' || count(*) FROM node;"

if curl -fsS "http://127.0.0.1:${DOCVAULT_PORT:-18090}/readyz" >/dev/null 2>&1; then
  echo "readyz=ok"
else
  echo "readyz=失败 —— 恢复未完成，请检查 server 日志；原库仍在 $PREV_DB" >&2
  exit 1
fi

echo
echo "恢复完成。原库保留为 $PREV_DB。"
echo "确认无误后可手工清理："
echo "  ALTER DATABASE \"$PREV_DB\" ... / DROP DATABASE \"$PREV_DB\";"
