#!/usr/bin/env bash
# 恢复演练（不触碰生产库）
#
# 为什么单独一个脚本：
#   "备份能恢复"这句话只有跑过一次才算数，但在生产库上做恢复演练风险极高。
#   本脚本把备份恢复到**临时库**，核对表与行数，然后删掉临时库——
#   既验证了备份可用，又不动任何线上数据。
#
# 用法：bash scripts/restore-drill.sh ./data/backups/<时间戳>

set -euo pipefail
cd "$(dirname "$0")/.." || exit 1

SRC="${1:-}"
if [ -z "$SRC" ] || [ ! -f "$SRC/db.dump" ]; then
  echo "用法: bash scripts/restore-drill.sh <备份目录>" >&2
  exit 1
fi

ENV_FILE="docker/.env"
PG_CONTAINER="${PG_CONTAINER:-docvault-postgres}"
DRILL_DB="docvault_drill_$(date +%s)"

# shellcheck disable=SC1090
set -a; . "$ENV_FILE"; set +a

echo "== 1/4 校验备份 =="
( cd "$SRC" && sha256sum -c SHA256SUMS )

echo "== 2/4 恢复到临时库 $DRILL_DB =="
docker exec -e PGPASSWORD="$POSTGRES_PASSWORD" "$PG_CONTAINER" \
  psql -U "$POSTGRES_USER" -d postgres -v ON_ERROR_STOP=1 \
  -c "CREATE DATABASE \"$DRILL_DB\" OWNER \"$POSTGRES_USER\";" >/dev/null

cleanup() {
  docker exec -e PGPASSWORD="$POSTGRES_PASSWORD" "$PG_CONTAINER" \
    psql -U "$POSTGRES_USER" -d postgres -c "DROP DATABASE IF EXISTS \"$DRILL_DB\";" >/dev/null 2>&1 || true
}
trap cleanup EXIT

docker exec -i -e PGPASSWORD="$POSTGRES_PASSWORD" "$PG_CONTAINER" \
  pg_restore -U "$POSTGRES_USER" -d "$DRILL_DB" --no-owner --no-privileges --exit-on-error \
  < "$SRC/db.dump"

echo "== 3/4 核对关键表 =="
docker exec -e PGPASSWORD="$POSTGRES_PASSWORD" "$PG_CONTAINER" \
  psql -U "$POSTGRES_USER" -d "$DRILL_DB" -t -A -F'=' -c "
    SELECT 'migrations', count(*) FROM schema_migrations
    UNION ALL SELECT 'tenants', count(*) FROM tenant
    UNION ALL SELECT 'users', count(*) FROM app_user
    UNION ALL SELECT 'spaces', count(*) FROM space
    UNION ALL SELECT 'nodes', count(*) FROM node
    UNION ALL SELECT 'versions', count(*) FROM version
    UNION ALL SELECT 'audit_events', count(*) FROM audit_event;"

echo "== 4/4 核对内容目录引用 =="
# 只核对"有多少 blob 行"，不校验文件是否存在（文件在 data.tar.gz 里，备份侧已打包）
docker exec -e PGPASSWORD="$POSTGRES_PASSWORD" "$PG_CONTAINER" \
  psql -U "$POSTGRES_USER" -d "$DRILL_DB" -t -A -c "SELECT 'blobs=' || count(*) FROM blob;"

echo
echo "演练通过：备份可恢复，临时库将自动删除。"
