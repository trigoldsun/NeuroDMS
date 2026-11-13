#!/usr/bin/env bash
# DocVault 备份脚本（M2 交付项：备份恢复）
#
# 为什么用 docker exec 调 pg_dump 而不是要求宿主机装客户端：
#   私有化交付环境常常只有 Docker，没有 postgresql-client。
#   备份脚本要求"宿主机装一套与容器同版本的客户端"是最容易在客户现场失败的一步。
#
# 备份内容（缺一不可）：
#   1. 数据库逻辑备份（pg_dump -Fc：可单表恢复、可跨小版本恢复）
#   2. 内容目录（blob/preview/media/onlyoffice 的数据都在这里）
#   3. 校验清单（sha256）：没有校验的备份等于"不知道能不能用"
#
# 用法：
#   bash scripts/backup.sh [输出目录]
#   BACKUP_KEEP=14 bash scripts/backup.sh /data/backups   # 保留 14 份

set -euo pipefail
cd "$(dirname "$0")/.." || exit 1

OUT_DIR="${1:-./data/backups}"
KEEP="${BACKUP_KEEP:-7}"
COMPOSE_FILE="docker/docker-compose.yml"
ENV_FILE="docker/.env"
PG_CONTAINER="${PG_CONTAINER:-docvault-postgres}"
STAMP=$(date +%Y%m%d-%H%M%S)
WORK="$OUT_DIR/$STAMP"

if [ ! -f "$ENV_FILE" ]; then
  echo "缺少 $ENV_FILE，无法确定数据库口令" >&2
  exit 1
fi
# shellcheck disable=SC1090
set -a; . "$ENV_FILE"; set +a

if ! docker ps --format '{{.Names}}' | grep -qx "$PG_CONTAINER"; then
  echo "数据库容器 $PG_CONTAINER 未运行，拒绝生成半份备份" >&2
  exit 1
fi

mkdir -p "$WORK"
echo "== 1/4 数据库逻辑备份 =="
docker exec -e PGPASSWORD="$POSTGRES_PASSWORD" "$PG_CONTAINER" \
  pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Fc --no-owner --no-privileges \
  > "$WORK/db.dump"
DB_SIZE=$(wc -c < "$WORK/db.dump")
if [ "$DB_SIZE" -lt 10000 ]; then
  echo "数据库备份异常小（$DB_SIZE 字节），疑似失败" >&2
  exit 1
fi

echo "== 2/4 内容目录打包 =="
# 只打包真正需要的数据目录；onlyoffice 的缓存不进备份（可由容器重建）。
# 显式列出要打包的目录，而不是"排除某一个"：新增目录时漏备份的代价远大于多备一点。
DATA_DIRS=""
for d in blob preview media; do
  if [ -d "docker/data/$d" ]; then DATA_DIRS="$DATA_DIRS $d"; fi
done
if [ -z "$DATA_DIRS" ]; then
  echo "docker/data 下没有可备份的内容目录（blob/preview/media），请检查挂载" >&2
  exit 1
fi
# shellcheck disable=SC2086
tar -czf "$WORK/data.tar.gz" -C docker/data $DATA_DIRS

echo "== 3/4 记录环境与版本 =="
{
  echo "created_at=$(date -Iseconds)"
  echo "postgres_version=$(docker exec "$PG_CONTAINER" postgres --version 2>/dev/null || echo unknown)"
  echo "compose_file=$COMPOSE_FILE"
  docker inspect "$PG_CONTAINER" --format 'postgres_image={{.Config.Image}}' 2>/dev/null || true
} > "$WORK/meta.txt"

echo "== 4/4 生成校验清单 =="
( cd "$WORK" && sha256sum db.dump data.tar.gz meta.txt > SHA256SUMS )

# 清理超期备份（只删本脚本自己创建的目录，不做通配删除）
if [ "$KEEP" -gt 0 ]; then
  (ls -1dt "$OUT_DIR"/*/ 2>/dev/null || true) | tail -n +$((KEEP + 1)) | while read -r old; do
    case "$old" in
      "$OUT_DIR"/*) echo "清理超期备份: $old"; rm -rf -- "$old" ;;
    esac
  done
fi

echo
echo "备份完成: $WORK"
echo "  db.dump      $(du -h "$WORK/db.dump" | cut -f1)"
echo "  data.tar.gz  $(du -h "$WORK/data.tar.gz" | cut -f1)"
echo "校验: cd $WORK && sha256sum -c SHA256SUMS"
