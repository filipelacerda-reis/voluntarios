#!/usr/bin/env sh
set -eu

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BACKUP_DIR="$ROOT_DIR/backups"
TS="$(date +%Y%m%d_%H%M%S)"
OUT="$BACKUP_DIR/voluntario_$TS.sql.gz"

mkdir -p "$BACKUP_DIR"

echo "Gerando backup em $OUT"
docker compose exec -T db pg_dump -U voluntario -d voluntario | gzip > "$OUT"

echo "Backup concluído: $OUT"
