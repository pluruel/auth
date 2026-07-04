#!/usr/bin/env bash
# backup.sh — snapshot this auth deployment into a single tar.gz
# Usage: ./backup.sh [output-dir] [--no-db]
# Output: <output-dir>/auth_backup_<timestamp>.tar.gz (or _nodb.tar.gz with --no-db)
#
# Env overrides:
#   POSTGRES_CONTAINER — postgres container name (default: auth_rs_db_postgres,
#     shared by both docker-compose.yaml and docker-compose.dev.yaml)

set -euo pipefail
umask 077

NO_DB=0
OUTPUT_DIR=""
for arg in "$@"; do
  case "$arg" in
    --no-db) NO_DB=1 ;;
    *) OUTPUT_DIR="$arg" ;;
  esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="${OUTPUT_DIR:-$SCRIPT_DIR}"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
BACKUP_NAME="auth_backup_${TIMESTAMP}"
[[ "$NO_DB" -eq 1 ]] && BACKUP_NAME="${BACKUP_NAME}_nodb"
WORK_DIR="$(mktemp -d)"
STAGE="${WORK_DIR}/${BACKUP_NAME}"

cleanup() { rm -rf "$WORK_DIR"; }
trap cleanup EXIT

echo "[backup] staging in $STAGE"
mkdir -p "$STAGE"

# ── 1. env + compose ────────────────────────────────────────────────────────
for f in .env docker-compose.yaml docker-compose.dev.yaml nginx.conf; do
  [[ -f "$SCRIPT_DIR/$f" ]] && cp "$SCRIPT_DIR/$f" "$STAGE/" && echo "[backup] copied $f"
done

# ── 2. Ed25519 keypair ────────────────────────────────────────────────────────
if [[ -d "$SCRIPT_DIR/keys" ]]; then
  cp -r "$SCRIPT_DIR/keys" "$STAGE/keys"
  echo "[backup] copied keys/"
else
  echo "[warn] keys/ not found — skipping"
fi

# ── 3. PostgreSQL dump ───────────────────────────────────────────────────────
DB_CONTAINER="${POSTGRES_CONTAINER:-auth_rs_db_postgres}"

if [[ "$NO_DB" -eq 1 ]]; then
  echo "[backup] --no-db given — skipping DB dump"
elif docker ps --format '{{.Names}}' | grep -qx "$DB_CONTAINER"; then
  echo "[backup] dumping postgres ($DB_CONTAINER) ..."
  docker exec "$DB_CONTAINER" \
    sh -c 'pg_dump -U "$POSTGRES_USER" -d "$POSTGRES_DB" --no-password' \
    > "$STAGE/postgres.dump.sql"
  echo "[backup] dump complete ($(wc -c < "$STAGE/postgres.dump.sql") bytes)"
else
  echo "[error] container '$DB_CONTAINER' is not running — refusing to take a DB-less backup."
  echo "[error] start the stack first (./run.sh or 'docker compose up -d') and retry,"
  echo "[error] or pass --no-db to explicitly take a config-only backup."
  exit 1
fi

# ── 4. pack ─────────────────────────────────────────────────────────────────
ARCHIVE="${OUTPUT_DIR}/${BACKUP_NAME}.tar.gz"
mkdir -p "$OUTPUT_DIR"
tar -czf "$ARCHIVE" -C "$WORK_DIR" "$BACKUP_NAME"

echo ""
echo "[backup] done: $ARCHIVE"
echo "[backup] contents:"
tar -tzf "$ARCHIVE" | sed 's/^/  /'
