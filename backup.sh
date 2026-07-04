#!/usr/bin/env bash
# backup.sh — snapshot this auth deployment into a single tar.gz
# Usage: ./backup.sh [output-dir]
# Output: <output-dir>/auth_backup_<timestamp>.tar.gz

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="${1:-$SCRIPT_DIR}"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
BACKUP_NAME="auth_backup_${TIMESTAMP}"
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
# Load .env so we can talk to the container
if [[ -f "$SCRIPT_DIR/.env" ]]; then
  # shellcheck disable=SC1090
  set -a; source "$SCRIPT_DIR/.env"; set +a
fi

DB_CONTAINER="${POSTGRES_CONTAINER:-auth_rs_db_postgres}"
DB_USER="${POSTGRES_USER:-auth}"
DB_NAME="${POSTGRES_DB:-auth}"

if docker ps --format '{{.Names}}' | grep -qx "$DB_CONTAINER"; then
  echo "[backup] dumping postgres ($DB_CONTAINER / $DB_NAME) ..."
  docker exec "$DB_CONTAINER" \
    pg_dump -U "$DB_USER" -d "$DB_NAME" --no-password \
    > "$STAGE/postgres.dump.sql"
  echo "[backup] dump complete ($(wc -c < "$STAGE/postgres.dump.sql") bytes)"
else
  echo "[warn] container '$DB_CONTAINER' not running — skipping DB dump"
fi

# ── 4. pack ─────────────────────────────────────────────────────────────────
ARCHIVE="${OUTPUT_DIR}/${BACKUP_NAME}.tar.gz"
mkdir -p "$OUTPUT_DIR"
tar -czf "$ARCHIVE" -C "$WORK_DIR" "$BACKUP_NAME"

echo ""
echo "[backup] done: $ARCHIVE"
echo "[backup] contents:"
tar -tzf "$ARCHIVE" | sed 's/^/  /'
