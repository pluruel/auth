#!/usr/bin/env bash
# restore.sh — restore an auth backup archive on the target server
# Usage: ./restore.sh <backup.tar.gz> [target-dir]
#   target-dir defaults to the directory containing this script.
#
# Steps:
#   1. Extract archive
#   2. Copy env / keys / compose / nginx to target-dir
#   3. Start postgres, wait for healthy
#   4. Restore DB dump
#   5. Start remaining services

set -euo pipefail

ARCHIVE="${1:-}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET_DIR="${2:-$SCRIPT_DIR}"

if [[ -z "$ARCHIVE" || ! -f "$ARCHIVE" ]]; then
  echo "Usage: $0 <backup.tar.gz> [target-dir]"
  exit 1
fi

ARCHIVE="$(cd "$(dirname "$ARCHIVE")" && pwd)/$(basename "$ARCHIVE")"
WORK_DIR="$(mktemp -d)"
cleanup() { rm -rf "$WORK_DIR"; }
trap cleanup EXIT

echo "[restore] extracting $ARCHIVE ..."
tar -xzf "$ARCHIVE" -C "$WORK_DIR"
STAGE="$(find "$WORK_DIR" -mindepth 1 -maxdepth 1 -type d | head -1)"
echo "[restore] source: $STAGE"

# ── 1. copy config files ─────────────────────────────────────────────────────
for f in .env docker-compose.yaml docker-compose.dev.yaml nginx.conf; do
  if [[ -f "$STAGE/$f" ]]; then
    if [[ -f "$TARGET_DIR/$f" ]]; then
      echo "[restore] backing up existing $f → $f.bak"
      cp "$TARGET_DIR/$f" "$TARGET_DIR/$f.bak"
    fi
    cp "$STAGE/$f" "$TARGET_DIR/$f"
    echo "[restore] restored $f"
  fi
done

# ── 2. keys ──────────────────────────────────────────────────────────────────
if [[ -d "$STAGE/keys" ]]; then
  mkdir -p "$TARGET_DIR/keys"
  cp -r "$STAGE/keys/." "$TARGET_DIR/keys/"
  chmod 600 "$TARGET_DIR/keys"/*.pem 2>/dev/null || true
  echo "[restore] restored keys/"
else
  echo "[warn] no keys/ in archive — skipping"
fi

# ── 3. load env ──────────────────────────────────────────────────────────────
if [[ -f "$TARGET_DIR/.env" ]]; then
  # shellcheck disable=SC1090
  set -a; source "$TARGET_DIR/.env"; set +a
fi

DB_CONTAINER="${POSTGRES_CONTAINER:-auth_rs_db_postgres}"
DB_USER="${POSTGRES_USER:-auth}"
DB_NAME="${POSTGRES_DB:-auth}"

# ── 4. start postgres only ───────────────────────────────────────────────────
echo "[restore] starting postgres ..."
(cd "$TARGET_DIR" && docker compose up -d postgres)

echo "[restore] waiting for postgres to be healthy ..."
for i in $(seq 1 30); do
  STATUS="$(docker inspect --format='{{.State.Health.Status}}' "$DB_CONTAINER" 2>/dev/null || echo 'missing')"
  if [[ "$STATUS" == "healthy" ]]; then
    echo "[restore] postgres healthy"
    break
  fi
  [[ $i -eq 30 ]] && echo "[error] postgres did not become healthy in 30s" && exit 1
  echo "  ... ($i/30) status=$STATUS"
  sleep 1
done

# ── 5. restore dump ──────────────────────────────────────────────────────────
DUMP="$STAGE/postgres.dump.sql"
if [[ -f "$DUMP" ]]; then
  echo "[restore] restoring database dump ..."
  # Drop and recreate DB (idempotent)
  docker exec "$DB_CONTAINER" \
    psql -U "$DB_USER" -d postgres -c "
      SELECT pg_terminate_backend(pid)
        FROM pg_stat_activity
       WHERE datname = '$DB_NAME' AND pid <> pg_backend_pid();
      DROP DATABASE IF EXISTS $DB_NAME;
      CREATE DATABASE $DB_NAME OWNER $DB_USER;
    " --quiet
  docker exec -i "$DB_CONTAINER" \
    psql -U "$DB_USER" -d "$DB_NAME" --quiet < "$DUMP"
  echo "[restore] database restored"
else
  echo "[warn] no postgres.dump.sql in archive — skipping DB restore"
fi

# ── 6. start all services ────────────────────────────────────────────────────
echo "[restore] starting all services ..."
(cd "$TARGET_DIR" && docker compose up -d)

echo ""
echo "[restore] done. running containers:"
docker compose -f "$TARGET_DIR/docker-compose.yaml" ps
