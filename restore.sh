#!/usr/bin/env bash
# restore.sh — restore an auth backup archive on the target server
# Usage: ./restore.sh [-y|--yes] <backup.tar.gz> [target-dir]
#   target-dir defaults to the directory containing this script.
#   -y/--yes skips the confirmation prompt (for automation).
#
# Env overrides:
#   POSTGRES_CONTAINER — postgres container name (default: auth_rs_db_postgres,
#     shared by both docker-compose.yaml and docker-compose.dev.yaml)
#
# Steps:
#   1. Extract archive, show a summary, and confirm before touching anything
#   2. Copy env / keys / compose / nginx to target-dir (timestamped .bak of existing)
#   3. Start postgres via `compose up -d --wait`, verify connectivity
#   4. Stop the auth container, safety-dump + drop/recreate + replay the DB dump
#   5. Start remaining services

set -euo pipefail
umask 077

ASSUME_YES=0
ARGS=()
for arg in "$@"; do
  case "$arg" in
    -y|--yes) ASSUME_YES=1 ;;
    *) ARGS+=("$arg") ;;
  esac
done

ARCHIVE="${ARGS[0]:-}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET_DIR="${ARGS[1]:-$SCRIPT_DIR}"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
DB_CONTAINER="${POSTGRES_CONTAINER:-auth_rs_db_postgres}"

if [[ -z "$ARCHIVE" || ! -f "$ARCHIVE" ]]; then
  echo "Usage: $0 [-y|--yes] <backup.tar.gz> [target-dir]"
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

# Every top-level regular file in the stage (except the DB dump) is a config
# file to restore — this is the single source of truth, so backup.sh and
# restore.sh can't drift on a hardcoded filename list.
CONFIG_FILES=()
while IFS= read -r fname; do
  CONFIG_FILES+=("$fname")
done < <(find "$STAGE" -maxdepth 1 -type f ! -name 'postgres.dump.sql' -exec basename {} \;)
DUMP="$STAGE/postgres.dump.sql"

# ── confirmation summary ─────────────────────────────────────────────────────
DATA_DIR="$TARGET_DIR/data"
DATA_DIR_STALE=0
if [[ -d "$DATA_DIR" ]] && [[ -n "$(ls -A "$DATA_DIR" 2>/dev/null)" ]]; then
  DATA_DIR_STALE=1
fi

echo ""
echo "[restore] ── summary ─────────────────────────────────────────"
echo "  archive:       $ARCHIVE"
echo "  target dir:    $TARGET_DIR"
echo "  db container:  $DB_CONTAINER"
echo "  config files:  ${CONFIG_FILES[*]:-none}"
[[ -f "$DUMP" ]] && echo "  db dump:       yes ($(wc -c < "$DUMP") bytes) — target DB will be DROPPED and recreated"
if [[ ${#CONFIG_FILES[@]} -gt 0 ]]; then
  for f in "${CONFIG_FILES[@]}"; do
    [[ -f "$TARGET_DIR/$f" ]] && echo "  will overwrite: $f (backed up to $f.bak.$TIMESTAMP)"
  done
fi
if [[ "$DATA_DIR_STALE" -eq 1 ]]; then
  echo "  !! WARNING: $DATA_DIR already exists and is non-empty."
  echo "  !! postgres only runs initdb on an EMPTY data dir — it will boot the"
  echo "  !! EXISTING cluster there, and the restored .env credentials may not"
  echo "  !! match it. If this is unexpected, abort and move/remove $DATA_DIR first."
fi
echo "[restore] ──────────────────────────────────────────────────────"
echo ""

if [[ "$ASSUME_YES" -ne 1 ]]; then
  REPLY=""
  # Probe /dev/tty openability in a subshell: redirections there don't persist,
  # and `-r /dev/tty` alone is not enough (the node exists even with no
  # controlling terminal, e.g. under CI/pipes).
  if ( : </dev/tty ) 2>/dev/null; then
    read -r -p "Type 'yes' to proceed: " REPLY </dev/tty
  else
    read -r -p "Type 'yes' to proceed: " REPLY
  fi
  if [[ "$REPLY" != "yes" ]]; then
    echo "[restore] aborted."
    exit 1
  fi
fi

# ── 1. copy config files ─────────────────────────────────────────────────────
if [[ ${#CONFIG_FILES[@]} -gt 0 ]]; then
  for f in "${CONFIG_FILES[@]}"; do
    if [[ -f "$TARGET_DIR/$f" ]]; then
      echo "[restore] backing up existing $f → $f.bak.$TIMESTAMP"
      cp "$TARGET_DIR/$f" "$TARGET_DIR/$f.bak.$TIMESTAMP"
    fi
    cp "$STAGE/$f" "$TARGET_DIR/$f"
    echo "[restore] restored $f"
  done
fi

# ── 2. keys ──────────────────────────────────────────────────────────────────
if [[ -d "$STAGE/keys" ]]; then
  mkdir -p "$TARGET_DIR/keys"
  cp -r "$STAGE/keys/." "$TARGET_DIR/keys/"
  chmod 600 "$TARGET_DIR/keys"/*.pem 2>/dev/null || true
  echo "[restore] restored keys/"
else
  echo "[warn] no keys/ in archive — skipping"
fi

# ── 3. start postgres, wait for healthy ──────────────────────────────────────
echo "[restore] starting postgres ..."
(cd "$TARGET_DIR" && docker compose up -d --wait postgres)

# Read credentials from the container's own environment — compose already
# parsed $TARGET_DIR/.env natively and injected them; no need to re-parse it.
DB_USER="$(docker exec "$DB_CONTAINER" sh -c 'printf %s "$POSTGRES_USER"')"
DB_NAME="$(docker exec "$DB_CONTAINER" sh -c 'printf %s "$POSTGRES_DB"')"

echo "[restore] verifying connectivity ($DB_USER@$DB_NAME) ..."
if ! docker exec "$DB_CONTAINER" psql -U "$DB_USER" -d postgres -c "SELECT 1" >/dev/null 2>&1; then
  echo "[error] could not connect to postgres as '$DB_USER'."
  echo "[error] this usually means $DATA_DIR held a pre-existing cluster whose"
  echo "[error] credentials don't match the restored .env. Move/remove $DATA_DIR"
  echo "[error] and re-run, or fix the credentials, then retry."
  exit 1
fi

# ── 4. restore dump ──────────────────────────────────────────────────────────
if [[ -f "$DUMP" ]]; then
  echo "[restore] stopping auth container to avoid migration races ..."
  docker stop auth_rs 2>/dev/null || true

  EXISTS="$(docker exec "$DB_CONTAINER" psql -U "$DB_USER" -d postgres -v ON_ERROR_STOP=1 -tAc \
    "SELECT 1 FROM pg_database WHERE datname = '$DB_NAME'")"
  if [[ "$EXISTS" == "1" ]]; then
    SAFETY_DUMP="$TARGET_DIR/pre_restore_${DB_NAME}_${TIMESTAMP}.sql.gz"
    echo "[restore] safety-dumping existing '$DB_NAME' → $SAFETY_DUMP"
    docker exec "$DB_CONTAINER" pg_dump -U "$DB_USER" -d "$DB_NAME" --no-password \
      | gzip > "$SAFETY_DUMP"
    echo "[restore] pre-restore safety dump saved: $SAFETY_DUMP"
  fi

  echo "[restore] dropping and recreating '$DB_NAME' ..."
  docker exec "$DB_CONTAINER" psql -U "$DB_USER" -d postgres -v ON_ERROR_STOP=1 --quiet -c \
    "DROP DATABASE IF EXISTS \"$DB_NAME\" WITH (FORCE)"
  docker exec "$DB_CONTAINER" psql -U "$DB_USER" -d postgres -v ON_ERROR_STOP=1 --quiet -c \
    "CREATE DATABASE \"$DB_NAME\" OWNER \"$DB_USER\""

  echo "[restore] replaying database dump ..."
  docker exec -i "$DB_CONTAINER" \
    psql -U "$DB_USER" -d "$DB_NAME" -v ON_ERROR_STOP=1 --single-transaction --quiet < "$DUMP"
  echo "[restore] database restored"
else
  echo "[warn] no postgres.dump.sql in archive — skipping DB restore"
fi

# ── 5. start all services ────────────────────────────────────────────────────
echo "[restore] starting all services ..."
(cd "$TARGET_DIR" && docker compose up -d)

echo ""
echo "[restore] done. running containers:"
(cd "$TARGET_DIR" && docker compose ps)
