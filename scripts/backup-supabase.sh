#!/usr/bin/env bash
# backup-supabase.sh — dump the SmartKontrakt archive to a local file.
#
#   bash scripts/backup-supabase.sh                 # custom-format dump (recommended)
#   bash scripts/backup-supabase.sh --sql           # plain .sql instead
#   bash scripts/backup-supabase.sh --schema-only   # structure, no rows
#   bash scripts/backup-supabase.sh --dry-run       # print the command, run nothing
#
# Reads DATABASE_URL (or DIRECT_URL). The transaction pooler cannot be used for a
# dump — pg_dump needs a session, and Supabase's pooler on 6543 is transaction
# mode, so the script rewrites 6543 to 5432 and says so. Use the direct
# connection string from the Supabase dashboard if 5432 on the pooler host is not
# enabled on your plan.
set -euo pipefail

FORMAT=custom
SCHEMA_ONLY=""
DRY_RUN=0
OUT_DIR="${OUT_DIR:-backups}"

while [ $# -gt 0 ]; do
  case "$1" in
    --sql)          FORMAT=plain ;;
    --schema-only)  SCHEMA_ONLY="--schema-only" ;;
    --dry-run)      DRY_RUN=1 ;;
    -h|--help)      sed -n '2,17p' "$0"; exit 0 ;;
    *) echo "unknown flag: $1" >&2; exit 2 ;;
  esac
  shift
done

if ! command -v pg_dump >/dev/null 2>&1; then
  echo "pg_dump not found. Install the client (no server needed):" >&2
  echo "  Ubuntu/Debian: apt install -y postgresql-client" >&2
  echo "  macOS:         brew install libpq && brew link --force libpq" >&2
  exit 1
fi

SRC_URL="${DIRECT_URL:-${DATABASE_URL:-}}"
if [ -z "$SRC_URL" ]; then
  echo "DATABASE_URL (or DIRECT_URL) is not set. It lives in pipeline-worker/.env:" >&2
  echo "  set -a; . pipeline-worker/.env; set +a" >&2
  exit 1
fi

# Supabase's pooler host on 6543 is TRANSACTION mode: pg_dump fails there
# ("prepared statement ... does not exist" or a mid-dump disconnect) because it
# relies on a session. Rewrite to 5432, which is the session pooler on the same
# host, and tell the operator.
DUMP_URL="$SRC_URL"
case "$SRC_URL" in
  *pooler.supabase.com:6543*)
    DUMP_URL="${SRC_URL/\.pooler\.supabase\.com:6543/.pooler.supabase.com:5432}"
    echo "[backup] DATABASE_URL is the transaction pooler (6543) — pg_dump needs a" >&2
    echo "[backup] session, so dumping over 5432 on the same host instead." >&2
    ;;
esac

mkdir -p "$OUT_DIR"
STAMP="$(date +%Y-%m-%dT%H%M)"
if [ "$FORMAT" = "plain" ]; then
  OUT="$OUT_DIR/smartkontrakt-${STAMP}${SCHEMA_ONLY:+-schema}.sql"
else
  OUT="$OUT_DIR/smartkontrakt-${STAMP}${SCHEMA_ONLY:+-schema}.dump"
fi

# --no-owner / --no-privileges: Supabase role names (postgres,
# authenticated, anon, service_role) do not exist on a local restore target, and
# a dump that insists on them fails there. --no-comments keeps it portable too.
TMP="$OUT.part"
ARGS=(--no-owner --no-privileges --no-comments)
if [ "$FORMAT" = "plain" ]; then
  ARGS+=(--format=plain --file="$TMP")
else
  ARGS+=(--format=custom --compress=9 --file="$TMP")
fi
[ -n "$SCHEMA_ONLY" ] && ARGS+=("$SCHEMA_ONLY")

echo "[backup] -> $OUT"
if [ "$DRY_RUN" = "1" ]; then
  # The URL is redacted in the printed command on purpose.
  printf '[backup] pg_dump %s %s\n' "${ARGS[*]}" "$(printf '%s' "$DUMP_URL" | sed -E 's#://[^@]*@#://***@#')"
  exit 0
fi

start=$(date +%s)
# A failed dump must not leave a file behind: an empty .dump sitting in the
# backup directory is worse than no backup, because it looks like one.
if ! pg_dump "$DUMP_URL" "${ARGS[@]}"; then
  rm -f "$TMP"
  echo "[backup] FAILED: pg_dump could not complete. Nothing was written." >&2
  exit 1
fi
elapsed=$(( $(date +%s) - start ))

# A dump that "succeeded" but wrote nothing is the failure worth catching: an
# empty or missing DATABASE_URL, or a connection that fell back to a fresh
# database, both produce a valid empty file.
SIZE=$(wc -c < "$TMP" | tr -d ' ')
if [ "$SIZE" -lt 1000 ]; then
  rm -f "$TMP"
  echo "[backup] FAILED: the dump was ${SIZE} bytes — that is not a real backup." >&2
  echo "[backup] Check DATABASE_URL points at the project database, not a fresh one." >&2
  exit 1
fi
mv "$TMP" "$OUT"

echo "[backup] done in ${elapsed}s, $(numfmt --to=iec "$SIZE" 2>/dev/null || echo "${SIZE}B")"
if [ "$FORMAT" = "custom" ]; then
  OBJECTS=$(pg_restore -l "$OUT" 2>/dev/null | grep -vc '^;' || true)
  echo "[backup] $OBJECTS restorable objects. Verify with: pg_restore -l '$OUT' | head"
  echo "[backup] restore with:  pg_restore --clean --if-exists -d \"\$DATABASE_URL\" '$OUT'"
else
  echo "[backup] restore with:  psql \"\$DATABASE_URL\" -v ON_ERROR_STOP=1 -f '$OUT'"
fi
