#!/usr/bin/env bash
# scripts/db-env.sh — load the database environment for terminal work.
#
#   source scripts/db-env.sh          # export everything from pipeline-worker/.env
#   source scripts/db-env.sh --direct # same, but point at :5432 (pg_dump needs this)
#   bash    scripts/db-env.sh --check # verify without sourcing (masked URL + select 1)
#
# Why a script: the real env lives in pipeline-worker/.env, not the repo root. And a
# plain `source pipeline-worker/.env` SETS the variables without EXPORTING them — so
# `echo "$DATABASE_URL"` works in that shell while `psql "$DATABASE_URL"` (a child
# process) sees an empty string. Verified: after a plain source, `env` in a child shows
# zero DATABASE_URL lines; after this script, one. `set -a` is the part that matters.
#
# Nothing here prints a credential. --check masks the password.

set -o pipefail

_db_env_file="${DB_ENV_FILE:-pipeline-worker/.env}"
if [ ! -f "$_db_env_file" ]; then
  # Called with `source` from a different directory: resolve relative to the repo.
  _db_env_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
  if [ -f "$_db_env_root/pipeline-worker/.env" ]; then
    _db_env_file="$_db_env_root/pipeline-worker/.env"
  else
    echo "db-env: no env file. Looked for pipeline-worker/.env" >&2
    echo "db-env: copy pipeline-worker/.env.example and fill it in." >&2
    return 1 2>/dev/null || exit 1
  fi
fi

_want_direct=0
case "${1:-}" in
  --direct) _want_direct=1 ;;
  --check)  _check_only=1 ;;
esac

# Load every KEY=VALUE, skipping comments and blanks, tolerating `export ` and quotes.
set -a
while IFS= read -r _line || [ -n "$_line" ]; do
  _line="${_line#"${_line%%[![:space:]]*}"}"          # ltrim
  case "$_line" in ''|'#'*) continue ;; esac
  _line="${_line#export }"
  _key="${_line%%=*}"
  _val="${_line#*=}"
  [ "$_key" = "$_line" ] && continue                   # no '=' on the line
  case "$_val" in
    \"*\") _val="${_val#\"}"; _val="${_val%\"}" ;;
    \'*\') _val="${_val#\'}"; _val="${_val%\'}" ;;
  esac
  export "$_key=$_val"
done < "$_db_env_file"
set +a

# Supabase's pooler (6543) is for app traffic; pg_dump and long sessions need the
# direct port (5432). scripts/backup-supabase.sh does the same rewrite.
if [ "$_want_direct" = "1" ] && [ -n "${DATABASE_URL:-}" ]; then
  DATABASE_URL="${DATABASE_URL/:6543/:5432}"
  export DATABASE_URL
fi

_mask() {
  printf '%s' "$1" | sed -E 's#(://[^:]+:)[^@]+@#\1***@#'
}

if [ "${_check_only:-0}" = "1" ]; then
  echo "env file   $_db_env_file"
  echo "DATABASE_URL ${DATABASE_URL:-<unset>}" | sed -E 's#(://[^:]+:)[^@]+@#\1***@#'
  for _k in SUPABASE_URL SUPABASE_SERVICE_ROLE_KEY OPENROUTER_API_KEY; do
    eval "_v=\${$_k:-}"
    [ -n "$_v" ] && echo "$_k set (${#_v} chars)"
  done
  if command -v psql >/dev/null 2>&1; then
    if psql "$DATABASE_URL" -tAc 'select 1' >/dev/null 2>&1; then
      echo "psql       OK"
    else
      echo "psql       FAILED — wrong password, no SSL, or egress blocked"
    fi
  else
    echo "psql       not installed"
  fi
  exit 0
fi

# Interactive `source` path: report what happened, without the credential.
if [ -n "${DATABASE_URL:-}" ]; then
  echo "db-env: loaded $(basename "$_db_env_file") -> $( _mask "$DATABASE_URL" )"
  case "$DATABASE_URL" in
    *:6543*) [ "$_want_direct" = "1" ] || echo "db-env: on the pooler (:6543). Use --direct for pg_dump." ;;
  esac
else
  echo "db-env: file loaded but DATABASE_URL is empty — check $_db_env_file" >&2
fi

unset _line _key _val _db_env_file _want_direct _check_only _k _v 2>/dev/null
