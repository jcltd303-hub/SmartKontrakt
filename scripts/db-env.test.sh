#!/usr/bin/env bash
# Tests for scripts/db-env.sh — run directly: bash scripts/db-env.test.sh
set -uo pipefail
pass=0; fail=0
ok()   { pass=$((pass+1)); printf 'ok   %s\n' "$1"; }
bad()  { fail=$((fail+1)); printf 'FAIL %s\n' "$1"; }

TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/pipeline-worker" "$TMP/scripts"
cp "$(dirname "$0")/db-env.sh" "$TMP/scripts/"
cat > "$TMP/pipeline-worker/.env" <<'ENV'
# a comment
DATABASE_URL="postgres://u:sekrit@host.pooler.supabase.com:6543/postgres"
export SUPABASE_URL=https://x.supabase.co
OPENROUTER_API_KEY='sk-or-xyz'
ENV

# 1. exported to a child process (the whole point)
n=$(cd "$TMP" && bash -c 'source scripts/db-env.sh >/dev/null; env | grep -c "^DATABASE_URL="')
[ "$n" = "1" ] && ok "DATABASE_URL reaches a child process" || bad "not exported (child saw $n)"

# 2. a plain source does NOT export — the distinction the script exists for
n=$(cd "$TMP" && bash -c 'source pipeline-worker/.env; env | grep -c "^DATABASE_URL="')
[ "$n" = "0" ] && ok "a plain source leaves it unexported (so psql would miss it)" || bad "plain source exported ($n)"

# 3. quotes are stripped
v=$(cd "$TMP" && bash -c 'source scripts/db-env.sh >/dev/null; printf %s "$DATABASE_URL"')
case "$v" in *'"'*|*"'"*) bad "quotes survived: $v" ;; *) ok "quotes stripped" ;; esac

# 4. --direct rewrites the pooler port, and only then
d=$(cd "$TMP" && bash -c 'source scripts/db-env.sh --direct >/dev/null; printf %s "$DATABASE_URL"')
case "$d" in *:5432*) ok "--direct rewrites 6543 -> 5432" ;; *) bad "--direct did not rewrite: $d" ;; esac
p=$(cd "$TMP" && bash -c 'source scripts/db-env.sh >/dev/null; printf %s "$DATABASE_URL"')
case "$p" in *:6543*) ok "default leaves the pooler port alone" ;; *) bad "default changed the port: $p" ;; esac

# 5. --check never prints the password
out=$(cd "$TMP" && bash scripts/db-env.sh --check 2>&1)
case "$out" in *sekrit*) bad "--check leaked the password" ;; *) ok "--check masks the password" ;; esac
case "$out" in *"***"*) ok "--check shows a masked URL" ;; *) bad "--check has no masked URL" ;; esac

# 6. a missing env file fails with a usable message, not a silent no-op
rm "$TMP/pipeline-worker/.env"
out=$(cd "$TMP" && bash scripts/db-env.sh --check 2>&1); rc=$?
[ "$rc" != "0" ] && ok "missing env file exits non-zero" || bad "missing env file exited 0"
case "$out" in *"env.example"*) ok "missing env file names the fix" ;; *) bad "unhelpful message: $out" ;; esac

printf '\n%d passed, %d failed\n' "$pass" "$fail"
[ "$fail" = "0" ]
