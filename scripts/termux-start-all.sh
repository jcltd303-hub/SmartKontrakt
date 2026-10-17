#!/usr/bin/env bash
# Start every SmartKontrakt backend part on the phone with one command.
#
# Run in proot (NOT plain Termux):
#   cd ~/SmartKontrakt && git pull && bash scripts/termux-start-all.sh
#
# Starts:
#   - Foundry PoC backend  (termux-backend/server.mjs)  on 127.0.0.1:8787
#   - Pipeline worker      (pipeline-worker/worker.ts)   on 127.0.0.1:8788
#
# Services already running are left alone. Logs go to /tmp/smartkontrakt-logs/.
# This script boots the services only — it does NOT start the 43k-address
# run. The run command is printed at the end; run it when ready.
#
# Before this, in a plain Termux session (not proot), run:
#   termux-wake-lock
# so Android does not kill the backends.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."
export PATH="$HOME/.foundry/bin:$PATH"
# llamrpc (eth.llamarpc.com) is dead (HTTP 525) — default to PublicNode.
export ETH_RPC_URL="${ETH_RPC_URL:-https://ethereum.publicnode.com}"
LOGDIR="${LOGDIR:-/tmp/smartkontrakt-logs}"
mkdir -p "$LOGDIR"

command -v node >/dev/null 2>&1 || { echo "error: node not found in proot" >&2; exit 1; }
if ! command -v forge >/dev/null 2>&1; then
  echo "warning: forge not found — PoC backend will report forge:false. Run bash scripts/termux-setup.sh first." >&2
fi

wait_for() { # wait_for <url> <label> <seconds>
  local url="$1" label="$2" tries="${3:-30}" i=0
  until curl -s -m 2 -o /dev/null "$url" 2>/dev/null; do
    i=$((i + 1))
    if [[ $i -ge $tries ]]; then
      echo "error: $label did not answer $url within ${tries}s — see $LOGDIR" >&2
      return 1
    fi
    sleep 1
  done
  echo "$label up: $url"
}

# --- Foundry PoC backend :8787 ---------------------------------------------
if curl -s -m 2 http://127.0.0.1:8787/health >/dev/null 2>&1; then
  echo "PoC backend already up (:8787)"
else
  nohup node termux-backend/server.mjs >"$LOGDIR/poc-backend.log" 2>&1 &
  echo "PoC backend starting (:8787) — log $LOGDIR/poc-backend.log"
fi

# --- Pipeline worker :8788 ---------------------------------------------------
if curl -s -m 2 http://127.0.0.1:8788/status >/dev/null 2>&1; then
  echo "Worker already up (:8788)"
else
  nohup npx -y tsx pipeline-worker/worker.ts >"$LOGDIR/worker.log" 2>&1 &
  echo "Worker starting (:8788) — log $LOGDIR/worker.log"
fi

echo "--- status ---"
wait_for "http://127.0.0.1:8787/health" "PoC backend" 30 || true
curl -s http://127.0.0.1:8787/health; echo
wait_for "http://127.0.0.1:8788/status" "Worker" 60 || true
curl -s http://127.0.0.1:8788/status | head -c 600; echo

echo "--- to start the 43k-address run (when ready) ---"
echo "curl -s -X POST http://127.0.0.1:8788/start -H 'Content-Type: application/json' -d '{\"addressesFile\":\"/root/addresses.csv\",\"chainId\":\"ethereum\",\"aiSecondPass\":true,\"delayMs\":600}'"
echo "(If /start rejects aiSecondPass, the OpenRouter key is missing from pipeline-worker/.env — retry with aiSecondPass:false.)"
