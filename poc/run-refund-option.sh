#!/usr/bin/env bash
# poc/run-refund-option.sh
#
# Runner for poc/refund-option.mjs — no Foundry, no anvil, no forge, no build.
# Needs: node >= 18 and one HTTPS JSON-RPC endpoint that can serve eth_getLogs.
#
#   ./poc/run-refund-option.sh 0x6eb0e558140025cb740f99979613a0876685f0be
#   RPC_URL=https://… FROM_BLOCK=19000000 ./poc/run-refund-option.sh 0x…
#
# Everything is a read. Nothing is signed, nothing is sent, no keys needed.

set -euo pipefail

ADDRESS="${1:-}"
if [ -z "$ADDRESS" ]; then
  echo "usage: $0 <address> [extra args…]" >&2
  echo "  env: SOURCE=blockscout|rpc (default blockscout — keyless, archive-capable)" >&2
  echo "       RPC_URL (only when SOURCE=rpc)" >&2
  echo "       FROM_BLOCK (default: 0), TO_BLOCK (default: latest), OUT_DIR, MAX_TXS" >&2
  exit 2
fi
shift || true

# Default source is the keyless explorer API: public RPCs now refuse eth_getLogs over
# old ranges without a paid token ("Archive requests require a personal token"), which
# made FROM_BLOCK=0 unusable. Set SOURCE=rpc and RPC_URL=… only if you have an endpoint
# that will serve getLogs.
SOURCE="${SOURCE:-blockscout}"
RPC_URL="${RPC_URL:-}"
FROM_BLOCK="${FROM_BLOCK:-0}"
TO_BLOCK="${TO_BLOCK:-latest}"
OUT_DIR="${OUT_DIR:-poc/out}"
MAX_TXS="${MAX_TXS:-400}"

cd "$(dirname "$0")/.."

# --- preflight ---------------------------------------------------------------
command -v node >/dev/null 2>&1 || { echo "node is required (>=18 for node:http + ESM)" >&2; exit 2; }
NODE_MAJOR="$(node -p 'process.versions.node.split(".")[0]')"
[ "$NODE_MAJOR" -ge 18 ] || { echo "node >= 18 required, found $(node -v)" >&2; exit 2; }

if [ ! -d node_modules/js-sha3 ]; then
  echo "js-sha3 is not installed — run: npm install js-sha3" >&2
  echo "(it is already a dependency of this repo; 'npm ci' is enough)" >&2
  exit 2
fi

mkdir -p "$OUT_DIR"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
JSON_OUT="$OUT_DIR/refund-option-${ADDRESS:0:10}-${STAMP}.json"

# --- reachability ------------------------------------------------------------
if [ "$SOURCE" = "rpc" ]; then
  if [ -z "$RPC_URL" ]; then
    echo "SOURCE=rpc needs RPC_URL" >&2
    exit 2
  fi
  echo "source:  rpc ($RPC_URL)"
  if ! curl -sS --max-time 15 -X POST "$RPC_URL" \
        -H 'content-type: application/json' \
        -d '{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}' \
        >/dev/null 2>&1; then
    echo "warning: eth_blockNumber probe failed; the script will report the real error" >&2
  fi
else
  echo "source:  blockscout (keyless)"
fi

# --- run ---------------------------------------------------------------------
echo "address: $ADDRESS"
echo "blocks:  $FROM_BLOCK .. $TO_BLOCK"
echo "----------------------------------------------------------------------"
set +e
node poc/refund-option.mjs \
  --address "$ADDRESS" \
  --source "$SOURCE" \
  ${RPC_URL:+--rpc "$RPC_URL"} \
  --from "$FROM_BLOCK" \
  --to "$TO_BLOCK" \
  --max-txs "$MAX_TXS" \
  --json "$JSON_OUT" \
  "$@"
STATUS=$?
set -e

echo "----------------------------------------------------------------------"
if [ "$STATUS" -eq 0 ]; then
  echo "result:  $JSON_OUT"
  echo
  echo "Reading the output:"
  echo "  'unsettled' stake that is a large share of the total is the finding —"
  echo "  those bets could never have been paid a win, only refunded."
  echo "  'under 64 bits', 'duplicates' or 'sequential' reveals mean the preimage"
  echo "  is guessable, so a gambler can settle their own wins instead."
else
  echo "failed with status $STATUS" >&2
fi
exit "$STATUS"
