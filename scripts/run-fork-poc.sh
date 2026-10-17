#!/usr/bin/env bash
# Run a SmartKontrakt Foundry PoC against a local anvil fork of live chain state.
#
# Usage:
#   ./scripts/run-fork-poc.sh <target-address> [test-file] [fork-block-number]
#
#   <target-address>   0x-address of the contract under audit (required)
#   [test-file]        Test file to run, relative to foundry/ (default: test/PoC.t.sol)
#   [fork-block-number] Pin the fork to this block (default: latest)
#
# Env:
#   ETH_RPC_URL    Upstream RPC tried FIRST; on failure the script rotates
#                  through PublicNode, drpc, 1rpc.io, Cloudflare, llamrpc.
#                  (Default with no ETH_RPC_URL: the same list, PublicNode first.)
#   POC_ANVIL_PORT Port for the local anvil sandbox (default: 8545)
#
# Safety: fork-only. Anvil serves a local copy of chain state; nothing is
# broadcast, nothing is spent, no private key is needed or accepted.
set -euo pipefail

TARGET="${1:-}"
TEST_FILE="${2:-test/PoC.t.sol}"
BLOCK="${3:-}"
PORT="${POC_ANVIL_PORT:-8545}"
ANVIL_URL="http://127.0.0.1:${PORT}"

usage() {
  echo "Usage: $0 <target-address> [test-file] [fork-block-number]" >&2
  echo "  e.g. $0 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2" >&2
  echo "       $0 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2 test/PoC.t.sol 19000000" >&2
}

# --- Validate inputs ---------------------------------------------------------
if [[ -z "$TARGET" ]]; then
  echo "error: missing <target-address>" >&2
  usage
  exit 2
fi
if ! [[ "$TARGET" =~ ^0x[0-9a-fA-F]{40}$ ]]; then
  echo "error: target must be a 0x address (40 hex chars), got: $TARGET" >&2
  exit 2
fi
if [[ -n "$BLOCK" ]] && ! [[ "$BLOCK" =~ ^[0-9]+$ ]]; then
  echo "error: fork-block-number must be a non-negative integer, got: $BLOCK" >&2
  exit 2
fi
if ! command -v forge >/dev/null 2>&1; then
  echo "error: 'forge' not found. Install Foundry: curl -L https://foundry.paradigm.xyz | bash && foundryup" >&2
  exit 2
fi
if ! command -v anvil >/dev/null 2>&1; then
  echo "error: 'anvil' not found. Install Foundry: curl -L https://foundry.paradigm.xyz | bash && foundryup" >&2
  exit 2
fi
if ! command -v curl >/dev/null 2>&1; then
  echo "error: 'curl' not found (needed to probe the anvil sandbox)" >&2
  exit 2
fi

# Resolve repo paths: this script lives in <repo>/scripts/, the harness in <repo>/foundry/.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FOUNDRY_DIR="${SCRIPT_DIR}/foundry"
if [[ ! -d "$FOUNDRY_DIR" ]]; then
  echo "error: foundry project not found at $FOUNDRY_DIR" >&2
  exit 2
fi

# Refuse to run if something already answers on the sandbox port — we must
# not run a PoC against a stranger's node.
if curl -s -m 2 -o /dev/null "$ANVIL_URL"; then
  echo "error: something already listens on port $PORT ($ANVIL_URL). Stop it or set POC_ANVIL_PORT." >&2
  exit 2
fi

# --- RPC rotation ------------------------------------------------------------
# ETH_RPC_URL (if set) first, then the provider list — same order as the
# backend/worker: PublicNode, drpc, 1rpc.io, Cloudflare, llamrpc (dead,
# kept last in case it comes back). A dead RPC rotates to the next
# provider instead of failing the run.
RPC_CANDIDATES=()
if [[ -n "${ETH_RPC_URL:-}" ]]; then RPC_CANDIDATES+=("$ETH_RPC_URL"); fi
for _rpc in "https://ethereum.publicnode.com" "https://eth.drpc.org" "https://1rpc.io/eth" "https://cloudflare-eth.com" "https://eth.llamarpc.com"; do
  _seen=0
  for _have in "${RPC_CANDIDATES[@]}"; do [[ "$_have" == "$_rpc" ]] && _seen=1 && break; done
  [[ $_seen -eq 0 ]] && RPC_CANDIDATES+=("$_rpc")
done
unset _rpc _seen _have

# Does this log smell like an RPC/transport failure (worth rotating for)?
is_rpc_error() {
  grep -qiE "HTTP error|failed to (fetch|get).*chain|failed to fetch|error sending request|connection (refused|reset|aborted|timed? ?out)|timed? ?out|rate ?limit|too many requests|\b429\b|\b502\b|\b503\b|\b504\b|\b525\b|failed to (instantiate|create).*fork|fork.*failed|provider.*(error|failed)|eth_chainId" "$1" 2>/dev/null
}

stop_anvil() {
  if [[ -n "$ANVIL_PID" ]] && kill -0 "$ANVIL_PID" 2>/dev/null; then
    kill "$ANVIL_PID" 2>/dev/null || true
    wait "$ANVIL_PID" 2>/dev/null || true
  fi
  ANVIL_PID=""
}

# --- Start the anvil fork sandbox + run the PoC, rotating RPCs ---------------
ANVIL_LOG=""
ANVIL_PID=""

cleanup() {
  stop_anvil
  rm -f "$ANVIL_LOG"
}
trap cleanup EXIT INT TERM

cd "$FOUNDRY_DIR"
FORGE_LOG="$(mktemp -t smartkontrakt-forge.XXXXXX.log)"
LAST_RPC=""
for RPC_URL in "${RPC_CANDIDATES[@]}"; do
  LAST_RPC="$RPC_URL"
  echo "Trying RPC: $RPC_URL"
  ANVIL_LOG="$(mktemp -t smartkontrakt-anvil.XXXXXX.log)"
  ANVIL_ARGS=(--fork-url "$RPC_URL" --port "$PORT")
  if [[ -n "$BLOCK" ]]; then
    ANVIL_ARGS+=(--fork-block-number "$BLOCK")
  fi
  echo "Starting anvil fork sandbox on $ANVIL_URL (upstream: $RPC_URL${BLOCK:+ @ block $BLOCK})..."
  anvil "${ANVIL_ARGS[@]}" >"$ANVIL_LOG" 2>&1 &
  ANVIL_PID=$!

  # Wait for anvil to answer eth_blockNumber (max ~30s).
  READY=0
  ANVIL_DIED=0
  for _ in $(seq 1 30); do
    if ! kill -0 "$ANVIL_PID" 2>/dev/null; then ANVIL_DIED=1; break; fi
    if curl -s -m 2 -X POST -H "Content-Type: application/json" \
        --data '{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}' \
        "$ANVIL_URL" >/dev/null 2>&1; then
      READY=1
      break
    fi
    sleep 1
  done
  if [[ "$READY" -ne 1 ]]; then
    if [[ "$ANVIL_DIED" -eq 1 ]] || ! kill -0 "$ANVIL_PID" 2>/dev/null; then
      # Anvil exited early — rotate only if the log smells like RPC failure.
      if is_rpc_error "$ANVIL_LOG"; then
        echo "anvil failed on $RPC_URL (RPC error) — rotating to next provider..." >&2
        stop_anvil
        rm -f "$ANVIL_LOG"
        continue
      fi
      echo "error: anvil exited early. Log:" >&2
      cat "$ANVIL_LOG" >&2
      exit 1
    fi
    # Anvil alive but never answered — treat as RPC failure, rotate.
    echo "anvil did not answer on $ANVIL_URL within 30s — rotating to next provider..." >&2
    stop_anvil
    rm -f "$ANVIL_LOG"
    continue
  fi

  # --- Run the PoC ------------------------------------------------------------
  echo "Running forge test (target=$TARGET, file=$TEST_FILE, fork=anvil @ $ANVIL_URL)..."
  # forge exits 0 when NO tests match --match-path, so an `if forge ...; then
  # PASS` verdict is a false PASS when the test file is missing or has no
  # test functions. Capture output and fail loudly on zero matches.
  FORGE_STATUS=0
  POC_TARGET="$TARGET" POC_FORK_BLOCK="${BLOCK:-0}" POC_RPC_URL="$ANVIL_URL" \
    forge test --fork-url "$ANVIL_URL" --match-path "$TEST_FILE" -vvv >"$FORGE_LOG" 2>&1 || FORGE_STATUS=$?
  cat "$FORGE_LOG"
  stop_anvil
  rm -f "$ANVIL_LOG"
  if grep -q "no tests match" "$FORGE_LOG"; then
    rm -f "$FORGE_LOG"
    echo "FAIL: no tests matched $TEST_FILE — the file is missing or has no test functions. 0 exploit tests ran." >&2
    exit 1
  fi
  if [[ $FORGE_STATUS -eq 0 ]]; then
    rm -f "$FORGE_LOG"
    echo "PASS: PoC test(s) in $TEST_FILE reproduced against the fork. (RPC: $RPC_URL)"
    exit 0
  fi
  # Forge failed. Rotate only if it died before running tests with an
  # RPC-looking error — a test verdict (tests ran, pass or fail) is final,
  # and so is a compile error.
  if ! grep -q "Ran [0-9]* test" "$FORGE_LOG" && ! grep -qiE "error\[|Compiler run failed" "$FORGE_LOG" && is_rpc_error "$FORGE_LOG"; then
    echo "forge failed on $RPC_URL (RPC error) — rotating to next provider..." >&2
    continue
  fi
  rm -f "$FORGE_LOG"
  echo "FAIL: PoC test(s) in $TEST_FILE did not reproduce (or the harness errored)." >&2
  echo "Check the output above: a failing exploit assertion means the exploit did not reproduce on fork state." >&2
  exit 1
done
rm -f "$FORGE_LOG"
echo "FAIL: all RPC providers failed (last: $LAST_RPC)." >&2
exit 1
