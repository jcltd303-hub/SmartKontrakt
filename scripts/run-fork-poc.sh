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
#   ETH_RPC_URL    Upstream RPC to fork from (default: https://eth.llamarpc.com,
#                  the same public mainnet endpoint the app uses for bytecode fetches)
#   POC_ANVIL_PORT Port for the local anvil sandbox (default: 8545)
#
# Safety: fork-only. Anvil serves a local copy of chain state; nothing is
# broadcast, nothing is spent, no private key is needed or accepted.
set -euo pipefail

TARGET="${1:-}"
TEST_FILE="${2:-test/PoC.t.sol}"
BLOCK="${3:-}"
RPC_URL="${ETH_RPC_URL:-https://eth.llamarpc.com}"
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

# --- Start the anvil fork sandbox --------------------------------------------
ANVIL_LOG="$(mktemp -t smartkontrakt-anvil.XXXXXX.log)"
ANVIL_PID=""

cleanup() {
  if [[ -n "$ANVIL_PID" ]] && kill -0 "$ANVIL_PID" 2>/dev/null; then
    kill "$ANVIL_PID" 2>/dev/null || true
    wait "$ANVIL_PID" 2>/dev/null || true
  fi
  rm -f "$ANVIL_LOG"
}
trap cleanup EXIT INT TERM

ANVIL_ARGS=(--fork-url "$RPC_URL" --port "$PORT")
if [[ -n "$BLOCK" ]]; then
  ANVIL_ARGS+=(--fork-block-number "$BLOCK")
fi
echo "Starting anvil fork sandbox on $ANVIL_URL (upstream: $RPC_URL${BLOCK:+ @ block $BLOCK})..."
anvil "${ANVIL_ARGS[@]}" >"$ANVIL_LOG" 2>&1 &
ANVIL_PID=$!

# Wait for anvil to answer eth_blockNumber (max ~30s).
READY=0
for _ in $(seq 1 30); do
  if ! kill -0 "$ANVIL_PID" 2>/dev/null; then
    echo "error: anvil exited early. Log:" >&2
    cat "$ANVIL_LOG" >&2
    exit 1
  fi
  if curl -s -m 2 -X POST -H "Content-Type: application/json" \
      --data '{"jsonrpc":"2.0","id":1,"method":"eth_blockNumber","params":[]}' \
      "$ANVIL_URL" >/dev/null 2>&1; then
    READY=1
    break
  fi
  sleep 1
done
if [[ "$READY" -ne 1 ]]; then
  echo "error: anvil did not come up on $ANVIL_URL within 30s. Log:" >&2
  cat "$ANVIL_LOG" >&2
  exit 1
fi

# --- Run the PoC --------------------------------------------------------------
echo "Running forge test (target=$TARGET, file=$TEST_FILE, fork=anvil @ $ANVIL_URL)..."
cd "$FOUNDRY_DIR"
# forge exits 0 when NO tests match --match-path, so an `if forge ...; then
# PASS` verdict is a false PASS when the test file is missing or has no
# test functions. Capture output and fail loudly on zero matches.
FORGE_LOG="$(mktemp -t smartkontrakt-forge.XXXXXX.log)"
FORGE_STATUS=0
POC_TARGET="$TARGET" POC_FORK_BLOCK="${BLOCK:-0}" POC_RPC_URL="$ANVIL_URL" \
  forge test --fork-url "$ANVIL_URL" --match-path "$TEST_FILE" -vvv >"$FORGE_LOG" 2>&1 || FORGE_STATUS=$?
cat "$FORGE_LOG"
if grep -q "no tests match" "$FORGE_LOG"; then
  rm -f "$FORGE_LOG"
  echo "FAIL: no tests matched $TEST_FILE — the file is missing or has no test functions. 0 exploit tests ran." >&2
  exit 1
fi
rm -f "$FORGE_LOG"
if [[ $FORGE_STATUS -ne 0 ]]; then
  echo "FAIL: PoC test(s) in $TEST_FILE did not reproduce (or the harness errored)." >&2
  echo "Check the output above: a failing exploit assertion means the exploit did not reproduce on fork state." >&2
  exit 1
fi
echo "PASS: PoC test(s) in $TEST_FILE reproduced against the fork."
