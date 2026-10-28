#!/usr/bin/env bash
# poc/anvil-partition.sh
#
# Prove the settle/refund partition of BlockChainCasino on a local anvil chain.
# Foundry only — no Node, no solc-js, no RPC keys.
#
#   ./poc/anvil-partition.sh
#
# What it proves, and what it does not:
#
#   PROVES   settleBet succeeds at B+250 and reverts at B+251
#            ("Blockhash can't be queried by EVM")
#            refundBet reverts at B+250 ("Blockhash can't be queried by EVM")
#            and succeeds at B+251, paying exactly bet.totalAmount
#            => after 250 blocks the house can never collect that bet
#
#   DOES NOT PROVE  "the gambler can force that". settleBet has no access control,
#            so the operator settles losses inside the window regardless of what the
#            gambler waits for. The partition is a fact about the code; who wins is a
#            fact about who holds the reveal.
#
# Requires: anvil, cast, forge (Foundry). Exits non-zero on the first surprise.

set -euo pipefail
cd "$(dirname "$0")/.."

RPC=${RPC:-http://127.0.0.1:8545}
PORT=${PORT:-8545}
# anvil's first two well-known keys. Local chain only, obviously.
OWNER_KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
SIGNER_KEY=0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d
OWNER=$(cast wallet address --private-key $OWNER_KEY)
SIGNER=$(cast wallet address --private-key $SIGNER_KEY)

step() { printf '\n== %s\n' "$*"; }
fail() { printf 'FAILED: %s\n' "$*" >&2; exit 1; }
expect_revert() { # expect_revert <label> <needle> <cast args…>
  local label=$1 needle=$2; shift 2
  local out
  if out=$(cast "$@" 2>&1); then
    fail "$label — expected a revert, but it succeeded"
  fi
  case "$out" in
    *"$needle"*) printf '  ok: %s reverted with "%s"\n' "$label" "$needle" ;;
    *) fail "$label — reverted, but not with \"$needle\": $out" ;;
  esac
}
expect_ok() { # expect_ok <label> <cast args…>
  local label=$1; shift
  local out
  if out=$(cast "$@" 2>&1); then
    printf '  ok: %s succeeded\n' "$label"
  else
    fail "$label — expected success, got: $out"
  fi
}

# ---------------------------------------------------------------- chain -----
step "chain"
if ! cast chain-id --rpc-url "$RPC" >/dev/null 2>&1; then
  echo "  no anvil on $RPC — starting one"
  anvil --port "$PORT" --silent &
  ANVIL_PID=$!
  trap 'kill $ANVIL_PID 2>/dev/null || true' EXIT
  for _ in $(seq 1 50); do
    cast chain-id --rpc-url "$RPC" >/dev/null 2>&1 && break
    sleep 0.2
  done
fi
cast chain-id --rpc-url "$RPC" >/dev/null 2>&1 || fail "no chain at $RPC"
echo "  rpc $RPC  chain $(cast chain-id --rpc-url "$RPC")"
echo "  owner  $OWNER"
echo "  signer $SIGNER"

# ---------------------------------------------------------------- build -----
step "build (own forge root, solc 0.4.26 — the source is pragma ^0.4.24)"
CASINO_SRC=${CASINO_SRC:-poc/forge/src/BlockChainCasino.sol}
[ -f "$CASINO_SRC" ] || fail "set CASINO_SRC=/path/to/BlockChainCasino.sol (the verified source)"
# `--root poc/forge` keeps forge away from test/fixtures/**, which needs solc 0.4.9
# through 0.8.30 and forge-std remappings this repo does not have. Building from the
# repo root fails there long before it reaches the PoC.
mkdir -p poc/forge/src
cp "$CASINO_SRC" poc/forge/src/BlockChainCasino.sol
cp poc/mocks/*.sol poc/forge/src/ 2>/dev/null || true
forge build --root poc/forge >/dev/null || fail "forge build --root poc/forge failed"

deploy() { # deploy <ContractName> [args…]
  local name=$1; shift
  local out
  out=$(forge create --root poc/forge --broadcast --rpc-url "$RPC" --private-key "$OWNER_KEY" \
        "$name" "$@" 2>&1) || { echo "$out" >&2; fail "deploy $name"; }
  echo "$out" | grep -oE 'Deployed to: 0x[a-fA-F0-9]{40}' | awk '{print $3}'
}

step "deploy casino + mock game"
# No constructor arguments: owner = msg.sender, secretSigner = DUMMY_ADDRESS.
CASINO=$(deploy BlockChainCasino)
GAME=$(deploy MockGame)
echo "  casino $CASINO"
echo "  game   $GAME"

step "configure"
cast send --rpc-url "$RPC" --private-key "$OWNER_KEY" "$CASINO" "setSecretSigner(address)" "$SIGNER" >/dev/null
cast send --rpc-url "$RPC" --private-key "$OWNER_KEY" "$CASINO" "setGameContract(uint256,address)" 0 "$GAME" >/dev/null
cast send --rpc-url "$RPC" --private-key "$OWNER_KEY" "$CASINO" --value 5ether >/dev/null  # bankroll
echo "  signer set, game 0 -> $GAME, bankroll 5 ETH"

# ---------------------------------------------------------------- bet -------
step "build a signed commit"
REVEAL=12345678901234567890
REVEAL_WORD=$(printf '0x%064x' "$REVEAL")
COMMIT=$(cast keccak "$REVEAL_WORD")
COMMIT_LAST_BLOCK=$(( $(cast block-number --rpc-url "$RPC") + 100 ))
# abi.encodePacked(uint40 commitLastBlock, uint256 commit) is 5 + 32 = 37 bytes.
# A 32-byte word here hashes a different message and every signature fails ecrecover.
LAST_PACKED=$(printf '0x%010x' "$COMMIT_LAST_BLOCK")
DIGEST=$(cast keccak "${LAST_PACKED}${COMMIT#0x}")
SIG=$(cast wallet sign --no-hash --private-key "$SIGNER_KEY" "$DIGEST")
SIG=${SIG#0x}
R=0x${SIG:0:64}
S=0x${SIG:64:64}
V=$(cast to-dec 0x${SIG:128:2})
[ "$V" -ge 27 ] || V=$(( V + 27 ))
echo "  commit $COMMIT"
echo "  v=$V"

step "placeBet (0.01 ETH, mask 7, modulo 6)"
cast send --rpc-url "$RPC" --private-key "$OWNER_KEY" "$CASINO" \
  "placeBet(uint8,uint256[],uint256[],uint8,uint256,uint256,uint8,bytes32,bytes32)" \
  0 "[7]" "[10000000000000000]" 6 "$COMMIT_LAST_BLOCK" "$COMMIT" "$V" "$R" "$S" \
  --value 0.01ether >/dev/null
PLACED=$(cast block-number --rpc-url "$RPC")
BLOCKHASH=$(cast block "$PLACED" --field hash --rpc-url "$RPC")
echo "  placed in block $PLACED  (blockhash $BLOCKHASH)"

# ---------------------------------------------------------------- window ----
step "at B+250: settle must work, refund must not"
cast rpc --rpc-url "$RPC" anvil_mine $(printf '0x%x' 249) >/dev/null
NOW=$(cast block-number --rpc-url "$RPC")
[ "$NOW" -eq $((PLACED + 250)) ] || fail "expected block $((PLACED + 250)), at $NOW"
expect_ok "settleBet at B+250" call --rpc-url "$RPC" "$CASINO" \
  "settleBet(uint256,bytes32)" "$REVEAL" "$BLOCKHASH"
expect_revert "refundBet at B+250" "Blockhash can't be queried by EVM" \
  call --rpc-url "$RPC" "$CASINO" "refundBet(uint256)" "$COMMIT"

step "at B+251: settle is closed forever, refund pays the stake"
cast rpc --rpc-url "$RPC" anvil_mine 0x1 >/dev/null
NOW=$(cast block-number --rpc-url "$RPC")
[ "$NOW" -eq $((PLACED + 251)) ] || fail "expected block $((PLACED + 251)), at $NOW"
expect_revert "settleBet at B+251" "Blockhash can't be queried by EVM" \
  call --rpc-url "$RPC" "$CASINO" "settleBet(uint256,bytes32)" "$REVEAL" "$BLOCKHASH"
BEFORE=$(cast balance "$OWNER" --rpc-url "$RPC")
expect_ok "refundBet at B+251" send --rpc-url "$RPC" --private-key "$OWNER_KEY" \
  "$CASINO" "refundBet(uint256)" "$COMMIT"
AFTER=$(cast balance "$OWNER" --rpc-url "$RPC")
echo "  owner balance delta: $(echo "$AFTER - $BEFORE" | bc) wei (gas paid, stake refunded to the gambler)"

step "state after refund"
cast call --rpc-url "$RPC" "$CASINO" "getBet(uint256)(uint256,uint256[],uint256,uint8,uint40,uint40[],uint8,address)" "$COMMIT" \
  | head -3

printf '\nPARTITION PROVED:\n'
printf '  settleBet open in [B+1, B+250], closed from B+251\n'
printf '  refundBet open from B+251, pays bet.totalAmount\n'
printf '  => an unsettled bet can never be collected by the house\n'
printf '\nNOT proved, and not true: that a gambler can force this. settleBet has no\n'
printf 'access control — the operator settles its own wins inside the window.\n'
