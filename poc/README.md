# poc/ — proofs that need no Foundry

## refund-option.mjs — the settlement option in BlockChainCasino

Proves, from the chain's own data and with **no EVM execution**, that the operator
holds a free option on every bet in `0x6eb0e558…5f0be` (a dice2.win derivative):

- `settleBet(reveal, blockHash)` is the only path that pays a **win**, and `reveal`
  is the preimage of the `commit` that `secretSigner` signed — only the operator
  knows it.
- `refundBet(commit)` is permissionless but pays exactly `bet.totalAmount`: the
  stake.
- So on any bet the house would lose, the operator simply never settles. After
  `BET_EXPIRATION_BLOCKS` (250, ~50 minutes) the gambler is refunded their own
  money. The gambler's upside is capped at zero; the house cannot lose.
- Because `settleBet` is permissionless, the inverse also matters: if `reveal` is
  low-entropy, a gambler can brute-force `commit = keccak256(abi.encodePacked(uint256 reveal))`
  and settle their own winning bets. That is the only way this game is winnable.

```bash
./poc/run-refund-option.sh 0x6eb0e558140025cb740f99979613a0876685f0be
```

That is the whole command — no key, no node, no Foundry. It reads logs from the
Blockscout explorer API, which is keyless and archive-capable.

Public JSON-RPC endpoints now refuse `eth_getLogs` over old ranges without a paid
token ("Archive requests require a personal token"), which is why the default is not
RPC.

The chain head is read from `?module=block&action=eth_block_number`, falling back to
`/api/v2/stats` (`total_blocks`) and then `/api/v2/main-page/blocks` — all three
shapes verified against the live API. The deployment block comes from
`/api/v2/addresses/{addr}` → `creation_transaction_hash` → `gettxinfo` →
`result.blockNumber`.

The explorer refuses a single query spanning millions of blocks ("Something went
wrong."), so the range is walked in windows — starting at 2,000,000 blocks and
shrinking by 4× whenever the explorer refuses, down to a 1,000-block floor, with a
request cap. `--from` now defaults to the contract's **deployment block**, read from
the explorer, so it does not scan from genesis. Override the window with
`POC_LOG_WINDOW=<blocks>` and the floor with `POC_LOG_MIN_WINDOW=<blocks>`.

If you do have an endpoint that will serve `getLogs`:

```bash
SOURCE=rpc RPC_URL="$YOUR_RPC" FROM_BLOCK=<deployment block> ./poc/run-refund-option.sh 0x…
```

A credential goes in the environment, never in a file or a commit. Providers differ
on how they want it — put it in `RPC_URL` if it goes in the path, or in
`RPC_HEADERS` if it goes in a header:

```bash
RPC_HEADERS="Authorization: Bearer $TOKEN" SOURCE=rpc RPC_URL=… ./poc/run-refund-option.sh 0x…
```

### Blockscout PRO key (the `proapi_…` prefix)

Blockscout's **PRO API requires a key on every tier including free**; only the
per-instance route (`eth.blockscout.com/api?module=…`) is keyless, and that is the
one being changed by v12. PRO exposes a JSON-RPC endpoint with archive depth, which
is the better path — no window chunking, and `eth_getTransactionByHash` supplies the
calldata:

```bash
export BS_TOKEN=proapi_…          # never in a file, never in a commit
SOURCE=rpc \
RPC_URL=https://api.blockscout.com/1/json-rpc \
RPC_HEADERS="Authorization: Bearer $BS_TOKEN" \
FROM_BLOCK=10455555 \
./poc/run-refund-option.sh 0x6eb0e558140025cb740f99979613a0876685f0be
```

Free tier: 100K credits/day at 5 RPS, and `addresses/:hash/logs` costs 30 credits, so
a run is a few hundred credits. `apikey=<token>` as a query parameter works too, if
you prefer it to the header.

Measured on this endpoint (2026-10-27): `eth_blockNumber` 461 ms, `eth_getLogs` at
block 10,455,555 returns 200 with zero logs — archive depth is there. `eth_getLogs`
at the **tip** returns HTTP 500 "Internal server error" while a window two blocks
back is fine, so the walk stops two blocks short of the head. Those two blocks are
not indexed yet; for a historical audit they cost nothing.

## leak-check.mjs — did a failed settle publish a live reveal?

A reverted transaction still publishes its calldata, and `settleBet(reveal, blockHash)`
carries the reveal in the clear. So a settlement that **fails** hands the preimage to
anyone reading the chain. That is only a vulnerability if the bet was still inside its
250-block window at that moment; a retry against an already-settled bet leaks nothing
of value.

```bash
node poc/leak-check.mjs --address 0x6eb0…5f0be \
  --rpc https://api.blockscout.com/1/json-rpc \
  --headers "Authorization: Bearer $BS_TOKEN" \
  --txs 0x38b8…,0x7c7c…,0x3fd2…
```

or `--txlist` to pull the failed transactions from the explorer itself.

Each failed call is classified, not counted:

| verdict | meaning |
| --- | --- |
| `never placed` | the reveal matches no bet — a typo, or a commit never placed |
| `already processed` | `totalAmount == 0`: settled or refunded before this attempt |
| `expired` | past `placeBlock + 250` when it failed |
| **`LIVE`** | inside the window and still unprocessed — **the reveal leaked while the bet was claimable** |

Only `LIVE` is a finding. The script says which case it found in plain words, so it
cannot be quoted as the stronger claim when the answer is the weaker one.

## anvil-partition.sh — the settle/refund window, on a local chain

Foundry only: `anvil`, `cast`, `forge`. No Node, no RPC keys, nothing live.

```bash
CASINO_SRC=/path/to/BlockChainCasino.sol ./poc/anvil-partition.sh
```

It deploys the casino and a `MockGame`, sets `secretSigner` to anvil's second key,
signs a commit, places one 0.01 ETH bet, then walks the window and asserts:

| block | expected |
| --- | --- |
| B+250 | `settleBet` **succeeds**, `refundBet` reverts "Blockhash can't be queried by EVM" |
| B+251 | `settleBet` reverts with the same message, `refundBet` **succeeds** and pays `bet.totalAmount` |

**What that proves:** after 250 blocks an unsettled bet can never be collected by the
house — the settle path is closed permanently and the only terminal outcome is the
stake going back to the gambler.

**What it does not prove, and what is not true:** that a gambler can *force* that.
`settleBet` has no access control and no caller check, so the operator settles its own
wins inside the window whatever the gambler waits for. The window is a property of the
code; who wins is a property of who holds the `reveal`.

> Note: this script was written without an anvil available to run it against. Every
> assertion is explicit and exits non-zero on a surprise, but treat the first run as a
> test of the script itself. If a step fails, the message says which.

### Probe an endpoint before trusting it

```bash
node poc/probe-rpc.mjs 0x6eb0e558140025cb740f99979613a0876685f0be --deploy 10455555
```

A plain `eth_blockNumber` answers happily on endpoints that refuse `eth_getLogs`
outright, which is how an endpoint gets graded healthy and then returns an empty
result that reads as "no bets". The probe runs the **real filter** — your address and
the `Commit` topic — at the head, at the deployment block, and over a 2,000-block
window, and prints what each one actually said. It never echoes the credential.

Known limits, measured 2026-10-24: publicnode refuses a start more than ~10,000
blocks behind the head (`-32602`, "Archive requests require a personal token")
whatever the window width — a depth rule, not a width one. `rpc.mevblocker.io`
served a 26,262,495-block window on a narrow filter in 305 ms, keyless.

Needs `node >= 18`; `js-sha3` is already a repo dependency (`npm ci`). Read-only:
nothing is signed or sent. Output JSON lands in `poc/out/`.

### Measuring the settled outcomes (`--outcomes`)

Expiry alone does not tell you whether the operator declined a winner. This does:

```bash
SOURCE=rpc RPC_URL=https://api.blockscout.com/1/json-rpc \
RPC_HEADERS="Authorization: Bearer $BS_TOKEN" \
./poc/run-refund-option.sh 0x6eb0…5f0be --outcomes
```

For each settled bet it recomputes the game result instead of inferring it:
`blockhash(placeBlockNumber)` is the block's own hash, so
`entropy = keccak256(reveal ‖ blockHash)` is reproducible off-chain, and
`gameAddress(gameId).game(mask, modulo, entropy, amount − edge − fee)` returns the
win as a view call. It also **self-checks**: the recomputed total must equal the
`totalWin` the `Game` event reported. A mismatch means the derivation is wrong and
nothing downstream should be believed — that is printed, not swallowed.

Output:

| Line | Meaning |
| --- | --- |
| `gambler won` / `gambler lost` | across settled bets, recomputed |
| `self-check N/M` | recomputed totals that match the event |
| `mismatches` | bets where they did not, with both numbers |

### Reading the output

| Line | Meaning |
| --- | --- |
| `decoded N placeBet transactions` | bets reconstructed from calldata |
| `settled … stake S paid out W` | bets the operator chose to settle, and what they paid |
| `unsettled … stake S` | bets that expired — value the gambler could only get back, never win |
| `% of decoded stake expired` | the exposure the option creates |
| `under 64 bits` / `duplicates` / `sequential` | the reveal is guessable, so the gambler can settle their own wins |
| `source` | `blockscout` (keyless, default) or `rpc` |

A large `unsettled` share is the finding. `under 64 bits 0`, `duplicates 0`,
`sequential 0` means the operator's entropy is sound and only the option remains.

### Scope, honestly

This proves the mechanism and quantifies the exposure. It does **not** execute the
EVM, so it cannot demonstrate a reentrant drain — because there isn't one:
`refundBet` clears `bet.totalAmount` before any external call and pays with
`.send()` (2300 gas). A PoC claiming reentrancy there is chasing a bug that isn't
in the code.

### Tested against a fake explorer

`refund-option.test.mjs` builds `placeBet` calldata and `Game` event data the way
the contract does, serves them from a local fake Blockscout (v1 logs + v2
`raw_input`), and asserts the classification — so the ABI decoding is verified, not
assumed. It also pins the two failure modes that actually bit: an RPC that refuses
archive logs must fail loudly rather than report zero bets, and an address with no
code must be rejected.

```bash
node --test poc/refund-option.test.mjs     # 8 tests
```
