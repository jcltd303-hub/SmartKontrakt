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

Needs `node >= 18`; `js-sha3` is already a repo dependency (`npm ci`). Read-only:
nothing is signed or sent. Output JSON lands in `poc/out/`.

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
