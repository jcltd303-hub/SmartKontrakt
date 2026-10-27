# The games work — D1, D2, D3

Plan §3b. Eight weak-randomness games were audited in depth and **seven were
not exploitable** — and not one of them failed for the reason the entropy
detectors were looking at. That is the finding this document records: the
detectors were answering a question the games were not asking.

What shipped: the gate now reports its **kind** (D1), a new detector for the
**free option** (D2), and a marker for logic that lives in a sub-contract (D3).

## D1 — precondition gates

"Unguarded" was hiding six different situations. `ReachabilityVerdict` now
carries `gate: GATED_MODIFIER | GATED_REQUIRE | GATED_PRECONDITION | UNGATED`,
and a `GATED_PRECONDITION` site carries its precondition text verbatim
(`Finding.preconditions`), because that text is the difference between
"unreachable" and "reachable at a cost".

| Precondition kind | Evidence tested inside a `require`/`if` condition | Game |
| --- | --- | --- |
| `token-holding` | `balanceOf(msg.sender) > 0`, `ownerOf(...)` | KatWalkerz (needs **both** collections) |
| `allowlist` | `isExcludedFromFees[msg.sender]`, `whitelist[...]`, `verified[...]` | HPBD |
| `signature` | `ecrecover`, `ECDSA.recover`, `isValidSignature` | TorpedoLaunchGame |
| `eoa-only` | `tx.origin == msg.sender` | POT token, Gana Payment |
| `contract-only` | `msg.sender == game` (contract-shaped name) | Lottery1ETH / 10ETH |
| `round-fill` | `players.length >= 2`, `ticketCount == N` | the lottery pair |
| `live-threshold` | `address(this).balance >= moonLevel`, `totalStaked >= ...` | TwoCoins (16 ETH vs 0.101 ETH) |
| `privileged-role` | `onlyOwner`, `hasRole(` | MyDice75, HNDGame |

Two details matter more than the list:

- **Preconditions are tested against guard spans, never the whole body.** A
  `balanceOf(msg.sender)` inside an `emit` is not a gate, and treating it as
  one files a reachable function as unreachable — the failure this whole plan
  is about, in the other direction.
- **A contract-shaped caller is not a privileged one.** `require(msg.sender ==
  game)` previously matched the privileged-party guard and came out as
  `GATED_REQUIRE`. It is now a `contract-only` precondition, which is what made
  the Lottery1ETH/10ETH pair read as an owner-only game.

`isGatedAtCost(verdict)` exists so triage can rank a precondition gate above a
privileged one: buying an NFT is a different obstacle from being the owner.

## D2 — settlement optionality

Detector `settlement-optionality`. This is the only genuinely profitable case
in the eight, and it is invisible to every entropy rule.

BlockChainCasino's randomness is sound — `commit = keccak256(reveal)` binds the
reveal, so it cannot be ground, and the entropy detector was right to stop. The
flaw is one hop later:

```
settleBet(reveal, blockHash)   -> pays the win
refundBet(commit)              -> returns the FULL stake after BET_EXPIRATION_BLOCKS
```

Win → settle. Lose → refund. The loss is free, so the bet is a **call option on
the win condition**, worth more the more often the game pays. Nothing on the
house side forces settlement, so the player simply waits out the timeout.

The rule fires on a contract with (a) a caller-initiated settle path that pays
out, (b) a caller-initiated refund path that pays the stake back and mentions a
timeout, and (c) no privileged forced settlement. All three are needed: a
refund with no timeout is a cancel, and a house-side force-settle closes the
option.

Severity is capped at **high with a note**, deliberately. The magnitude is a
live read — per-bet cap, timeout length, bankroll — and publishing a figure
from source constants is exactly the F-14 400x error the plan exists to stop.
Harness `53-settlement-optionality.t.sol` judges on the observable (the stake is
back in the player's balance after a rolled timeout), not on a refund call
returning.

## D3 — registry-dispatched logic

Detector `registry-dispatched-logic`, marked `SEMANTICS_UNVERIFIED`.

`CasinoDrainer` computed `mask & (1 << (entropy % modulo))` — correct for
`CoinAndRoulette`, except that contract dispatches to whatever sits at
`gameAddress[gameId]`. A non-standard game makes the win check wrong while the
exploit still "runs". The finding says so rather than guessing: the win rule
lives in the registered implementation, fetch it before stating a verdict.

The detector follows the alias, because real code hoists the slot first:

```solidity
address game = gameAddress[gameId];
(bool ok,) = game.call{value: msg.value}(…);   // ← the dispatch
```

It declares no harness. There is nothing to execute against the reporting
contract — the harness would have to be written against the sub-contract once
its source is fetched — so `index.json` lists it under `notPocable` with that
reason, which is the honest treatment rather than a template that cannot judge
anything.

## Verification

`src/lib/audit/games-2026.test.ts` — 20 cases, all passing:

- **all eight games classified automatically**, each asserting both class and
  gate kind: KatWalkerz `GATED/GATED_PRECONDITION`, MyDice75
  `GATED/GATED_MODIFIER`, TwoCoins `GATED/GATED_PRECONDITION` (live
  threshold), TorpedoLaunchGame `GATED/GATED_PRECONDITION` (signature),
  Lottery1ETH `GATED/GATED_PRECONDITION` (contract-only), HNDGame
  `GATED/GATED_MODIFIER`, BlockChainCasino `REACHABLE/UNGATED`,
  CoinAndRoulette `REACHABLE/UNGATED`;
- the D1 vocabulary, including the two negatives that matter: a `balanceOf` in
  an `emit` is not a gate, and a privileged modifier is not "gated at cost";
- D2 against the casino shape plus three controls (forced settlement, refund
  without timeout, settle-only);
- D3 against the registry shape plus a fixed-callee control.

Whole-suite comparison against the previous commit shows no regressions.

**Two honest caveats.** TwoCoins is classified from its live-threshold gate,
but whether 16 ETH is ever reached is a live read — the classifier says
"gated on a balance threshold", not "dead". And the eight-game result is
8/8 *by classification*, not 8/8 by exploitability: the corpus asserts that
the analyzer now reaches the same verdict a human did, which is the metric the
plan sets, and it does not claim a PoC was run against any of them.
