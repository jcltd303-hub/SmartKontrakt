# Incidents 2021–2026 — what the detectors cover, and what they can't

The six-year record, one row per loss the corpus pins. Each entry is either a
rule (with a fixture in `src/lib/audit/incidents-2021-2026.test.ts`) or a
recorded gap with the reason no source rule can close it.

Five detectors were added for this sweep, for classes the 2026 work did not
reach: `arbitrary-dispatch-call`, `bridge-message-auth`,
`governance-live-voting-power`, `ecrecover-zero`, `oracle-staleness`.

## Covered by a rule

| Year | Incident | Loss | Detector | Mechanism |
| --- | --- | --- | --- | --- |
| 2021 | Poly Network | $611M | `arbitrary-dispatch-call` | The manager executed a caller-supplied target and `_method`; a brute-forced 4-byte selector reached the keeper-update function |
| 2021 | Cream Finance | $130M | `reentrancy` | ERC-777 `tokensReceived` hook re-entered the borrow path |
| 2021 | Yearn yDAI | $11M | `oracle-spot` | The strategy priced off live pool reserves |
| 2022 | Nomad Bridge | $190M | `bridge-message-auth` | `committedRoot` initialised to `0x00`, so every proof verified |
| 2022 | BNB Bridge (Token Hub) | $586M | `bridge-message-auth` | A forged proof released funds; the handler trusted caller-supplied proof material |
| 2022 | Beanstalk Farms | $182M | `governance-live-voting-power` | `emergencyCommit` read live Silo weight; a flash loan rented 2/3 in one transaction |
| 2022 | Mango Markets | $114M | `oracle-spot` | Mark price from a thin book the attacker moved |
| 2022 | *signature class* | family | `ecrecover-zero` | `ecrecover` returns `address(0)` and the code compares it without rejecting zero |
| 2023 | Euler Finance | $197M | `balance-as-price` | `donateToReserves` moved the balances the health check priced off |
| 2023 | KyberSwap | $47M | `div-before-mul` | Tick math divided before multiplying; the rounding doubled a position |
| 2023 | BonqDAO | $120M | `oracle-spot` | A single manipulable feed was the only collateral check |
| 2023 | *price plumbing* | family | `oracle-staleness` | `latestRoundData()` without `updatedAt`/`answeredInRound` |
| 2024 | Shezmu | $4.9M | `unprotected-initializer` | `initialize()` callable by anyone on the proxy |
| 2025 | Cetus | $223M | `unchecked-block` | Arithmetic overflow in CLMM math (Move in reality; the Solidity shape is an unchecked multiply) |
| 2025 | Cork Protocol | $12M | `hook-callback-auth` | `beforeSwap` never checked the caller was the PoolManager |
| 2025 | Abracadabra | $13M | `reentrancy` | GMX cauldron integration re-entered before debt was booked |
| 2026 | BlockChainCasino | free option | `settlement-optionality` | Settle a win, refund a loss; nothing forces settlement |
| 2026 | AlpsCon AI Trade Hub | $152.8k | `public-key-account-trust` | The reward gate whitelisted the published-key Hardhat account |

Plus the 2026 wave already documented in `docs/recent-exploits-2026.md`
(hook callbacks, calldata offsets, EIP-7702 guards, batch executors,
self-attested auth) and the games work in `docs/games-2026.md`.

## Recorded gaps — no source rule can see these

| Year | Incident | Loss | Why no rule |
| --- | --- | --- | --- |
| 2022 | Ronin Bridge | $625M | Five of nine validator keys compromised by social engineering |
| 2022 | Wormhole | $326M | Rust program bug on Solana (skipped sysvar/ownership check) |
| 2022 | Harmony Horizon | $100M | 2-of-5 multisig keys compromised |
| 2022 | Qubit Finance | $80M | `deposit()` accepted unvalidated input and minted; the entry is a plain deposit, so `bridge-message-auth` deliberately does not match it — widening the handler vocabulary would fire on every vault |
| 2023 | Curve / Vyper | $70M | The **source was correct**; the Vyper compiler (0.2.15–0.3.0) assigned different slots to reentrancy locks. Compiler-version hygiene is all a source tool can say |
| 2023 | Multichain | $125M+ | Admin keys held centrally; CEO arrested |
| 2023 | Mixin Network | $200M | Cloud database breach exposed keys |
| 2024 | Radiant Capital | $50M | Malware on signer machines; the signed payload was malicious but valid |
| 2024 | Orbit Chain | $82M | MPC signing keys compromised |
| 2024 | Hedgey Finance | $45M | Per-position share accounting across two functions — the class this repo leaves to a human read, because a pattern match on share debits fires on every correct vault |
| 2024 | WazirX | $235M | Multisig compromise |
| 2025 | Bybit | $1.46B | Safe{Wallet} frontend compromised; signers approved a delegatecall substitution |
| 2025 | Balancer V2 | $128M | Reported as pool logic; no public root cause sufficient to encode a rule |

This is not a shortcoming of the detector set so much as the shape of the loss
distribution. Halborn's Top-100 study puts compromised private keys at 27% of
attacks and 32.6% of value lost across its sample, and off-chain causes at
34.6% of funds stolen — rising to 56.5% of attacks and 57.5% of the stolen
amount in 2023 alone. For 2026 the same pattern held at the top of the table:
Drift ($285M) was pre-signed authority obtained by social engineering and
KelpDAO (~$290M) was a single-DVN configuration fed false data.

A code audit does not cover keys, signers, frontends or compilers, and the
corpus says so rather than implying coverage.

## What the numbers in this table are

Reported losses as published by the trackers and post-mortems, not figures
recomputed from chain state. Where sources disagree the row uses the most
commonly cited figure. Two entries are classes rather than single incidents
(`ecrecover-zero`, `oracle-staleness`) because the mechanism recurred across
years and no one incident is the canonical case.

## Verification

- `incidents-2021-2026.test.ts` — 32 cases: 18 rule entries fire, 4 controls
  stay quiet, 9 gaps are recorded with a reason, plus three structural tests
  (every year 2021–2026 has ≥2 entries, every named detector exists in
  `SMARTBUGS_BY_DETECTOR`, and the documented-only set contains the specific
  incidents a reader would expect).
- Harnesses 54–58, one per new detector, all passing
  `scripts/single-guess-lint.mjs` with zero errors and the structure test
  (SPDX, pragma, fork-only, no broadcast, `POC_TARGET` from env).
- `index.json`, the harness files and the registry agree: 59 harnesses listed
  and on disk, every claimed detector resolves to a category, all ten
  SmartBugs categories covered.
- Whole-suite comparison against the previous commit shows no regressions.
- `ANALYZER_BASELINE` bumped to `2026-10-27.4`.

Two caveats, as before. The checks that import TypeScript directly
(`npm run check:detectors`, and three cases in
`scripts/verify-poc-fallbacks.test.mjs`) cannot run in this sandbox — its Node
build has no `--experimental-strip-types` — so their logic was verified by hand
and CI runs them properly. And the fixtures are minimised reconstructions of
each mechanism, not the deployed bytecode: they prove the rule fires on the
shape, not that a PoC reproduces against the original contract.
