# Detection upgrade — implementation record (2026-10-27)

This records what shipped from the engagement-derived detection plan, what was
already in place, and what is deliberately still open. The plan itself is the
source document; this file is the map from each of its phases to the code that
now implements it, so the next pass can measure against something concrete.

Baseline for the numbers quoted here: 488 addresses, 480 detector hits, 227
false positives (47%), 23 findings, and one genuinely bad contract — which was
a honeypot, not a vulnerability.

## Shipped

### Phase 0 — precision (P1–P10)

Most of P1–P6 and P8–P10 were already implemented, and the regression corpus
now pins them so a later edit cannot quietly undo one:

| Item | Where it lives now |
| --- | --- |
| P1 comments scanned as code | `stripCommentsAndStrings` / `…KeepLines` in `detect.ts`; pinned by corpus test P1 |
| P2 name-based taint too broad | `hashInputHasBlockData` requires block data *inside* the hash input; corpus P2 (EIP-712 permit) |
| P3 interface declarations | AST-based: `body === null` members never become sites; corpus P3 |
| P4 internal helpers as entries | `isExternallyCallable` + `computeEntries` provenance; corpus P4 (OZ `sendValue`) |
| P5 constructors by name | AST `isConstructor`; corpus P5 (0.5.x `function Phoenix()`) |
| P6 multi-line guards | whitespace-squashed guard matching; corpus P6 (KydyCore) |
| **P7 custom modifier names** | **new**: `LEARNED_GUARD_MODIFIERS` in `reachability.ts`, credited through `isExplicitGuardModifierName` in `isAuthed` |
| P8 inheritance not followed | base-chain resolution in `modifierGuardsSender` / `transitiveSources`; corpus P8 |
| P9 view/pure `.transfer(` | `mutability` excluded from ether-out analysis; corpus P9 |
| P10 `super.transfer(` | `super` calls are internal jumps, not external calls; corpus P10 |

The one real change here is **P7**, and its shape is deliberate: only names
that were actually read in the engagement (`ownerOnly`, `hasMintPermission`,
`isPlayer`, `treasuryOnly`, `oraclizeAction`, `checkAdmin`, `restricted`) are
credited as *proven* access control. A bare `onlyXxx` convention — `onlyBeacon`
in the Cub fixtures — stays a *possible* guard, so it caps at high with a note
naming it instead of clearing the finding. Crediting an unread guard as proven
suppresses a real finding, which is the more expensive error; the gate
generalization fixtures enforce that distinction and they still pass.

### Phase 1 — recall (R1–R3)

- **R1 Team Just five-field mixer** — `teamJustMixer` in `detect.ts`: a
  `keccak256` whose input carries `block.timestamp`/`now` **and**
  `block.difficulty`/`prevrandao` **and** `block.coinbase`/`block.gaslimit`.
  Three distinct block fields in one hash is the fingerprint. It reports at
  `high` confidence with its own title, because the shape is unambiguous.
- **R2 derived-value entropy** — `derivedEntropySelected`: follows the *output*
  of a block-data hash into a later statement and flags arithmetic, comparison,
  branch, ternary, or a selection-named sink. The identifier-only suppression
  is preserved: a hash used as a mapping key (`games[gameId]`) is still not a
  draw, and the corpus has that control.
- **R3 `block.prevrandao`** — already first-class in the entropy source; now
  pinned by a corpus test so it cannot regress.

### Phase 2 — coverage (C1, C2)

- **C1 second registry**: `fetchBlockscoutSource` in `address-fetcher.ts`, tried
  after Sourcify for chains with a public instance (mainnet, Optimism, Gnosis,
  Polygon, Base, Arbitrum). Every match now records which registry answered.
- **C2 "no source" is not "no analysis"**: `fetchBlockscoutIdentity` returns
  name, `is_contract`, `is_verified`, creation-bytecode presence, proxy type and
  implementations — served even for unverified contracts. A bytecode-only audit
  is labelled `Bytecode-analysed (…)` with a note stating exactly what was and
  was not covered, never `unreadable`.
- New limiter `blockscoutLimiter` keeps the fallback from becoming a bottleneck.

### Phase 3 — identity (C3)

`Inventory.verifiedName` and `Inventory.labelCheck` are now set on every
address audit: `label_ok`, `label_mismatch: …` (naming both the display label
and the verified name), or `label_unverified` on the bytecode path. A
dashboard/product name is reported next to the verified name, never instead of
it.

### Phase 4 — reachability adjudication

`src/lib/audit/reachability.ts` classifies a call site as `REACHABLE`,
`GATED`, `INTERNAL`, `BOUNDED` or `NEEDS_READ`, in that order of precedence:

- `INTERNAL` — internal/private with no public entry, or a constructor; a
  compilation that declares derived contracts makes it `NEEDS_READ` instead.
- `GATED` — a guard modifier, or a body check on `msg.sender` against a global
  privileged party. Per-asset ownership (`items[id].owner == msg.sender`) is
  explicitly *not* a gate: it bounds the flow instead.
- `NEEDS_READ` — a modifier whose meaning could not be resolved. Uncertainty
  costs a human read; it is never promoted to `REACHABLE`.
- `BOUNDED` — moves value, but the recipient is the caller or a fixed address
  and the amount is bounded by caller-owned accounting.
- `REACHABLE` — everything else, and the only class that becomes a finding.

`detectSource` now tags every finding whose function the model resolves with
this class (`Finding.reachability`). It is additive: no severity changes, no
finding dropped. Internal/private helper sites are left untagged on purpose,
because their findings are already attributed to their public entries.

## Not shipped, and why

- **Phase 5 (live-state economics)** — no code path in this repo publishes a
  hardcoded gas price or treats the contract balance as the pot; the F-14 400x
  and 20-gwei 87x errors were engagement-process failures, not defects in
  `gas-estimator.ts` or `value.ts`. What the plan asks for here is a *reporting
  discipline* (state the assumption set, compute from a live read) rather than
  a rule change, so nothing was invented to satisfy it.
- **Phase 6 (the frozen corpora)** — the 480-hit triage set, the 86-address
  weak-randomness set, the 18 no-source addresses and the 32 dashboard labels
  are engagement artefacts that are not in this repository. The *shape* of the
  corpus is implemented instead: `regression-corpus.test.ts` (20 fixtures
  covering P1–P10, R1–R3 and three positive controls) and
  `reachability.test.ts` (29 cases) run in the normal suite. Dropping the real
  artefacts into `test/fixtures/detection-upgrade/` and pointing the same tests
  at them is the remaining step, and it needs the data.
- **Ranking change** — the plan says stop ranking by detector score. The score
  is still computed; the reachability class is now available to order the read
  queue, but the UI has not been re-sorted around it. That is a workbench
  change, not a detector change.

## Measuring the result

The targets from the plan, and where each is observable:

| Metric | Now | Target | Where to measure |
| --- | --- | --- | --- |
| FP rate on the 480-hit corpus | 47% | < 20% | needs the triage artefacts |
| Recall on the 86-address set | 79.1% | > 90% | needs the address set |
| Addresses with no analysis | 45 | < 10 | `inventory.kindNote` + `labelCheck` on a fresh run |
| TRUEs needing a human read | 100% | < 40% | share of findings tagged `NEEDS_READ` |
| Published figures not reproducible from live state | several | 0 | `inventory.value` / `liveState` |
| Label accuracy | 23/32 | all mismatches surfaced | `inventory.labelCheck` |

## Verification performed for this change

- `reachability.test.ts` — 29 cases, all passing.
- `regression-corpus.test.ts` — 20 cases, all passing.
- `blockscout-fallback.test.ts` — 5 cases, all passing.
- Whole-suite comparison against the pre-change commit: every existing audit
  test file reports the same pass/fail counts as before (the files that fail in
  this environment fail for missing optional dependencies and network access,
  identically before and after). Two gate-generalization fixtures were caught
  by this comparison mid-implementation — a bare `onlyXxx` was briefly credited
  as proven — and fixed before commit.
