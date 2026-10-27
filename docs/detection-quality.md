# Detection quality — the eight approved items

What changed after four commits of rules, and — more usefully — what the
measurement says about them.

## 1. A measured baseline (the headline)

`scripts/benchmark-smartbugs.ts` scores the detectors against **SmartBugs
Curated**: 143 contracts with hand-annotated DASP categories, vendored into
`test/fixtures/smartbugs-curated/` so the run is offline and deterministic.
`scripts/smartbugs-baseline.json` holds the committed numbers and the script
exits non-zero on any regression (recall down, precision down, or
findings-per-contract up). `smartbugs-benchmark.test.ts` runs it in the suite.

The first measurement, over the whole corpus:

| Category | Contracts | Predicted | TP | FN | FP | Recall | Precision |
| --- | --- | --- | --- | --- | --- | --- | --- |
| reentrancy | 31 | 28 | 2 | 29 | 26 | 0.065 | 0.071 |
| access_control | 18 | 87 | 17 | 1 | 70 | 0.944 | 0.195 |
| arithmetic | 15 | 3 | 0 | 15 | 3 | 0.000 | 0.000 |
| unchecked_low_level_calls | 52 | 40 | 26 | 26 | 14 | 0.500 | 0.650 |
| denial_of_service | 6 | 103 | 3 | 3 | 100 | 0.500 | 0.029 |
| bad_randomness | 8 | 19 | 7 | 1 | 12 | 0.875 | 0.368 |
| front_running | 4 | 0 | 0 | 4 | 0 | 0.000 | 0.000 |
| time_manipulation | 5 | 17 | 2 | 3 | 15 | 0.400 | 0.118 |
| short_addresses | 1 | 0 | 0 | 1 | 0 | 0.000 | 0.000 |
| other | 3 | 13 | 2 | 1 | 11 | 0.667 | 0.154 |

829 findings over 143 contracts — **5.8 per contract**. The engagement's
complaint was a 47% false-positive rate on 480 hits; this is the same disease,
measured in-house.

Three things this settles:

- **`arithmetic` recall is 0.** The dataset's 15 arithmetic contracts are 0.4.x
  overflows. `unchecked-block` looks for an `unchecked { }` block, which only
  exists from 0.8 — so the rule cannot see the class it claims. That is a real
  gap, not a corpus artefact, and it is now visible instead of assumed.
- **`reentrancy` recall is 0.065 while firing on 28 contracts.** The detector
  fires broadly and almost never on a contract the dataset labels reentrant —
  precision 0.071. Either the rule's evidence model does not match the classic
  shapes, or it fires on the wrong functions; either way, this is the number to
  move first.
- **`denial_of_service` precision is 0.029.** 103 contracts predicted against 6
  labelled. `locked-ether` alone fires 41 times with a 0.00 signal rate, and
  `eth-gas-stipend` fires 146 times (more than the corpus has contracts) at
  0.06.

The report (`docs/smartbugs-benchmark.md`) carries a noise-leader table so the
next pass knows where the attention is being spent.

## 2. Reachability is consumed, not just tagged

`sortFindingsForTriage()` orders REACHABLE → NEEDS_READ → BOUNDED → GATED →
INTERNAL, severity inside each; `reportableFindings()` returns only the
reachable class. The report itself now sorts by severity then reachability, so a
reachable finding leads its band. `detection-quality.test.ts` pins both, plus
the property that a clean control yields **no** REACHABLE finding — which is the
gate that makes the classifier worth having.

## 3. Fixtures are proven load-bearing

`scripts/detector-binding-check.mjs` renames each detector's emission in a copy
of `src/lib`, re-bundles the behavioural suites against it, and asserts a
fixture notices. Current result: **67 of 67 bound, 0 unbound** — every rule's
emission is depended on by at least one test.

Two things it taught me while being built, both worth recording:

- the repo's `"sideEffects": false` made esbuild drop the suite imports
  entirely, so the first version reported everything as "unbound" because no
  tests ran at all. A check that cannot fail is worse than no check; it now
  writes a `sideEffects: true` package.json into its work directory.
- `poc-fallbacks.test.ts` is deliberately excluded: it asserts the emitted set
  equals a hand-kept table, so it would notice any rename and make every rule
  look bound. The check measures whether a *behavioural* fixture depends on the
  rule.

A second, cheaper ratchet lives in the suite: every emitted detector must be
named by a fixture or sit on a debt list that may only shrink. It stands at 16
(`assembly-sstore`, `default-visibility`, `locked-ether`, `strict-balance`, …).

## 4. Findings are grouped by mechanism

`detector-registry.ts` gives every detector a family — 67 detectors, 11
families. `groupFindingsByFamily()` collapses a finding list into mechanism
groups ordered by whether they contain a reachable finding, so one contract with
six price-plumbing findings reads as one problem with six sub-points. This is
the mechanical version of "stop reporting counts as findings".

## 5. Confidence is derived, and `tx.origin` stopped being a gate

Findings now carry `confidenceBasis`: `resolved`, `unresolved-gate` (a modifier
the analyzer cannot see — caps at medium), `precondition-text` (gated on text —
caps at medium), or `file-level`. A rule may claim high confidence; the field
records what the evidence supported.

Building this exposed a genuine bug: `require(tx.origin == msg.sender)` matched
the privileged-party guard pattern, so every EOA-gated function was classified
as `GATED_REQUIRE` — an owner-only entry, which is the opposite of the truth. It
is now a precondition (`eoa-only`), which is what the plan's D1 asks for.

## 6. Money figures carry their basis

Any finding whose text contains a currency figure gets
`economicClaim: { figure, basis: "assumption" }` and a caution appended to its
summary. No rule can prove a live read, so the honest default is "assumption" —
the F-14 400x pot and the 87x gas overstatement both came from publishing a
source constant as a measurement. A consumer that renders the number must render
the basis.

## 7. Harness compilation in CI — already there

The `fallbacks` job already compiled every harness; the step name still said
"(46)" while the directory held 59. Fixed, and the count is no longer in the
title, because a step title is not a measurement.

## 8. One declaration per detector

`detector-registry.ts` is total over what the engine emits, and the tests assert
that. Making it total found **three phantom detectors**: `front-running`,
`short-address` and `external-contract-referencing` each had a PoC harness and a
SmartBugs category, and no rule ever emitted them — so no scan has ever produced
one. They are listed in `HARNESS_ONLY_DETECTORS` rather than given a family,
because a family would claim coverage that does not exist.

The full file split of `detect.ts` (~4,900 lines) is **not** done. The registry
gives the sustainable half — a new rule has one place to be declared and one
gate to pass — while the scanners stay where the model and helpers already live.
A mechanical split with no behaviour change is safe but large; it should be its
own commit, and I would rather not fold it into a change that also moved the
numbers.

## The four weaknesses, fixed (2026-10-27, second pass)

The list that used to be here. Each item is now closed, and the benchmark
measures the result.

| # | Was | Fix | Effect on the benchmark |
| --- | --- | --- | --- |
| 1 | `reentrancy` recall 0.065 / precision 0.071 | Pre-0.5 call syntax normalised in `unwrapCallee`: `.call.value(x)()` parses as a member access named `value`, so the walker called it an ordinary member call and no `kind: "call"` rule ever saw it | recall **0.710**, precision **0.407** |
| 2 | `eth-gas-stipend` (146 firings, 0.06 signal) and `locked-ether` (41, 0.00) voting for `denial_of_service` | Both are info severity and neither votes in the category table — they are presence notes, not vulnerability classes | `denial_of_service` precision 0.029 → 0.043, and its recall drop from 0.5 to 0.167 is the **truth**: those two were the only DoS hits |
| 3 | `arithmetic` recall 0.000 on 15 contracts | `unchecked-block` now also fires pre-0.8: a compound assignment on stored state with no SafeMath in the function, gated on the pragma floor | recall **0.867**, precision 0.203 |
| 4 | `front_running` and `short_addresses` had no rule at all | `front-running` implemented (ERC-20 approve race, answer-in-the-mempool) with a commit-reveal exemption; `short-address` retired with a reason | `front_running` recall 0 → 0.250 |

The single biggest win was #1, and it was found by measuring rather than by
reading: the same minimal contract fired `critical: reentrancy` in the modern
`.call{value: x}("")` form and produced **nothing** in the `.call.value(x)()`
form. That one normalisation also took `unchecked_low_level_calls` recall from
0.500 to **1.000** (precision 0.650 → 0.788), because pre-0.5 `call()`/
`send()` returns were invisible for the same reason.

### The price, stated

Noise rose from 5.797 to **7.091** findings per contract, and
`access_control` precision fell 0.195 → 0.177. That is the trade for +13
arithmetic true positives and +26 on `unchecked_low_level_calls`: revealing
calls that were invisible adds findings on contracts the dataset does not
label as well as on those it does. The benchmark test's ceiling was raised from
6.5 to 7.5 with the reason written next to it, so this cannot be re-baselined
silently.

### Recall-first loosening (2026-10-27)

Policy change, at the project owner's direction: **a missed actionable
vulnerability is worse than a false positive**, so a rule that is tight enough
to miss real incidents should be loosened rather than kept precise.

Four gates were loosened. Each keeps its evidence trail in the code with a
`LOOSENED 2026-10-27` comment, and the weaker cases report **low confidence** so
triage can still sort them:

| Rule | Was | Now also fires on | Why |
| --- | --- | --- | --- |
| `hook-callback-auth` | a v4 callback name | an ungated settlement entry (`accept`/`settle`/`close`/`execute`/`finalize`/`payout`/`redeem`) in a hook contract | the real KolanHook exploit calls `accept()`, not `beforeSwap` — the name-keyed rule missed the incident |
| `self-attested-auth` | a cast inside a `require`/`if` condition | the assigned-boolean form (`bool ok = IGuard(msg.sender).isEnabled(…); require(ok);`) | that is how the adapter in the real PoC is written |
| `settlement-optionality` | a settle-named function **and** a refund | a refund-with-timeout **and any** unguarded payout path | games settle through entries that are not named `settle`; the option exists regardless of the name |
| `registry-dispatched-logic` | a registry slot indexed by a parameter | a slot indexed by `msg.sender`, a stored id, or a loop variable | the id often arrives from storage or from the caller's identity |

The overflow valve is `src/lib/audit/triage.ts` (2026-10-27): low-confidence
findings go to `read-next`, not into the same list as the criticals, and the
certificate's findings table now uses `sortFindingsForTriage` so a reachable
finding leads its severity band. `triageQueue` / `readQueue` / `triageCounts`
band every finding as `read-now`, `read-next`, `needs-live-state` or
`background`, with the reason attached — so loosening the rules did not simply
make the report longer.

Measured cost: **SmartBugs unchanged** (1014 findings, 7.091 per contract, no
per-category movement) — the loosened paths need modern constructs the 2018
corpus does not have. The 2026-era corpus gained the real KolanHook case and
holds recall 100% with cross-talk 0 once three co-fires on that case are
justified (they are all true of it: it pays an unguarded caller, checks
`block.timestamp`, and writes-then-transfers).

## How much of SmartBugs we catch (2026-10-27)

**117 of 143 contracts — 81.8%.** A contract counts as caught when at least one
of its labelled categories was predicted. The number is now in the report
(`docs/smartbugs-benchmark.md`), in the baseline, on the console line, and gated
in the suite, because per-category recall is a diagnostic and this is the
question people actually ask.

The 26 misses, by category:

| Category | Missed | Contracts |
| --- | --- | --- |
| reentrancy | 9 | seven `0x…` contracts, plus `modifier_reentrancy`, `reentrancy_bonus` |
| denial_of_service | 5 | `auction`, `dos_address`, `dos_number`, `dos_simple`, `send_loop` — **parked at the owner's direction** |
| front_running | 3 | `ERC20`, `eth_tx_order_dependence_minimal`, `odds_and_evens` |
| time_manipulation | 3 | `ether_lotto`, `roulette`, `timed_crowdsale` |
| arithmetic | 2 | `BECToken`, `integer_overflow_benign_1` |
| access_control | 1 | `arbitrary_location_write_simple` |
| bad_randomness | 1 | `random_number_generator` |
| other | 1 | `name_registrar` |
| short_addresses | 1 | `short_address_example` — retired deliberately (the class died with the 0.5 ABI decoder) |

Two of those are structural rather than tuning:

- **`modifier_reentrancy`**: the reentrancy is inside a *modifier*, and
  `walkFn` only walks function bodies. Modifier bodies are never analysed for
  call-then-write ordering, so this whole class is invisible. That is the
  biggest single gap in the reentrancy column and it is not a threshold to
  loosen — it is a missing traversal.
- **`random_number_generator`**: the entropy is `salt = block.timestamp` stored
  in a state variable and then combined by multiplication (`salt * block.number
  / 3`, `salt % 300`). `weak-randomness` looks for block data inside a hash or a
  modulo in the same function, so entropy laundered through a state variable is
  missed. A recall-first loosening would catch it at low confidence.

## What is still wrong

1. **`denial_of_service` recall 0.167.** The real DoS detectors
   (`strict-balance`, `gas-estimator-dos`, `msg-value-loop`, `zero-address`,
   `hardcoded-gas`) catch 1 of 6 contracts. The old 0.5 was an artefact.
2. **`arithmetic` precision 0.203** — 64 contracts predicted against 15
   labelled. Pre-0.8 arithmetic really is everywhere in a 2018 corpus, so this
   may be the honest number; it needs a human read to say.
3. **`front_running` recall 0.250** — 2 of 4. The remaining two
   (`eth_tx_order_dependence_minimal`, `odds_and_evens`) pay out on a race this
   rule does not model.
4. **`short_addresses` recall 0.000, deliberately.** The class died with the
   0.5 ABI decoder; the detector is retired with that reason in
   `detector-registry.ts` rather than given a rule that would fire on every
   pre-0.5 token and mean nothing.
5. ~~**The benchmark is 2018-era.** It cannot exercise the 2026 classes.~~
   Closed on 2026-10-27 by `test/fixtures/incident-corpus` +
   `scripts/benchmark-incidents.ts`: 12 detectors, 24 cases, recall 100% and
   cross-talk 0 (see `docs/incident-corpus.md`). It caught two real bugs on its
   first run — a pre-0.8 gate that was always true, and a self-attestation rule
   that matched a payout.

## Verification

- `smartbugs-benchmark.test.ts` — the corpus scores and stays within the
  committed baseline.
- `detection-quality.test.ts` — 14 cases: registry totality, the fixture-debt
  ratchet, the clean-control gate, triage order, confidence bases, economic
  claims, family grouping.
- `scripts/detector-binding-check.mjs` — 67/67 detectors bound.
- Whole-suite comparison against the previous commit: no regressions (one
  unrelated `batch-writer` flake, which passes 5/5 on re-run).
- `ANALYZER_BASELINE` bumped to `2026-10-27.5`.

Two caveats. The TypeScript-importing checks still cannot run in this sandbox
(no `--experimental-strip-types`), so `npm run check:detectors` and three
`verify-poc-fallbacks` cases were verified by hand and left to CI. And the
benchmark scores file-level categories, not lines: the dataset annotates lines,
the analyzer reports sites, and joining them would measure whitespace
normalisation rather than detection.
