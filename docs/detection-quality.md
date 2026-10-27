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

## What is still wrong, in order

1. **`reentrancy` precision 0.071.** The biggest single number in the table.
2. **`eth-gas-stipend` / `locked-ether` noise.** 146 and 41 firings at 0.06 and
   0.00 signal. Both are "presence" findings that should probably be info, not
   findings, unless something is at stake.
3. **`arithmetic` has no pre-0.8 rule.** Recall 0 on 15 contracts.
4. **`front_running` and `short_addresses` have no rule at all** — 5 contracts
   between them, and the three phantoms above.
5. **The benchmark is 2018-era.** It cannot exercise the 2026 classes. The
   incident corpora cover those, but with reconstructions rather than deployed
   code.

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
