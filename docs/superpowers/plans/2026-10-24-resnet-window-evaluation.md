# ResNet window evaluation implementation plan

> Execute inline with superpowers:executing-plans; tests first and one fresh final review.

Goal: complete a real fixed-checkpoint bounded-window experiment and novelty diagnostic.
Architecture: pure bounded window helpers plus Torch evaluation CLI, fixed cohorts and validation-only thresholds.
Tech stack: existing Python, NumPy, PyTorch, sklearn.
Spec: docs/superpowers/specs/2026-10-24-resnet-window-design.md

## Global constraints
- At most8 windows,16384 bytes each; at most16 encoded windows per inference batch.
- Existing selected checkpoint and exact cohort hashes; no training or browser artifact changes.
- Validation grid .05..95 step.025; test/slices never select.
- New window/train-prefix or validation/test window collision blocks eligibility; no cohort filtering after observation.
- Skeleton novelty is not semantic-family isolation. No convergence/exploit-ground-truth claims.

## Tasks
- [x] Task1: test window_starts(length,window_size=16384,max_windows=8), encoded_windows(code,...), covered_bytes(length,starts,window_size), normalized_fingerprint(vector) and predict_windows(codes,predict,batch_size=16,...). RED: missing module; GREEN: short-input equivalence, full coverage within budget, bounded deterministic head/tail coverage above budget, proportional fingerprints, global batching/owner max aggregation, malformed/dimension/nonfinite-output rejection.
- [x] Task2: test validation_decision(prefix_validation,window_validation,collision_counts), collision_audit(train_prefixes,validation_windows,test_windows), and protocol verification. Implement evaluate_resnet_windows.py using load_rows, load_candidate, existing metrics and novelty helpers. Verify all fixed hashes/counts, stream bounded vectors, calibrate validation only, freeze decision before test, reconstruct existing prefix validation/test, report seen/unseen null-empty diagnostics and coverage/timing. RED→GREEN whole Python suite.
- [ ] Task3: run the actual full validation/test evaluation from selected epoch2, preserve JSON plus concise model-card interpretation. Fresh read-only review; one fix pass with RED→GREEN as needed. Run full Python and required CI, publish explicit intended files to successor PR26 without merging. Browser files remain identical unless a separately verified deployment is implemented.
- [ ] Task4 (explicit user steering): add image-ml-insights.tsx components for actual model evaluation, current-input coverage and hash-bound offline window comparison. Add defensive metadata/coverage parsing in src/lib/image-ml/insights.ts with Node tests; malformed values remain unavailable. Integrate with result data and valid input, preserve cancellation/stale clearing, fix table spacing. Extend browser regression to assert cards, model switching, long-input coverage and unchanged inference scores. Verify desktop/mobile dev and built screenshots and all tests/types/lint/build. Use existing CSS tokens.

## Review focus
- Window beginnings need not align to EVM instructions: model reads raw bytes; do not claim opcode windows.
- Lengths just above16384 and131072 must retain tail and report union coverage honestly.
- Multiple contracts sharing a batch must never receive each other's probabilities.
- Tail/window preprocessing can introduce held-out/training matches absent from prefix safeguards.
- Fixed test diagnostics cannot leak into selection or silently change cohorts.

## Ledger
Pre-flight: Task2 consumes Task1 window order, bounded batching and normalization fingerprints. Prefix is always first; ownership must survive global batches; all interfaces above are shared.
Recovery: fresh clone of PR25 d374a1e because the prior scratch clone was not retained. Selected checkpoint restored from the completed durable bundle and SHA verified. Main/PR25 merge state was checked; PR25 remains open.

Task1/2 verified RED→GREEN. Actual run reconstructed fixed prefix metrics and all cohort hashes. Window validation micro/macro .7359093086/.7026543257; test .7351348424/.7000843308. No validation improvement; one shared validation/test window, no training-prefix overlaps; retain prefix model. Held-out window byte coverage100%, with8354/12178 validation/test windows. Test skeletons2879seen/7807unseen. User explicitly requested UI components; added measured metadata cards, prefix coverage and hash-bound offline comparison, plus spacing/touch-target improvement. Node738 tests/self-check, types, lint and build passed. Local Chromium downloads are truncated; use actual CI browser jobs and inspect screenshots before completion.

Final review: no Critical issues. Regraded contradictory decision metadata as Important because it could falsely display passing validation/audits; fixed RED→GREEN with real parser tests, whole738Node suite, types and lint green.
Final: minor (deferred): image-ml workflow path filter does not separately include the new insights component; this PR also changes the parent panel, so all browser checks run now. Future component-only PRs should extend the filter.
Final: minor (deferred): committed compact UI summary is not yet equality-pinned against report generation by a test; reviewer independently verified all eight current F1 values and the checkpoint binding.
Final: Ruling: reviewer set aside actual Chromium behavior; verify through required CI and inspect dev/built desktop/mobile images before completion. Local downloads were truncated, so CI is the executable browser environment. Cost if wrong: UI layout/interaction defects could remain; do not claim success without the evidence.
PR25 was externally merged during this session. Its main merge tree exactly matches our base d374a1e; publish these scoped changes in PR26 without merging.

Browser regression exposed an existing Bytecode toolbar overflow. Diagnostic Chromium bounds identified the opcode search input at x257..423 on a390px viewport; intended clipped tab scrolling was excluded. Make the toolbar wrap and the search input full-width on mobile. Keep the same failing page-overflow regression for verification. Coverage progress uses the existing amber palette; unavailable metric text uses compact typography. RGB browser checks now also verify evaluation cards, unavailable micro F1, absence of ResNet-only cards and no page overflow. No clipping workaround was introduced. Node738 tests/types/lint/build passed locally; actual fixed browser CI pending.
