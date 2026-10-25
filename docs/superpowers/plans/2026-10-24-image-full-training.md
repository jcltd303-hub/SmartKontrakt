# Full image training implementation plan

**Goal:** expand the fixed CNN training data and quantify exact opcode-skeleton novelty.
**Architecture:** existing CPU training/export, label-independent skeleton slices, unchanged browser runtime.
**Tech stack:** Python/PyTorch/NumPy/sklearn, TypeScript worker.
**Spec:** docs/superpowers/specs/2026-10-24-image-full-training-design.md

## Constraints and review focus
- Validation-only model promotion; known test benchmark is repeated, not fresh.
- PUSH immediates/widths and plausible metadata cannot create false novelty.
- Truncated PUSH and empty novelty slices have explicit deterministic behavior.
- Both models share the exact test ordering; selection hashes prove alignment.
- No family-isolation/external benchmark claims from this proxy.

## Tasks
- [x] Train the existing pipeline with cap55632/epochs12/seed20261024; preserve original20k artifacts externally and metrics in comparison report. Compare validation only before promotion.
- [x] Add failing Python tests for opcode skeleton equivalence, instruction differences, malformed hex, truncated PUSH and empty-slice counts. Implement `opcode_skeleton` and `novelty_indices` in `novelty.py`; run Python suite RED→GREEN.
- [x] Build `evaluate_novelty.py` to reconstruct each JSON model, use the same cleaned/sorted splits, and report paired seen/unseen skeleton metrics/counts/hash. Keep diagnostic data out of selection.
- [x] Update model card/counts/audit and parity tests to pin thresholds to the selected report. Run Python parity, Node suite, lint/types/build and configure actual browser CI.
- [ ] Independent review, resolve actionable findings, publish an update to PR24 and inspect browser evidence.

Verification: 16 Python tests, five Torch fixtures, 25 TypeScript/Torch scores, 728 Node tests and detector self-check passed; strict lint, types and production build passed. Independent fresh-context review found no actionable issues. Browser CI will rerun on PR24 with the new weights.
