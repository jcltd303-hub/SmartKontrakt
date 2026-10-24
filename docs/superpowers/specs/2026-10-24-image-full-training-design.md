# Full training and opcode novelty evaluation

Continue the approved image detector by training the existing architecture on all 55,632 eligible training contracts, retaining the fixed seed, optimizer, epochs, original deduplicated splits and validation-only selection. Preserve the 20k model's metrics and evaluate both models on the same benchmark; this is a repeated benchmark, not a newly untouched test set. Promote the full model only if its selected validation macro F1 improves.

Use the existing CPU PyTorch pipeline and browser model schema. Alternatives were increasing architecture/epochs (confounds data-scale comparison) or fetching a new externally labeled corpus (not currently available locally). The chosen controlled data-scale comparison costs no new dependencies/API calls.

Add a label-independent opcode-skeleton novelty diagnostic: strip plausible Solidity metadata, remove PUSH operands, normalize PUSH widths/PUSH0, and hash the complete resulting opcode sequence. Report test rows whose skeleton occurs in neither training nor validation, separately from seen-skeleton rows; record counts and address hashes. This is an exact-skeleton proxy, not semantic family clustering or an external generalization benchmark. Never use slice labels or test metrics to select weights, epochs, thresholds or architecture. Explicitly handle empty slices without fabricated scores.

Ship real weights/parity only after validation selection, matching evaluation and training-count documentation, reproducible CLI commands and numerical/browser checks. Retain uncalibrated experimental copy. No new audit findings, API inference, persistence, migrations or changes to the PoC runner.
