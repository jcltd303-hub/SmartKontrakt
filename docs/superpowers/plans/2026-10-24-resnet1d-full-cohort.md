# Full-cohort ResNet1D experiment

Goal: train and evaluate on all 55,626 eligible training contracts, retaining the fixed 7,358 validation and 10,686 known test contracts.

Protocol: fresh seed 20261024, two epochs, batch 16, eight CPU threads, identical architecture/optimizer/normalization. Changing the cohort requires a fresh optimizer and model, not resuming the 8,192-row checkpoint. Select epoch and thresholds by validation only. This is a bounded experiment, not a convergence claim.

- [x] Verify remote baseline b669f3d and restore current task source after a stale local snapshot.
- [x] Preserve held-out content hashes and six excluded input collisions.
- [x] Reduce encoding peak memory: one uint8 matrix, release original rows after encoding; regression RED→GREEN.
- [x] Complete two real full-cohort epochs, verify saved checkpoint and metrics.
- [x] Compare against deployed-model candidate epoch5 validation micro .6596268120 and macro .6213193462. Both must improve before promotion. Known test scores cannot select a model.
- [x] Save resumable checkpoints and reports, publish successor PR25 after PR24 was externally merged. Both validation and deployment gates passed for the PR candidate; main is unchanged by this work.

The initial full-cohort invocation was interrupted during startup memory pressure before any evaluation report. Restart uses bounded encoding, preserving exact inputs, batch size, optimizer and seed. Fresh run output is resnet-full-cohort2-bounded.

Review: fixed both P2 findings with RED→GREEN regressions. The top-level promotion flag now agrees with the current-ResNet gate; the legacy RGB decision is separately named. Exports stage their report/parity sidecars beside the model, with portable references; legacy repository references remain supported. Whole Python suite: 42 tests passed.

The prior six-epoch download was incomplete. Its selected epoch5 checkpoint was recovered and verified against SHA256 f8ddd71621d6019c3aa0a6a5578254e04002ae42fea38904823204836009895e. The same download identity now supplies a valid inference-only ZIP; old epoch6 resume state was unavailable. Replacement was read back and checked byte-for-byte and by ZIP CRC. Full-cohort checkpoints are independent fresh-run artifacts.

Recovery on continuation: remote PR24 was already merged as 39cf88a and its branch deleted. A fresh clone of main is authoritative. The previous scratch run/session and logs were not retained; no completed full-cohort checkpoint was found locally. Restart the same fresh two-epoch protocol in resnet-full-cohort2-recovered using existing pinned data. Preserve the current browser model. Save an independent durable checkpoint after each completed epoch before claiming resumability. Whole Python suite reverified: 42 tests passed.

Epoch1 completed: validation micro F1 .6752043391 / macro .6447574599. Verified all 16 BatchNorm and 66 Adam counters equal3477. Independent epoch1 resume backup saved and read back with matching SHA256 and ZIP CRC. Ruling: build checkpoint ZIPs under a temporary filename and atomically rename only after closing and checking CRC; a directly written archive was truncated in transfer despite command completion. Rebuilt replacement readback is56132131bytes, SHA256 1c51097d94fe0fe9a5f794b2b07940725757f551609c62b86fec92beece7e5bc. Cost if wrong: resumability would be lost; exact readback and step-counter checks mitigate this.

Completed epoch2 selected: validation micro/macro .7374643130/.7039670827; known-test .7361406958/.7003373146. Reloaded PyTorch parity passed; all16 BatchNorm and66 Adam counters equal6954. Both validation gates pass against pilot6. ONNX SHA256 984b3ee002e5491942c447aac45f54c47052e606105ed61e8ea61372c71242ab; all25 scores max error4.172325e-7. Historical pilot6 reports retained unchanged, associated tests now reference immutable historical files. Python42/42 and production build pass; browser CI pending.

Final review: the CLI could overwrite a historical decision after its default active baseline became the same model. Fixed with a RED→GREEN regression that exercises default CLI baseline resolution and proves the report stays unchanged. Ruling: retain the active-model default for future experiments, reject identical checkpoint comparisons, and document explicit immutable pilot6 baseline for historical reproduction. Permanently defaulting to pilot6 would allow future models worse than the newly active full-cohort model. Cost if wrong: CLI reruns require an explicit historical baseline; promotion remains conservative. Reviewer pending-CI language will be replaced with actual evidence after verification.

Final review fix: CLI self-baseline regression RED→GREEN, whole Python suite43/43. All733 Node tests/self-check, types, strict lint, build and general CI40154712022 passed. Artifact/browser CI40154712044 passed,110 scores within1e-5; all dev/built desktop/mobile screenshots inspected.
Final: Ruling: reviewer set aside browser behavior, remote checkpoint durability and provenance beyond inspected files. Resolve browser behavior with successful actual Chromium CI/screenshots and remote durability with full ZIP readback. Reuse existing acquired data cache, verifying full-training and held-out content hashes and training source39cf88a rather than reacquiring data. Cost if wrong: matching cached data hashes would be insufficient to establish independently audited dataset provenance; no such independent audit is claimed.
Final: minor (deferred): mobile score/threshold table is readable but cramped; improve column spacing in a later UI pass.

Final full-cohort bundle read back successfully:72310396bytes, SHA256 b95df8113203ed4fd9a7cc4f647e63e6e9a23e2770d6f3d4b87a3fed4819f6a4, full ZIP CRC and every contained file hash verified. Includes selected.pt epoch2 SHAa488b44abc0021499406012c8a8f22d08bba927a07d01e51458509f632657eae and last.pt epoch2 SHA99605fbbb4f8ee7c5f7d4f68a4c661d8ebf1f8fc01287da17b593f8ef4526c8f, protocol/history/Adam/RNG, measured reports/parity, dataset manifest/schema and continuation commands. PR25 remains unmerged. Final Python43/43 and ONNX25-score parity passed after evidence-only report edits.
