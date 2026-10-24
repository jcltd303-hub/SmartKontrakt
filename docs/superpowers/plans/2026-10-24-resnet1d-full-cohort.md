# Full-cohort ResNet1D experiment

Goal: train and evaluate on all 55,626 eligible training contracts, retaining the fixed 7,358 validation and 10,686 known test contracts.

Protocol: fresh seed 20261024, two epochs, batch 16, eight CPU threads, identical architecture/optimizer/normalization. Changing the cohort requires a fresh optimizer and model, not resuming the 8,192-row checkpoint. Select epoch and thresholds by validation only. This is a bounded experiment, not a convergence claim.

- [x] Verify remote baseline b669f3d and restore current task source after a stale local snapshot.
- [x] Preserve held-out content hashes and six excluded input collisions.
- [x] Reduce encoding peak memory: one uint8 matrix, release original rows after encoding; regression RED→GREEN.
- [ ] Complete two real full-cohort epochs, verify saved checkpoint and metrics.
- [ ] Compare against deployed-model candidate epoch5 validation micro .6596268120 and macro .6213193462. Both must improve before promotion. Known test scores cannot select a model.
- [ ] Save resumable checkpoints and reports, update PR24. Keep browser weights unless deployment parity and checks pass.

The initial full-cohort invocation was interrupted during startup memory pressure before any evaluation report. Restart uses bounded encoding, preserving exact inputs, batch size, optimizer and seed. Fresh run output is resnet-full-cohort2-bounded.

Review: fixed both P2 findings with RED→GREEN regressions. The top-level promotion flag now agrees with the current-ResNet gate; the legacy RGB decision is separately named. Exports stage their report/parity sidecars beside the model, with portable references; legacy repository references remain supported. Whole Python suite: 42 tests passed.

The prior six-epoch download was incomplete. Its selected epoch5 checkpoint was recovered and verified against SHA256 f8ddd71621d6019c3aa0a6a5578254e04002ae42fea38904823204836009895e. The same download identity now supplies a valid inference-only ZIP; old epoch6 resume state was unavailable. Replacement was read back and checked byte-for-byte and by ZIP CRC. Full-cohort checkpoints are independent fresh-run artifacts.
