# ResNet1D continuation to six epochs

User requested continuation of the completed two-epoch candidate. Resume its actual Adam, RNG and model state; preserve all data, class mapping, preprocessing, optimizer, seed, batch and thread settings. Predeclare four more epochs (six total), with best checkpoint/thresholds selected only using validation. The test benchmark is known and reused, not an independent replication of upstream results.

- [x] Resume old last.pt into a separate output directory, train epochs3–6 on8192 rows.
- [x] Preserve the original two-epoch report/parity; assert history prefix, split/content hashes, filtering and protocol remain identical.
- [x] Verify the selected checkpoint against saved parity, run Python/Node checks and update measured comparison. Promotion requires both validation micro and macro F1 to beat the RGB incumbent; browser runtime still requires its own export/parity/performance verification.
- [ ] Persist selected and continuation checkpoints together; publish code/report updates and CI evidence to PR24.

Current report timing covers the new invocation, not the previous two epochs. Add explicit parent checkpoint SHA256, starting epoch, added epochs and separate/cumulative measured invocation durations to prevent timing/provenance ambiguity.

Completed: selected epoch5, validation micro/macro .6596/.6213, test .6626/.6243. All31 Python tests and728 Node tests pass; types/lint/build pass. Checkpoint parity25scores passes, history/protocol hashes identical,16BN/66Adam counters verify3072batches. Independent review found no actionable issue. Browser export remains separate.
