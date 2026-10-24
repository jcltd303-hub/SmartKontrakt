# Bytecode image CNN v1 — full-data CPU baseline

This is a real trained multilabel classifier inspired by Martina Rossini's
[smart-contracts-vulnerabilities](https://github.com/mwritescode/smart-contracts-vulnerabilities).
It predicts **Slither category labels**, not verified exploitability. It is a
bounded experiment, not a reproduction of the paper's models/results, an audit,
or a proof that a contract is safe. Sigmoid scores are uncalibrated model outputs.

## Data and split handling

Source: [Slither Audited Smart Contracts](https://huggingface.co/datasets/mwritescode/slither-audited-smart-contracts),
`big-multilabel`, official train/validation/test splits. Only `address`, `bytecode`
and `slither` columns were acquired from all ten Parquet files. `dataset-manifest.json`
records exact remote URLs/sizes; `label-schema.json` records official features.
Dataset card declares MIT; upstream software copyright (c) 2022 Martina Rossini,
MIT, preserved in `LICENSE.upstream`. Contract labels are automated Slither
pseudo-labels; the original contracts can have their own source licenses.

Official indices are 0 access-control, 1 arithmetic, 2 other, 3 reentrancy, 4 safe,
5 unchecked-calls. Outputs are ordered access-control, arithmetic, reentrancy,
unchecked-calls, others. `other` maps to `others`; `safe` means all five outputs
zero. This is independent multilabel prediction; no softmax/safe class is added.

| Split | Official rows | Invalid/empty | Cross-split duplicates removed | Within-split duplicates removed | Retained | Used |
|---|---:|---:|---:|---:|---:|---:|
| Train | 79,641 | 227 | 20,460 | 3,322 | 55,632 | 55,632 |
| Validation | 10,861 | 30 | 3,433 | 40 | 7,358 | 7,358 |
| Test | 15,972 | 51 | 5,161 | 74 | 10,686 | 10,686 |

Before sampling/training, every valid row was fingerprinted by SHA256 of raw
runtime bytecode, metadata-normalized bytecode, and the exact rendered 64x64 RGB
image. Normalization strips a plausible trailing Solidity CBOR metadata payload
using its final two-byte length; it does not decode creation code, prove semantic
equivalence, or identify contract families. Any fingerprint shared across official
splits excludes **all affected rows from all splits**. Within each split the first
official row is retained for duplicates. There were 3,940 distinct shared
fingerprints (fingerprint types can overlap). The deduped train set is sorted by
SHA256(seed + address), all 55,632 eligible rows are used.
Validation/test use every retained row. Deduplication changes their distributions;
these metrics are not metrics on the unfiltered official test split.

An independent audit found 167 fingerprint groups with contradictory pseudo-label
sets, affecting 990 train / 136 validation / 195 test input rows. After deduplication,
54 available train / 0 validation / 2 test rows have such within-split conflicts;
first-row labels remain, a quantified source of label noise. All 54 train rows are included in this full-data run. `dataset-audit.json` includes selection-address hashes,
conflict/drop counts, and an all-positive baseline. Exact-image exclusion cannot
remove all similar-contract/family leakage. No out-of-distribution test was run.
All valid inputs were at most 24,575 bytes; no dataset row exceeds the browser's
128 KiB bound.

## Image and training contract

Raw EVM bytes become consecutive RGB triples, zero-padded to a square of side
ceil(sqrt(ceil(byte_count/3))). Nearest-center resize to 64 uses
`min(side-1, floor((coordinate+0.5)*side/64))`. All bytes enter the square, although
nearest resize can discard pixels. NCHW floats are divided by 255. Odd **byte
counts** work; odd hex-nibble counts are rejected. No rotations/flips/augmentation.

Three Conv2d/ReLU blocks: 3→8→16→24 channels, 3x3 kernel, stride 2, padding 1;
AvgPool2d(2,2); NCHW flatten 384; Linear(384,5); independent sigmoid.
Seed 20261024; deterministic Torch CPU, eight threads. Adam learning rate .001,
weight decay .0001, batch 128, 12 epochs. BCEWithLogitsLoss positive weights are
negative/positive counts **from training rows only**. Maximum validation
macro F1 selects epoch 12. Per-class thresholds maximize validation F1 on the fixed
.05–.95 grid in .025 steps. No test-label tuning or test-driven model selection. This full-data follow-up reuses
the known test benchmark from the 20k experiment; it is not a newly untouched test.
Promotion was specified as a strict validation macro-F1 improvement before training: .5698→.6009.
Training took 69.1 measured seconds excluding acquisition/preprocessing/audit.

## Held-out results

| Metric | CNN | Train-majority constant | All-positive constant |
|---|---:|---:|---:|
| Micro F1 | 0.6370 | 0.3991 | 0.4872 |
| Macro F1 | 0.5963 | 0.1370 | 0.4738 |
| Exact match | 0.2912 | 0.1176 | 0.0240 |

The prevalence baseline uses train prevalences as constant probabilities and the
CNN's validation thresholds; it equals majority predictions in this run.
All-positive predicts every vulnerability category for every row and is included
because F1 rewards recall on common categories.

| Class | Precision | Recall | F1 | Test support | AP | AUROC |
|---|---:|---:|---:|---:|---:|---:|
| access-control | 0.4531 | 0.5118 | 0.4807 | 1,905 | 0.4962 | 0.7729 |
| arithmetic | 0.3447 | 0.6017 | 0.4383 | 2,169 | 0.4018 | 0.7244 |
| reentrancy | 0.5838 | 0.8384 | 0.6883 | 4,134 | 0.7406 | 0.8164 |
| unchecked-calls | 0.7391 | 0.8162 | 0.7757 | 5,566 | 0.8497 | 0.8306 |
| others | 0.5061 | 0.7324 | 0.5986 | 3,431 | 0.5822 | 0.7580 |

Precision is low for access-control/arithmetic. The model must remain advisory.
Pseudo-label error, omitted source context, compiler/version artifacts, lossy image
resizing, arbitrary within-split duplicate labels, and the compact CNN limit
these results. No confidence intervals, calibration, external benchmarks, or
exploit validation were performed. `evaluation.json` contains exact metrics,
thresholds, training history and selection details.

## Reproduce

Use Python 3.11+ and `requirements.txt` (CPU PyTorch wheel instructions included).
Keep the cache outside Git; acquisition uses HTTP range requests rather than
fetching source-code columns. Run from the repository root:

```bash
python -m unittest discover -s ml/image-vuln -v
python ml/image-vuln/acquire.py --manifest ml/image-vuln/dataset-manifest.json --cache /tmp/image-vuln-data
python ml/image-vuln/train.py --cache /tmp/image-vuln-data --output public/models --train-cap 55632 --epochs 12 --seed 20261024 --threads 8
python ml/image-vuln/audit.py --cache /tmp/image-vuln-data --train-cap 55632
python ml/image-vuln/verify_export.py
```

Full-column cache is approximately hundreds of MB; allow RAM for raw rows and
~906 MB of uint8 images. Remote data and library versions must remain available.
The trained JSON serializes actual float32 OIHW convolution and OI linear weights,
not a heuristic/random model. `bytecode-image-v1-parity.json` contains three real
public validation rows plus five-byte and one-byte synthetic edge cases, with
Torch probabilities. `verify_export.py` reconstructs Torch solely from serialized
weights and checks all five fixtures. The training checkpoint remains in the
external cache; the JSON is the portable trained model.


## Controlled full-data comparison and novelty diagnostic

The 20k baseline metrics are retained in `baseline-20k-evaluation.json`; its weights
are recoverable from commit `95d29ab119528179c425fd1bb7ff1e7a075f393c` at
`public/models/bytecode-image-v1.json`. `full-training-comparison.json` records both
artifact SHA256 values, paired validation/test metrics, fixed-0.5-threshold metrics,
per-class scores, cohort address hashes and the validation-only promotion rule.

| Cohort / metric | 20k baseline | Full 55,632 |
|---|---:|---:|
| Validation micro F1 | .6025 | .6397 |
| Validation macro F1 | .5698 | .6009 |
| Test micro F1 | .5996 | .6370 |
| Test macro F1 | .5667 | .5963 |
| Unseen-skeleton test micro F1 | .5612 | .5858 |
| Unseen-skeleton test macro F1 | .5266 | .5361 |

The novelty diagnostic uses the **same** reference for both models: all 55,632
eligible training rows plus 7,358 validation rows. Plausible metadata is removed;
PUSH operands are skipped, PUSH0 and PUSH1..32 normalize to one token, and the
entire remaining opcode sequence is SHA256-hashed. Of the 10,686 test rows, 2,879
have a skeleton in that reference and 7,807 do not. Test siblings do not influence
membership. Empty slices report null metrics. This coarse, exact-match proxy can
merge unrelated contracts and miss related ones; it is **not** semantic family
isolation, an external benchmark, or a safety verdict. Distribution shift, label
noise and shared compiler patterns remain. No training decision uses slice scores.

```bash
# Retrieve the 20k JSON from the pinned commit above into /tmp/baseline-20k.json.
python ml/image-vuln/evaluate_novelty.py --cache /tmp/image-vuln-data --baseline /tmp/baseline-20k.json --candidate public/models/bytecode-image-v1.json --output ml/image-vuln/full-training-comparison.json
```

## Upstream benchmark context

The upstream README reports **validation** micro F1 .8381 for ResNet1D, .7928 for
ResNet, .8015 for Inception and .7953 for its LSTM baseline. These are reference
results, not results reproduced by this project. Our full-data validation micro
F1 is .6397; there is still a substantial quality gap.

Source pinned at `d755f0f2232ce9ef873150ab0dbb0043f04ebded`:
[README](https://github.com/mwritescode/smart-contracts-vulnerabilities/blob/d755f0f2232ce9ef873150ab0dbb0043f04ebded/README.md),
[ResNet1D](https://github.com/mwritescode/smart-contracts-vulnerabilities/blob/d755f0f2232ce9ef873150ab0dbb0043f04ebded/src/modeling/network/backbone/resnet_1d.py),
[preprocessing](https://github.com/mwritescode/smart-contracts-vulnerabilities/blob/d755f0f2232ce9ef873150ab0dbb0043f04ebded/main.py).

ResNet1D uses raw uint8 byte sequences (not disassembled opcode IDs), residual
Conv1d blocks with 128/256/512 channels, BatchNorm, LeakyReLU and dropout. Its
README specifies a maximum sequence length of **16,384**, compared with the
LSTM's 512. Code applies truncation/padding and optional L2 normalization.
Our compact RGB CNN resizes to 64×64 using nearest-center sampling, which can
lose short code patterns. The different architecture, input representation,
deduplication, class ordering and threshold/selection protocols prevent a direct
leaderboard comparison. Upstream default config alone is not the complete
best-run configuration. A separate long-sequence ResNet1D experiment and external
family-aware validation are the next architecture work, not claims of this run.

Micro F1 pools TP/FP/FN across labels and favors frequent-label contributions;
macro F1 weights each class equally. Both and per-class precision/recall are
reported. Exact-match accuracy requires every label on a row to agree and is not
the model-selection objective.
