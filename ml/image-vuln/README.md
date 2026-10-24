# Bytecode image CNN v1 — measured CPU baseline

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
| Train | 79,641 | 227 | 20,460 | 3,322 | 55,632 | 20,000 |
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
SHA256(seed + address), then capped at 20,000, avoiding a first-shard sample.
Validation/test use every retained row. Deduplication changes their distributions;
these metrics are not metrics on the unfiltered official test split.

An independent audit found 167 fingerprint groups with contradictory pseudo-label
sets, affecting 990 train / 136 validation / 195 test input rows. After deduplication,
54 available train / 0 validation / 2 test rows have such within-split conflicts;
first-row labels remain, a quantified source of label noise. These train counts
precede the 20,000-row cap. `dataset-audit.json` includes selection-address hashes,
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
negative/positive counts **from sampled training rows only**. Maximum validation
macro F1 selects epoch 12. Per-class thresholds maximize validation F1 on the fixed
.05–.95 grid in .025 steps. No test-label tuning or test-driven model selection.
Training took 34.4 measured seconds excluding acquisition/preprocessing/audit.

## Held-out results

| Metric | CNN | Train-majority constant | All-positive constant |
|---|---:|---:|---:|
| Micro F1 | .5996 | .3991 | .4872 |
| Macro F1 | .5667 | .1370 | .4738 |
| Exact match | .2578 | .1176 | See audit JSON |

The prevalence baseline uses train prevalences as constant probabilities and the
CNN's validation thresholds; it equals majority predictions in this run.
All-positive predicts every vulnerability category for every row and is included
because F1 rewards recall on common categories.

| Class | Precision | Recall | F1 | Test support | AP | AUROC |
|---|---:|---:|---:|---:|---:|---:|
| access-control | .3086 | .6194 | .4119 | 1,905 | .3683 | .7169 |
| arithmetic | .2884 | .6823 | .4054 | 2,169 | .3449 | .6812 |
| reentrancy | .5775 | .8254 | .6795 | 4,134 | .6855 | .7889 |
| unchecked-calls | .7374 | .7997 | .7673 | 5,566 | .8215 | .8076 |
| others | .4816 | .6957 | .5692 | 3,431 | .5500 | .7334 |

Precision is low for access-control/arithmetic. The model must remain advisory.
Pseudo-label error, omitted source context, compiler/version artifacts, lossy image
resizing, arbitrary within-split duplicate labels, and the 20k training cap limit
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
python ml/image-vuln/train.py --cache /tmp/image-vuln-data --output public/models --train-cap 20000 --epochs 12 --seed 20261024 --threads 8
python ml/image-vuln/audit.py --cache /tmp/image-vuln-data
python ml/image-vuln/verify_export.py
```

Full-column cache is approximately hundreds of MB; allow RAM for raw rows and
~470 MB of uint8 images. Remote data and library versions must remain available.
The trained JSON serializes actual float32 OIHW convolution and OI linear weights,
not a heuristic/random model. `bytecode-image-v1-parity.json` contains three real
public validation rows plus five-byte and one-byte synthetic edge cases, with
Torch probabilities. `verify_export.py` reconstructs Torch solely from serialized
weights and checks all five fixtures. The training checkpoint remains in the
external cache; the JSON is the portable trained model.
