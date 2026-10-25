# ResNet1D long-byte candidate

Evaluated long-byte model with a browser-local ONNX deployment. The user
approved training this architecture after the upstream validation table. The
upstream .8381 micro F1 is a reference, not a score reproduced here.

## Architecture and representation

Adapted under MIT from Martina Rossini's
[ResNet1D source](https://github.com/mwritescode/smart-contracts-vulnerabilities/blob/d755f0f2232ce9ef873150ab0dbb0043f04ebded/src/modeling/network/backbone/resnet_1d.py).
The feature stack is preserved: initial stride3 Conv1d; two128-channel residual
blocks, three256-channel residual blocks, one512-channel residual block with
MaxPool3 reductions; BatchNorm/LeakyReLU; final Conv1d, adaptive average pooling,
dropout .4 and five logits. There are 3,719,173 parameters. This project orders
classes access-control, arithmetic, reentrancy, unchecked-calls, others.

Inputs are **raw bytes**, not disassembled opcode IDs or RGB pixels. Keep the
first16,384 bytes, right-pad zeros and divide each vector by its L2 norm. All-zero
vectors remain zero. Counts of truncated rows are measured per split. The
upstream README describes16,384 for this model and512 for its LSTM; they are
separate input budgets.

## Data and selection

Reuse the official data columns and the existing raw/metadata/image cross-split
deduplication. The candidate adds an input-specific safeguard: padded/truncated
byte vectors are divided by their integer gcd and SHA256-hashed. This removes
training rows that would duplicate or be proportional to validation/test inputs
once L2 normalized. Filter **before** deterministic sorting/capping; refill the
pilot's8,192 rows. Validation/test remain unchanged. If they collide with each
other under this representation, training refuses to produce a misleading
benchmark and requires split revision.

The full eligible training pool contains six such candidate collisions
(four with validation, two with test); all are excluded. Both exact uint8 and
independent Torch-normalized float32 scans confirmed these six. `candidateFiltering`
records the addresses and exclusions. This protects identical candidate inputs,
not semantic-family isolation. Official pseudo-label noise remains.

Seed20261024; Adam lr.001, weight decay.0001; weighted BCE from sampled training
prevalences; batch16; CPU8 threads. Per-class thresholds use validation F1 over
.05..95 step.025, then select the epoch by maximum **validation micro F1**.
Test data is scored only after selection. Reports retain per-class metrics,
macro F1, fixed-.5 scores, exact match, split/content hashes and truncation counts.
The known test benchmark is reused. No independent replication or convergence
claim is made.

## Training, continuation and offline inference

```bash
python ml/image-vuln/train_resnet1d.py --cache /tmp/image-vuln-data --output /tmp/resnet-pilot --train-cap 8192 --epochs 2 --batch-size 16 --threads 8
python ml/image-vuln/verify_resnet1d.py --directory /tmp/resnet-pilot
python ml/image-vuln/infer_resnet1d.py --checkpoint /tmp/resnet-pilot/selected.pt --bytecode-file /tmp/runtime.hex
# Continue with identical settings/data; epochs is the new TOTAL, not an increment.
python ml/image-vuln/train_resnet1d.py --cache /tmp/image-vuln-data --output /tmp/resnet-pilot --train-cap 8192 --epochs 4 --batch-size 16 --threads 8 --resume /tmp/resnet-pilot/last.pt
```

`last.pt` atomically retains current and best weights, Adam state, Torch RNG,
history and the complete protocol. Resume rejects changes to data, cap, seed,
normalization, optimizer, batch size, thread count or Torch version. A new run
refuses to overwrite a prior output directory without explicit resume.
`selected.pt` holds the validation-selected weights/thresholds; the report pins
its SHA256 and parity fixtures verify reloaded predictions. Tensor-only loads
use `weights_only=True`.

The manually dispatched `ResNet1D training` GitHub Actions workflow acquires real
data, caches its columns and publishes checkpoint/report artifacts. It supports
continuation from a previous run's artifact via `resume_run`; keep the same
protocol and increase total epochs. It runs with two threads, so checkpoints
from the local eight-thread pilot require the local command above. Full-data
training (`--train-cap55632`, using all remaining55,626 eligible rows) is expected
to take much longer; run bounded epoch chunks and resume. Acquisition uses the
same pinned manifest URLs and records content hashes to detect changes.

The browser uses a separate ONNX/WASM worker for ResNet, with RGB available as
an explicitly selected alternative. The larger ResNet does not use the RGB JSON
architecture or its small download limit; see Browser deployment below.


## Completed two-epoch pilot (2026-10-24)

Trained on8,192 rows, using all7,358 validation and10,686 test rows. Epoch2 won
validation selection. Training/validation/test scoring took805.2 measured seconds
excluding data loading and preprocessing. The checkpoint and Adam/RNG continuation
state are supplied in the downloadable `SmartKontrakt-resnet1d-pilot-2026-10-24.zip`
bundle; its manifest pins source revision and both checkpoint hashes. Binary
weights are kept outside Git to avoid repository bloat. The original pilot report
is preserved as `resnet1d-pilot2-evaluation.json`; `resnet1d-pilot2-parity.json` stores real validation/edge
case scores verified against the reloaded checkpoint.

| Metric | RGB CNN,55,632 train/12epochs | ResNet1D pilot,8,192 train/2epochs |
|---|---:|---:|
| Validation micro F1 | 0.6397 | 0.5963 |
| Validation macro F1 | 0.6009 | 0.5533 |
| Test micro F1 | 0.6370 | 0.5996 |
| Test macro F1 | 0.5963 | 0.5568 |
| Test exact match | 0.2912 | 0.2515 |

The original two-epoch pilot did **not** meet the validation promotion criterion.
The browser retained the RGB CNN at that stage. The continuation below supersedes
that initial candidate result. Different data/epoch budgets mean this is not a
controlled claim that one architecture is superior. Two epochs on8,192 rows
are insufficient evidence about the fully trained ResNet1D's potential, and
longer training is not guaranteed to reach upstream.8381. Test remains the same
known benchmark, with Slither pseudo-labels and no semantic family isolation.

| Class | Precision | Recall | F1 |
|---|---:|---:|---:|
| access-control | 0.3312 | 0.5517 | 0.4139 |
| arithmetic | 0.2871 | 0.5740 | 0.3828 |
| reentrancy | 0.5537 | 0.8512 | 0.6709 |
| unchecked-calls | 0.6719 | 0.8529 | 0.7516 |
| others | 0.4557 | 0.7418 | 0.5646 |

Selected checkpoint SHA256: `83a05a4b22b0c039077b77db6c55eecbd5c95aeb155e0fe92c2035fcc56e6897`.

To verify the original two-epoch checkpoint bundle, put `resnet1d-pilot2-evaluation.json` beside
`selected.pt` as `evaluation.json`, and `resnet1d-pilot2-parity.json` as `parity.json`,
then run `verify_resnet1d.py --directory` with that directory. The archive's
`README-checkpoint.txt` also gives inference and continuation commands.

The GitHub workflow becomes manually dispatchable once it is present on the
repository's default branch. Its tests passed in PR CI; this local measured
pilot was not run by that manual workflow.


## Six-epoch continuation (2026-10-24)

Resumed the actual two-epoch Adam/model/RNG checkpoint for four additional epochs
without changing data or training settings. All8,192 train /7,358 validation /
10,686 test contracts and content hashes remain identical. The six held-out input
collisions remain excluded from training.

| Epoch | Validation micro F1 | Validation macro F1 |
|---|---:|---:|
| 1 | 0.5645 | 0.5403 |
| 2 | 0.5963 | 0.5533 |
| 3 | 0.6260 | 0.5834 |
| 4 | 0.6477 | 0.6110 |
| 5 | 0.6596 | 0.6213 |
| 6 | 0.6480 | 0.6106 |

Epoch5 was selected using validation micro F1; epoch6 scored lower. Test scoring
used the selected epoch5 only. The training run produced an epoch6 `last.pt`
and epoch5 `selected.pt`. The original six-epoch download was incomplete: only
`selected.pt` was recoverable, with its published SHA256 verified. Its repaired
download is inference-only and does not contain the epoch6 optimizer/RNG state.
The full-cohort experiment starts independently from fresh weights and optimizer.

| Metric | Two-epoch pilot | Six-epoch run, selected epoch5 | Full-data RGB CNN |
|---|---:|---:|---:|
| Validation micro F1 | 0.5963 | 0.6596 | 0.6397 |
| Validation macro F1 | 0.5533 | 0.6213 | 0.6009 |
| Test micro F1 | 0.5996 | 0.6626 | 0.6370 |
| Test macro F1 | 0.5568 | 0.6243 | 0.5963 |

The candidate now passes both validation promotion thresholds. This is improved
ResNet1D performance. The browser deployment below preserves these float weights
and verifies numerical parity; its first-load cost is substantially larger than RGB.
Different sample/epoch budgets and a reused known benchmark prevent a claim of
architecture superiority or independent reproduction of upstream.8381.

The latest report/parity are `resnet1d-evaluation.json` and
`resnet1d-parity.json`; the original two-epoch pair is preserved under `pilot2`
filenames. `continuation.py` validates the parent checkpoint, exact protocol,
history prefix and training counters. All16 BatchNorm and66 Adam counters match
3,072 completed batches. The new invocation took1,447.0 measured seconds; the sum
of both completed invocations is2,252.2 seconds, excluding environment setup,
data loading and time between runs. Timings are explicitly separated in
`resumeProvenance`.

```bash
# Given both original and continued output directories:
python ml/image-vuln/continuation.py --current-directory /tmp/resnet6 --parent-directory /tmp/resnet-pilot
python ml/image-vuln/verify_resnet1d.py --directory /tmp/resnet6
# Future same-data continuation: total epochs must exceed the completed6.
# Requires an intact epoch6 last.pt; it is not available in the repaired inference-only download.
python ml/image-vuln/train_resnet1d.py --cache /tmp/image-vuln-data --output /tmp/resnet6 --train-cap 8192 --epochs 10 --batch-size 16 --threads 8 --resume /tmp/resnet6/last.pt
```

Latest selected checkpoint SHA256: `f8ddd71621d6019c3aa0a6a5578254e04002ae42fea38904823204836009895e`.


## Browser deployment

The selected epoch 5 float checkpoint is exported to ONNX opset 17 with sigmoid outputs.
The 14,850,766-byte graph is split into bounded 1 MiB files under `public/models`, with
per-shard and whole-model SHA256 integrity checks. The export differs from PyTorch by
at most 1.79e-7 over the five saved fixtures. Browser CI verifies all 25 scores within
1e-5 in desktop and CPU-throttled mobile Chromium, in dev and production builds.
ResNet uses raw bytes; RGB previews are visualizations, not its input.

Inference uses self-hosted ONNX Runtime Web 1.30.0 WASM, one thread, in a worker.
It runs only on manual request, can be cancelled, and clears results when input/model changes.
First load includes about 15 MB of model data plus about 14 MB of WASM. No bytecode is
sent to a model server. RGB remains an explicit alternative. Mobile viewport/throttling
checks are not measurements on a physical phone.

Re-export with `python ml/image-vuln/export_resnet1d.py --checkpoint PATH/selected.pt
--report ml/image-vuln/resnet1d-evaluation.json --parity ml/image-vuln/resnet1d-parity.json
--output public/models`; then run `python ml/image-vuln/verify_resnet_browser.py`.
Export tools require onnx==1.23.2 and onnxruntime==1.31.0.

The loader downloads at most four model shards concurrently and supplies bounded WASM
bytes directly to the runtime. The built preview serves these static assets without
Nitro's per-request default-quality Brotli compression and with the WASM MIME type.
A real HTTP regression covers these headers, byte preservation, HEAD, missing files
and path rejection. Browser CI enforces a 30-second load budget on its local server;
this is not a network-speed guarantee for end users. Result timings distinguish
model transport, WASM transport, session initialization and inference.


## Full-cohort two-epoch experiment

Fresh training used all55,626 eligible contracts, with the same7,358 validation
and10,686 known-test contracts. All six candidate-input collisions remain excluded.
Seed20261024, batch16, eight CPU threads, architecture, optimizer and normalization
match the pilot. The expanded cohort required fresh model/Adam state.

| Model | Validation micro F1 | Validation macro F1 | Test micro F1 | Test macro F1 |
|---|---:|---:|---:|---:|
| Pilot,8,192 train,selected epoch5 | .6596 | .6213 | .6626 | .6243 |
| Full cohort,55,626 train,selected epoch2 | .7375 | .7040 | .7361 | .7003 |

Epoch1 validation micro/macro was .6752/.6448; epoch2 won by maximum validation
micro F1. Both selected validation metrics strictly exceed the current pilot;
test did not select the epoch, thresholds or promotion. This is a bounded
two-epoch experiment on a reused benchmark, not convergence, semantic-family
isolation, confirmed exploit detection or reproduction of upstream .8381.

The six-epoch pilot reports are preserved as `resnet1d-pilot6-evaluation.json`
and `resnet1d-pilot6-parity.json`. The active report records the validation gate
and separately tracks deployment verification. `selected.pt` contains epoch2
weights; `last.pt` contains epoch2 model/Adam/RNG state for continuation with
unchanged settings and `--train-cap 55632 --epochs 4 --batch-size 16 --threads 8`.
The full checkpoint bundle is independent of the repaired pilot download.

Selected checkpoint SHA256: `a488b44abc0021499406012c8a8f22d08bba927a07d01e51458509f632657eae`.

To reproduce this experiment's historical promotion decision, use
`python ml/image-vuln/full_cohort_report.py --directory RUN --baseline ml/image-vuln/resnet1d-pilot6-evaluation.json`.
The default baseline follows the active model for future experiments. Comparing
a checkpoint with itself is rejected before any report is overwritten.
