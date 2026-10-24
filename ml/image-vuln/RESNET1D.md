# ResNet1D long-byte candidate

Real offline experiment, not a replacement for the shipped RGB CNN. The user
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

The browser stays on the validated RGB worker. This larger candidate does not
fit its small JSON architecture or download limit; it requires separate export,
numerical parity and runtime performance work before browser promotion.
