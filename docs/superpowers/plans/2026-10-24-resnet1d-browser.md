# ResNet1D browser deployment implementation plan

> Execute inline with superpowers:executing-plans; verify before completion.

**Goal:** Run the validation-selected epoch 5 float ResNet1D locally in the browser.
**Architecture:** Export the existing evaluated checkpoint to ONNX with sigmoid outputs. Self-host bounded model shards, verify SHA256, and run single-thread WASM in a cancellable worker. Retain RGB as an explicitly selected alternative. RGB previews remain labelled as RGB-only, not ResNet inputs.
**Choice:** Float ONNX avoids changing evaluated predictions. Quantization would require fresh validation; handwritten convolution would add CPU cost and numerical maintenance.
**Authorization:** Existing image detection/train-eval approval and repeated go/continue instructions; continue work on existing feature branch without another approval round.

## Tasks
- [x] Export: failing export/parity test, deterministic ONNX float export, validate five fixtures and checkpoint provenance, fixed size/hash manifest.
- [x] Browser: failing preprocessing/manifest tests, raw bytes padded/truncated to 16384 and L2 normalized, bounded verified shard downloads, single-thread WASM worker and explicit model selector.
- [ ] Verify: PyTorch/ONNX/browser numeric parity, dev+built desktop/mobile rendering, cancellation/stale clearing, offline network behavior, measured latency; full Node/Python/type/lint/build checks, fresh review, update PR24.

## Review focus
Malformed manifests; prefix-based preview URLs; truncated inputs; all-zero normalization; cancellation while assets load; no remote bytecode transmission; model/score metadata mismatch; mobile latency/memory.


## Evidence and decisions
- Export: all 25 selected-checkpoint scores match ONNX within 1.79e-7; ONNX model SHA256 77fbcfad7d0cc378e51c0106f5bdd8e5ffc41e5cc33a687df54d5bb75e5d298b.
- Preprocessing/manifest tests written RED then GREEN; prefix regression RED then GREEN after fresh review finding.
- Existing feature checkout retained; no merge or deployment authorized.
- Runtime choice: 15 MB float model and 14 MB single-thread WASM loaded only on manual run; quantization deferred to avoid changing evaluated behavior.
- Physical mobile memory was not measured. CPU-throttled mobile Chromium verifies practical completion, with first-load/inference timings reported separately.

- First dev browser run reproduced Vite lazy dependency discovery reloading the page during inference. Added explicit startup optimization for worker-only ONNX import; browser test remains the regression check.
