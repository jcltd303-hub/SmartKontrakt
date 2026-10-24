# ResNet1D browser deployment implementation plan

> Execute inline with superpowers:executing-plans; verify before completion.

**Goal:** Run the validation-selected epoch 5 float ResNet1D locally in the browser.
**Architecture:** Export the existing evaluated checkpoint to ONNX with sigmoid outputs. Self-host bounded model shards, verify SHA256, and run single-thread WASM in a cancellable worker. Retain RGB as an explicitly selected alternative. RGB previews remain labelled as RGB-only, not ResNet inputs.
**Choice:** Float ONNX avoids changing evaluated predictions. Quantization would require fresh validation; handwritten convolution would add CPU cost and numerical maintenance.
**Authorization:** Existing image detection/train-eval approval and repeated go/continue instructions; continue work on existing feature branch without another approval round.

## Tasks
- [ ] Export: failing export/parity test, deterministic ONNX float export, validate five fixtures and checkpoint provenance, fixed size/hash manifest.
- [ ] Browser: failing preprocessing/manifest tests, raw bytes padded/truncated to 16384 and L2 normalized, bounded verified shard downloads, single-thread WASM worker and explicit model selector.
- [ ] Verify: PyTorch/ONNX/browser numeric parity, dev+built desktop/mobile rendering, cancellation/stale clearing, offline network behavior, measured latency; full Node/Python/type/lint/build checks, fresh review, update PR24.

## Review focus
Malformed manifests; prefix-based preview URLs; truncated inputs; all-zero normalization; cancellation while assets load; no remote bytecode transmission; model/score metadata mismatch; mobile latency/memory.
