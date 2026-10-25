# Full-byte address audits

User request: process all bytes with ResNet on each address pipeline entry; fetch bytecode, ABI and existing audit context; include ML in scoring; repair detector fallbacks and prompts.

Use consecutive 16,384-byte windows, zero-pad only final window, normalize per-window and class-max pool. No sampled-window cap or silent omissions. Existing checkpoint and prefix-calibrated thresholds remain; pooled scores are experimental, not calibrated vulnerability probabilities and do not inherit prefix benchmark accuracy. One oversized tensor is incompatible with checkpoint shape; sampled windows omit bytes; consecutive windows meet the explicit requirement with bounded tensor memory.

Reuse one checked ONNX session per browser batch or Node worker; serialize inference. Cache reset on failure permits retry. Persist coverage, policy, checkpoint hash, class scores and actual scoring contribution in existing resnet_json (migration 0018), with failure status in inventory JSON, keeping raw runtime ephemeral. Failure is explicit missing evidence, never a clean result. Both verified-source and bytecode-only address audits invoke ML, after runtime/ABI/value gathering. Existing proxy/interface enrichment remains. Analyzer version refreshes stale entries.

Scoring proposal: the existing six-point ML cap for any above-threshold class, capped within static severity band; ML alone does not create a risk score. Preserve confirmed-PoC and static dominance rules. No synthetic vulnerability findings or automatic PoCs from ML. Carry actual ABI/provenance and ML evidence into review prompts and second pass. Audit concrete detector/template mismatches, remove unrelated attack assumptions and fabricated fallback claims.

Verify malformed/short bytecode, final tail beyond 128KiB, repeated real ONNX inference, unavailable providers, persistence, score bounds and prompt evidence. UI describes all-byte policy and experimental thresholds. Full tests, build/types/lint, browser dev/built desktop/mobile, fresh review and GitHub CI before completion. No automatic merge.
