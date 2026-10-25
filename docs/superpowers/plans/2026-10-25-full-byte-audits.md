# Full-byte audit implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans.

**Goal:** Every address audit processes its complete runtime with ResNet and retains honest scoring/prompt evidence.
**Architecture:** Shared sequential reducer, cached browser/Node sessions, shared fetcher attachment, inventory JSON persistence.
**Tech Stack:** TypeScript, ONNX Runtime WASM, React, Node test runner.
**Spec:** docs/superpowers/specs/2026-10-25-full-byte-audits-design.md

## Global constraints
- Consecutive 16,384-byte windows; no omissions or learned calibration claims.
- Preserve existing six-point scoring term and static/PoC gates.
- Runtime/ABI unavailable states explicit; never fabricate templates or exploits.

## Review focus
- Runtime over 128KiB reaches its final byte.
- Failed cached model can retry; no parallel session calls.
- Verified-source audits invoke inference too.
- Persist/reload and deep-agent rescoring preserve ML contribution.
- Unknown detector and missing ABI do not produce invented attack evidence.

### Task 1: Full-byte reducer and scoring
- [ ] Write/run failing behavioral tests for normalized windows, partial tail, malformed input/output, score caps and deep-agent rescoring.
- [ ] Implement audit.ts/types/risk and reusable browser worker/client; run targeted tests and real Node model inference.

### Task 2: Address enrichment
- [ ] Reproduce short-runtime/RPC parsing and missing ML integration; implement shared fetcher + Node worker callback and cached offline model.
- [ ] Verify source/bytecode/ABI/provider failure paths and serialized actual inference.

### Task 3: Fallbacks and prompts
- [ ] Reproduce unknown-detector unrelated templates, universal reentrancy/profit instructions and invented no-key claims.
- [ ] Correct generators/prompts; render bounded ABI/ML evidence and wire review/second pass consumers.

### Task 4: Product verification
- [ ] Update coverage/UI and browser all-byte checks, bump analyzer version.
- [ ] Run full tests/types/lint/build and browser CI; inspect screenshots; fresh review and regression fixes.
- [ ] Publish a reviewable PR with verified checks, leave unmerged.

## Progress
- Scratch reset interrupted initial implementation; current recovery starts from remote main d02615d.
