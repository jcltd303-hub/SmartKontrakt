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
- [x] Write/run failing behavioral tests for normalized windows, partial tail, malformed input/output, score caps and deep-agent rescoring.
- [x] Implement audit.ts/types/risk and reusable browser worker/client; run targeted tests and real Node model inference.

### Task 2: Address enrichment
- [x] Reproduce short-runtime/RPC parsing and missing ML integration; implement shared fetcher + Node worker callback and cached offline model.
- [x] Verify source/bytecode/ABI/provider failure paths and serialized actual inference.

### Task 3: Fallbacks and prompts
- [x] Reproduce unknown-detector unrelated templates, universal reentrancy/profit instructions and invented no-key claims.
- [x] Correct generators/prompts; render bounded ABI/ML evidence and wire review/second pass consumers.

### Task 4: Product verification
- [x] Update coverage/UI and browser all-byte checks, bump analyzer version.
- [x] Browser CI passed; dev/built desktop/mobile screenshots inspected; local tests/types/lint/build and fresh review complete.
- [ ] Finish PR28 CI verification; leave unmerged.

## Progress
- Scratch reset interrupted initial implementation; current recovery starts from remote main e0951cf (which includes PR27).

- Reused concurrent main e0951cf's existing ResnetResult, six-point scoring and migration0018 rather than introducing a duplicate result format.
- Fresh review: two important findings (stale model result on failed replay; ML band crossing) reproduced RED→GREEN. Node deep-agent stale weight bug also reproduced RED→GREEN.
- Final local full suite after upstream integration: 795 Node tests passed (252 scripts + 543 TypeScript). Typecheck, lint and build passed. CI c276b75 passed general checks, 55 Python tests/artifact checks and dev/built desktop/mobile browser verification. Current final branch checks are linked on PR28.
- Local Python attempt was blocked by missing torch (13 import errors); the complete pinned Python environment passed in GitHub artifact CI. Real Node ONNX coverage 131073 bytes and repeated inference passed. No checkpoint changes.

- Integrated main 9df65b1's optional ONNX lazy loading: missing package keeps the worker alive and yields explicit unavailable evidence. Preserved all-byte inference, cached serialized sessions and retryable model loads. Upstream missing-package tests now assert static findings/score preservation plus the required failure status (rather than byte-identical reports). All 13 loader/attachment tests passed; typecheck/lint/build and full suite passed after integration.
