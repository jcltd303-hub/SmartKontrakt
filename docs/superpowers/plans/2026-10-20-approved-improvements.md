# Approved reliability improvements

> **For agentic workers:** Use Superpowers development and verification skills. The user explicitly approved implementation of all three follow-ups.

**Goal:** Gate changes with CI, distinguish PoC origins from reproduced evidence, and make the existing UI maintainable without changing its workflows.

**Architecture:** Preserve public component props and persisted schemas. Move cohesive UI sections into typed modules. Use one pure evidence classifier and reusable badge across live and saved results; existing execution logs carry source binding without a database migration.

**Tech stack:** React, TypeScript, Node 24, native Node tests, Playwright, GitHub Actions.

**Spec:** The three follow-ups in PR #1 and the user's approval in this session.

## Global constraints

- Preserve bounded batch writers, checkpoint recovery, pause/resume, and pipeline mount retention.
- Never infer reproduction from code generation or a bare `passed` flag.
- Legacy, source-mismatched, zero-test, sanity-only, and infrastructure outcomes cannot receive the reproduced label.
- CI uses no application secrets, paid AI calls, live database, or live-fork execution.
- Keep the existing UI's structure and visual language.

## Review focus

- A saved old passed flag has no trustworthy execution evidence: label unverified.
- Editing code after execution invalidates its reproduced label.
- A failed test does not establish that the target is safe.
- Switching views must not unmount or restart a batch run.
- Browser smoke errors, overflow, empty pages, or build/dev divergence must fail CI.

## Task 1: CI

- [x] Add push and pull-request Node 24 checks for clean install, tests, typecheck, lint, build.
- [x] Install Chromium and run real desktop/mobile dev and production smoke tests with bounded startup and cleanup.
- [x] Preserve failure logs, screenshots, and verdicts as artifacts; test strict verdict validation.

## Task 2: Evidence labels

- [x] Test template/generated/passing/failed/stale/legacy/sanity-only source cases before implementation.
- [x] Implement a pure classifier, source digest in runner logs, and one reusable accessible badge.
- [x] Apply labels to Workbench, finding runs, saved audits, manual runs, and the interactive editor.
- [x] Replace unsafe claims that failed tests prove safety or passed status alone proves reproduction.

## Task 3: UI separation

- [x] Extract workbench editor, tabs, dialogs, shared configuration and orchestration into typed modules.
- [x] Extract pipeline address input, controls, settings modal, and paginated table; retain queue lifecycle ownership.
- [x] Verify component prop contracts, SSR render, full tests, types and build; independent review of combined diff.

## Verification notes

Local tests, types, lint, and production build pass. Real local browser execution remains blocked by the host network-interface syscall restriction; CI retains the real browser checks without bypassing it. No live database or fork execution was performed. Independent review found and fixed the empty-target evidence invalidation edge case.
