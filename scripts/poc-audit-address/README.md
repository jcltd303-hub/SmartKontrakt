# poc-audit-address — one address, audited end to end, headlessly

Runs the app's own audit pipeline against a single deployed contract
and executes the generated PoC on a fork of the live chain. Built for
CI (`.github/workflows/poc-audit-address.yml`) but runnable anywhere
the repo runs.

```bash
OPENROUTER_API_KEY=... node scripts/poc-audit-address/run.mjs \
  --address 0x... [--chain ethereum] [--block 19000000] \
  [--rpc https://...] [--out poc-audit-out] [--keep-work]

# Key-free smoke path — fetch + analysis only:
node scripts/poc-audit-address/run.mjs --address 0x... --analyze-only
```

## How it works (composition, not a parallel engine)

`run.mjs` is the driver; `bridge.ts` is a tsx bridge into the app's
real modules, on the same pattern as `scripts/ai-poc-proof/`:

| Step | App code that does it |
| --- | --- |
| Fetch + analyze the address | `analyzeAddress` (`src/lib/audit/address-fetcher.ts`) — Sourcify verified source, else runtime bytecode |
| Pick the finding to test | `pocAuditEligibility` (`src/lib/audit/adjudication.ts`), highest severity first, `critical_and_high` scope — the PoC feed's rule |
| Generate the review + PoC | `generateAiSecurityReview` (`src/lib/audit/ai-review.server.ts`) |
| Wrap a bare snippet | `wrapPocSnippetWithReason` (`src/lib/audit/poc-wrap.ts`) |
| Repair a compile error (once) | `repairPocCode` (`src/lib/audit/deep-agent.server.ts`) |
| Classify forge logs | `isPocCompileError` / `isRpcOrForkFailure` (`src/lib/audit/foundry-backend.ts`) |
| Execute the PoC | `forge test --match-contract PoC` with `POC_TARGET` / `POC_RPC_URL` / `POC_FORK_BLOCK` in env, 120s cap — the backend's exact invocation; the templates create the fork themselves, so no anvil is needed |

Scope, deliberately: **one PoC per run** — the single highest-severity
eligible finding. Re-run the audit to test another finding (fix or
exclude the first and it falls to the next). RPCs rotate through the
chain's public list (`address-fetcher.ts`) on RPC/fork failures only
— never on a verdict, never on a compile error.

## Output bundle (`--out` dir)

`report.json` (full analysis), `source.sol`, `findings.json`,
`review.json`, `poc-generated.sol` (as generated), `PoC.t.sol` (as
executed, post-wrap/repair), `forge.log`, and `verdict.json` — the
machine-readable summary, also printed on stdout.

Verdict semantics mirror `src/lib/audit/poc-outcome.ts`: `passed`
means the exploit reproduced **on the fork only**; `failed` is a real
non-reproduction; `no_tests` (forge matched zero tests) is never a
pass; `error` is a compile failure after the one repair.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | The audit ran to an end state (`passed` / `failed` / `no_tests` / `error`), or `--analyze-only` completed |
| 1 | Infrastructure error (fetch/RPC outage on every endpoint, harness failure) |
| 2 | Preflight: `OPENROUTER_API_KEY` not configured (live mode), or bad arguments |
| 3 | Nothing to test — no code at the address, no findings, or no PoC-eligible finding |
| 4 | Generation fell back to the structured template — the address is UNTESTED, not failed |

The key is only ever read by the app modules via `bridge.ts`; neither
file prints or persists it.
