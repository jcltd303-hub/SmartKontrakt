# AI-PoC proof suite — one end-to-end proof per type

SmartKontrakt's AI review generates a Foundry PoC for every finding:
`buildAiReviewPrompt` (`src/lib/audit/ai-review.server.ts`) injects up to
three matching templates from the fallback PoC library
(`src/lib/audit/poc-fallbacks.ts`, generated from
`foundry/poc-fallbacks/` + `index.json`), the model fills them in, and the
workbench runs the result against a fork. The fallback templates
themselves are forge-verified — but an **AI-generated** PoC had never run
end-to-end. This suite closes that gap: **one proof per type** in
`foundry/poc-fallbacks/index.json` (46 types on current main).

## What a proof is

For each type, the suite:

1. **Deploys a vulnerable fixture** (`fixtures/NN-*.sol`, described in
   `manifest.json`) to a **local anvil** — a minimal contract that is
   vulnerable in exactly that type's way, plus any setup steps
   (funding, liquidity, approvals) the exploit needs.
2. **Builds the AI-review prompt through the app's real prompt path** —
   `prompt-path.ts` imports `buildAiReviewPrompt` and
   `selectPocFallbacks` from the repo sources and runs them against the
   fixture's source and finding. No re-implemented prompt logic.
3. **Obtains a PoC for the finding:**
   - *Live mode:* `generateAiSecurityReview()` from the app (prompt →
     OpenRouter → JSON extraction). If the app silently falls back to
     the template review (`source != "openrouter"`), the type is a
     **generation FAILURE** — a fallback is never reported as an AI pass.
   - *`--dry-run`:* the type's fallback **template** from the app's own
     `POC_FALLBACK_TEMPLATES` map, with the manifest's TODO adaptations
     applied (the constants a human would fill in for a real target).
     No LLM is called; statuses are labeled `DRY-*`.
4. **Wraps a bare snippet** via the repo's `poc-wrap`
   (`wrapPocSnippetWithReason`) under the same rule the workbench uses:
   no `contract PoC is Test` in the code → wrap.
5. **Runs it exactly like the Termux backend** (`termux-backend`):
   the PoC is written to `test/PoC.t.sol` in a scratch foundry project
   (the repo's `foundry/foundry.toml` + `lib/forge-std`), then
   `forge test --match-contract PoC` with `POC_TARGET`, `POC_RPC_URL`
   and `POC_FORK_BLOCK=0` in the environment, 120 s cap. The templates
   fork `POC_RPC_URL`, which the runner points at the local anvil, so
   fixtures live entirely on anvil — **no type needs a mainnet fork**.
6. **Repairs once on a compile error (live mode only)**, replicating the
   app's contract: `repairPocCode` (`src/lib/audit/deep-agent.server.ts`)
   gets the broken PoC plus the compiler output, returns a fixed PoC,
   and it is re-run **once** — the same one-repair bound as
   `runSmartPoc` in `src/lib/audit/foundry-backend.ts`.

## Verdicts

A type **PASSES** only when forge reports ≥1 matched test and zero
failures — the templates assert observable exploit state (attacker
balance / drained vault / flipped flag), never merely "the call
returned". Failure categories:

| category     | meaning                                                        |
|--------------|----------------------------------------------------------------|
| `generation` | no AI PoC was produced (incl. silent template fallback)        |
| `compile`    | the PoC did not compile (after the one repair, in live mode)   |
| `no-tests`   | forge matched zero tests under `--match-contract PoC` — the hollow-PASS trap; always a failure |
| `assertion`  | tests ran and failed — the exploit did not reproduce           |
| `infra`      | harness/environment failure (deploy, setup, RPC, timeout)      |

Results print as a table (`type | status | category | detail`) and are
written to `results.json` next to the runner. Exit code is 0 only when
every selected type passed.

## Running it

Dry run (no key needed; verifies harness, fixtures and templates):

```
node scripts/ai-poc-proof/run.mjs --dry-run
```

**Live run (the one command):**

```
OPENROUTER_API_KEY=... node scripts/ai-poc-proof/run.mjs
```

- The key is read only by the app modules via `prompt-path.ts`
  (`resolveOpenRouterConfig`); the runner never prints or persists it.
  Without a key, live mode exits with a clear message **before** doing
  anything — it never fakes a run.
- Model: `OPENROUTER_MODEL` if set, else the repo default
  (`resolveOpenRouterConfig`).
- Useful flags: `--type 07b` (run a prefix subset, e.g. one type),
  `--keep-work` / `--work <dir>` (keep the scratch foundry project),
  `--port <n>` (anvil port, default 18545).
- Prerequisites: `npm install` done in the repo (the prompt path pulls
  `@solidity-parser/parser` through the deep-agent module graph),
  `forge`/`anvil`/`cast` (foundry), and `forge-std` — taken from
  `foundry/lib/forge-std` or `$FORGE_STD_PATH` when present, otherwise
  cloned into the scratch project.
- Runs are sequential with modest pacing (OpenRouter budget:
  60 req/min); a full live run makes 46 generation calls, plus at most
  one repair call per compile failure.

## Layout

```
scripts/ai-poc-proof/
  run.mjs          the runner (plain Node, no build step)
  prompt-path.ts   thin bridge into the app's real modules, run with
                   tsx (repo-local node_modules/.bin/tsx, else
                   `npx -y tsx`); JSON in, JSON out;
                   commands: config | prompt | template | generate |
                   wrap | repair. `config` reports {hasKey, model} —
                   never the key.
  manifest.json    per type: fixture, deployments, target, setup
                   steps, and the dry-run template adaptations
  fixtures/        one minimal vulnerable contract set per type
  results.json     output of the most recent run
```

The suite adds files only — it modifies no app code.
