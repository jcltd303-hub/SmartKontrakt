# AI-PoC proof suite — one end-to-end proof per type

SmartKontrakt's AI review generates a Foundry PoC for every finding:
`buildAiReviewPrompt` (`src/lib/audit/ai-review.server.ts`) injects up to
three matching templates from the fallback PoC library
(`src/lib/audit/poc-fallbacks.ts`, generated from
`foundry/poc-fallbacks/` + `index.json`), the model fills them in, and the
workbench runs the result against a fork. The fallback templates
themselves are forge-verified — but an **AI-generated** PoC had never run
end-to-end. This suite closes that gap: **one proof per type** in
`foundry/poc-fallbacks/index.json` (47 types on current main).

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
     the template review (`source != "openrouter"`), the generation
     step retries — up to **3 attempts** with 5 s / 15 s backoff
     (`generation-retry.mjs`). Only generation retries: a generated
     PoC that fails compile/assertion is a result, never a re-roll.
     If every attempt falls back, the type is a **generation
     FAILURE** and is reported as **UNTESTED** — a fallback is never
     reported as an AI pass, and an untested type is never reported
     as a failed PoC. The attempt count is recorded per type as
     `generationAttempts`.
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
written to `results.json` next to the runner. Types in the
`generation` category are also listed separately as **UNTESTED** in
the summary — no AI PoC was generated for them, so nothing about
their exploit was measured. Exit code is 0 only when every selected
type passed (with `--only-failed`, the merged set — see below).

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
  `--port <n>` (anvil port, default 18545), `--only-failed` (re-run
  only what didn't pass — see below).
- Prerequisites: `npm install` done in the repo (the prompt path pulls
  `@solidity-parser/parser` through the deep-agent module graph),
  `forge`/`anvil`/`cast` (foundry), and `forge-std` — taken from
  `foundry/lib/forge-std` or `$FORGE_STD_PATH` when present, otherwise
  cloned into the scratch project.
- Runs are sequential with modest pacing (OpenRouter budget:
  60 req/min); a full live run makes one generation call per type
  (47), plus extra attempts only for types whose generation falls
  back (up to 3 each), plus at most one repair call per compile
  failure.

**Re-running only what didn't pass (`--only-failed`):**

```
OPENROUTER_API_KEY=... node scripts/ai-poc-proof/run.mjs --only-failed
```

Loads the existing `results.json` and runs only the types whose
recorded status is not a pass (`PASS` / `DRY-PASS` are the runner's
passing statuses; a type with no entry counts as not passing). The
results then **merge** over the previous file:

- entries for types that were not re-run are carried over untouched;
- a re-run type's fresh entry keeps its earlier attempt in
  `previousStatus` / `previousCategory` / `previousDetail`;
- the summary counts and the exit code judge the merged set;
- without the flag, behavior is unchanged: a full run overwrites
  `results.json` with only the types it ran.

A missing or unparseable `results.json` is a hard stop (exit 2,
nothing runs) — merging against a guessed base could silently drop
recorded proofs. If every selected type already passes, the runner
says so and leaves the file untouched. Merging is mode-agnostic (it
keys on the recorded statuses), so re-run in the same mode that
produced the file. `--type` composes: it narrows the selection
first, then `--only-failed` filters within it.

## Layout

```
scripts/ai-poc-proof/
  run.mjs          the runner (plain Node, no build step)
  generation-retry.mjs  the live-mode generation retry policy
                   (fallback detection + bounded retry loop),
                   unit-tested by
                   scripts/ai-poc-proof-generation-retry.test.mjs
  results-merge.mjs     the --only-failed selection/merge rules,
                   unit-tested by
                   scripts/ai-poc-proof-results-merge.test.mjs
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
