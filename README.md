# SmartKontrakt / Kiln

EVM contract audit workbench with a batch address pipeline, comprehensive audit archive, optional Supabase summary sync, and a local full-text knowledge base.

## Large runs

- Address summaries stay lightweight. Updating one item and its progress counters takes constant time; the table renders one page at a time.
- Full inspection reports use a cache capped at 50 entries and 16 MB of serialized data. Cache keys include the chain.
- The archive writer accepts at most 50 records and 1.4 MB of serialized input per request. Its pending buffer includes in-flight records and stops producers at 100 records or 8 MB.
- A single archive write is active at a time. Transient failures retry three times with exponential backoff. Persistent failures retain the batch, show the error, and stop the producer at capacity. Use **Flush Buffer** to retry.
- Stable scan IDs make retries safe after a lost response. Each transaction bulk-upserts headers and payloads and replaces findings and knowledge-base chunks. Replaying a batch does not append duplicate chunks.
- Supabase summary sync uses its own bounded writer: one REST request per batch, minimal responses, finite retries, and surfaced errors. Pending summary acknowledgments are checkpointed and replayed after reload, even when the main archive already saved the report. Corrected saved connection settings apply to retries.
- IndexedDB stores all address summaries and updates only changed positions during processing. On reload, interrupted or unacknowledged results return to pending with the same scan ID. Keep the browser open until pending writes drain; full report bodies are not persisted in the browser checkpoint.
- Switching between pipeline and workbench views keeps the pipeline mounted. Pausing stops after the current address and drains both writers.

## Run and verify

Requires Node.js 22.16+ or 24 and npm.

```sh
npm install
npm run dev
npm test
npm run typecheck
npm run lint
npm run build
```

> No `package-lock.json` is committed yet, so use `npm install` (not `npm ci`).
> Commit a lockfile (`npm install` once, then commit the generated file) and CI
> can switch to `npm ci` for reproducible installs. `.github/workflows/ci.yml`
> runs typecheck, lint and test on every push and pull request.

`npm test` runs the script unit tests, the `src/lib` unit tests, and the detector
self-check (`npm run check:detectors`).

`npm run benchmark:batch -- --database` runs 50,000 synthetic address dossiers against a fresh in-memory Postgres instance. It makes no RPC calls and never touches a remote database. Without `--database`, it measures the queue and writer against an in-memory sink.

Measured locally on 2026-10-15 with two findings and three knowledge-base chunks per dossier:

| Measurement | Result |
| --- | ---: |
| Audit dossiers | 50,000 |
| Batches | 1,000 |
| Data statements | 6,000 |
| Maximum buffered records | 100 |
| Maximum buffered serialized bytes | 115,800 |
| Processing time, excluding database startup | 26.64 seconds |
| Peak JavaScript heap, including the local database workload | 105.54 MiB |

These are synthetic local results. Real RPC latency, report size, network distance, and database capacity determine production throughput. Each batch also uses BEGIN/COMMIT on a networked database. Serialized byte caps bound retained payloads; they are not exact JavaScript object heap measurements.

## Vercel and Postgres

The Vite/Nitro build emits `.vercel/output` with the Vercel preset. Use the GitHub integration with this repository and `npm run build` as the build command. Keep the existing platform/PWA middleware enabled.

**Vercel Supabase wiring (the production path):** connect the Vercel Supabase integration to this project. It syncs `POSTGRES_URL`, `POSTGRES_PRISMA_URL`, `POSTGRES_URL_NON_POOLING`, `SUPABASE_URL`, and the Supabase keys for preview + production. The server reads those vars directly — no manual copy-paste:

- Runtime (`src/lib/db.ts`) prefers `DATABASE_URL` if set, then `POSTGRES_PRISMA_URL` → `POSTGRES_URL` → `POSTGRES_URL_NON_POOLING` (the integration's pooler URLs, right for serverless traffic).
- Build-time migrations (`scripts/migrate-vercel.mjs`, run by `npm run db:migrate`) prefer `DATABASE_URL`, then `POSTGRES_URL_NON_POOLING` (direct, best for DDL), then the pooler URLs. Migrations apply on every deploy and are recorded in `_migrations`, so they run once and are safe to re-run.
- `DATABASE_URL` remains as an optional explicit override. Do not put database credentials in browser variables or commit them.

The application has **no sign-in**. Every read and write is unauthenticated, so deploy it only with access appropriate to your audit data. To lock down a public deployment, set `KILN_ADMIN_TOKEN` — mutating server functions (save, delete, AI calls, database-config changes) then require that value in the `x-kiln-admin-token` header. The browser attaches it automatically once `localStorage.setItem("kiln_admin_token", "<the token>")` is set; an operator can also inject the header at a reverse proxy. With the variable unset the app is open, as before. See `.env.example`.

Local development can use PGLite without a database connection. On Vercel, archive writes fail clearly when no Postgres URL is present rather than acknowledging writes into a temporary in-memory database.

## AI via OpenRouter (free tier)

All model calls run server-side through OpenRouter (`POST https://openrouter.ai/api/v1/chat/completions`, OpenAI-compatible). No vendor SDK is used — just `fetch` with a bearer key.

Models are chosen **per purpose** from OpenRouter's free tier (verified 2026-10-21):

| Purpose | Default model | Used by |
| --- | --- | --- |
| `review` | `nvidia/nemotron-3-ultra-550b-a55b:free` | threat model, pipeline second pass |
| `code` | `thinkingmachines/inkling-small:free` | Foundry PoC synthesis + repair (GRE-Engine) |
| `json` | `qwen/qwen3.8-27b:free` | Deep Agent hypotheses, SmartPoC DV extraction/verdict |

- Set `OPENROUTER_API_KEY` in the Vercel project's production + preview environments (server-only, never a browser variable).
- Override one purpose with `OPENROUTER_MODEL_REVIEW` / `_CODE` / `_JSON`, or all of them with `OPENROUTER_MODEL`. Any OpenRouter model id works.
- The free endpoints share a per-account daily quota (50/day, or 1000/day after a one-time $10 top-up) and run 4-bit quantised; ids churn, so re-check the free-models collection before relying on one.
- Without a key, reviews fall back to the deterministic template review (`source: "template"`) — the audit still completes.

## SmartPoC-aligned PoC validation

The PoC pipeline follows **SmartPoC** (Chen et al., *SmartPoC: Generating Executable and Validated PoCs for Smart Contract Bug Reports*, arXiv:2511.12993) end to end:

1. **Bug-Context Extraction (BCE)** — `src/lib/audit/smartpoc/bce.ts`. From the finding it slices the contract to the bug-relevant functions, expanding along semantic links (inverse pairs like deposit/withdraw, state-coupled functions) and structural links (modifiers, wrapper → underscore internal), plus the call graph ±1 hop and the constructors/initializers. The Deep Agent prompt uses this slice instead of the whole file.
2. **Generate-Repair-Execute Engine (GRE-Engine)** — `src/lib/audit/smartpoc/engine.server.ts`. Generate → **pre-execution sanitizer** (`sanitize.ts`: align `pragma`/`abicoder` to the target compiler, enforce the `forge-std` import, and strip any re-declaration of the target's own functions that would mask the bug) → execute → **post-execution debugger** (feed compiler/runtime diagnostics back, up to the retry budget `B = 5`).
3. **Action-State Differential Verification (DV)** — same file. Extract an action + observable state from the public ABIs, instrument the PoC with pre/post-trigger state queries (`SMARTPOC_STATE` markers), execute, and let the model issue a strict `VALIDATED` / `NOTVALIDATED` verdict. Only validated PoCs become findings.

The headless pipeline worker runs the full pipeline per flagged address. Settings mirror the paper: temperature 0.3, retry budget B = 5, Foundry fork tests.

## Risk score

`src/lib/audit/risk.ts` scores 0-100 by **dominance, not a sum**. The old model
was `min(100, Σ weight)` with `critical: 28`, so a single critical scored 28 and a
critical plus a high scored 42 — a critical contract read as "medium". Now the
worst finding sets the floor (`critical: 78`, `high: 55`, `medium: 30`,
`low: 12`, `info: 0`), the rest add bounded pressure (so ten mediums can never
outrank a critical), and a fork-PoC-confirmed exploit adds proof weight. Bands
are 75 / 50 / 25 — the same thresholds the UI filters on, so the number, the
colour and the filter agree. Value at risk is kept as a separate axis.

## Idempotency

Everything expensive is keyed so it is not repeated:

- **PoC runs** — a run's identity is `(finding, sha3-256 of the executed source)`
  (`src/lib/audit/poc-run-key.ts`, migration 0013). Re-saving the same proof
  **upserts** the run row instead of appending a duplicate, and the unique index
  makes the identity a database guarantee. `needsSmartPoc` already refuses to
  re-run a proof whose input digest is unchanged.
- **Findings dispositions** — triage states live in `contract_scans.triage_states_json`,
  written through the batched upsert, so a save is a row update, not an append.
- **Tabs** — the workbench tabs are always-mounted pure renderers over a single
  controller, so switching tabs runs nothing. Loading a saved record rehydrates
  the report, probes, AI review, triage states and per-finding PoC verdicts.

## Balance guard and the balance column

Every address audit reads the target's native balance (`eth_getBalance`) at analysis time and stores it as `contract_scans.balance_wei` — a decimal wei string, since balances exceed 2^53. `NULL` means "not read" (no RPC answered) and is deliberately distinct from `'0'` (a confirmed empty balance). The balance renders prominently in the workbench scorecard, the Records table, the Recent PoC audits list, and the batch pipeline.

Before any fork PoC run the target is valued (see *Value at risk* below): a **confirmed zero total skips the run** (nothing at stake), returning status `skipped` with the reason in the logs. An incomplete valuation does *not* skip — unknown is not zero. Pass `skipZeroValue: false` to force a run. The balance shown alongside it is the native coin only, read at the latest block.

## Value at risk

Every address audit is valued in USD at analysis time — native coin plus ERC-20
holdings — and stored as `contract_scans.value_usd` (with the full breakdown in
`value_json`). The sources are keyless: public JSON-RPC for the native balance,
[Blockscout](https://www.blockscout.com/) for token balances and per-chain native
prices, and [DefiLlama](https://defillama.com/) for any token Blockscout leaves
unpriced. Set `ETHERSCAN_API_KEY` to prefer Etherscan's ABI endpoint when it is
available.

The Records tab sorts and filters by value (funded / zero / not valued) and shows
a running **value at risk** total for the current selection; the batch pipeline
queue carries a value column too.

`complete` is the flag that matters: a valuation is only complete when every
provider answered and every holding was priced. An incomplete valuation is
*unknown*, never zero, so it can never trigger a skip.

## Target ABI, gathered once

`src/lib/audit/abi.ts` gathers the target's ABI — Sourcify `metadata.json`
first, then Etherscan (with a key), then a heuristic ABI rebuilt from what the
analyzer already parsed (functions with their selectors, and event topics).
It is stored with the scan (`abi_json` / `abi_source`) so a PoC run in **any**
context reuses it instead of re-fetching. At PoC time the chosen fallback
template is tailored additively: the real `ITarget` interface is prepended to
the template, and the generation prompt is given the same surface, so the model
starts from the contract's actual signatures rather than an invented one.

## How the PoC library is grounded in real code

The library is deliberately two layers, because the two artifacts have different
jobs and only one of them can run against a stranger's contract:

| Layer | What it is | Why |
| --- | --- | --- |
| `foundry/poc-fallbacks/` | tailored **pattern** harnesses, wired to the target's real ABI | must run against any deployed target, whose ABI and storage layout differ from any dataset contract |
| `foundry/poc-fixtures/` | verbatim, modernized **ports** of specific SmartBugs Curated contracts + the harness that reproduces them | ground truth: proves the pattern actually reproduces a known bug, and — run against a fixed variant — does not fire on patched code |

This mirrors how the field measures itself: [Immunefi's PoC templates](https://github.com/immunefi-team/forge-poc-templates)
are reusable *patterns* per vulnerability class precisely because "design
patterns [are] commonly repeated across different protocols"; [SmartBugs 2.0](https://joaoff.com/publication/2023/ase-smartbugs2/)
and [PoPoC](https://github.com/ASSERT-KTH/PoPoC) exist as *benchmarks* with
reproduction environments; and [SmartPoC](https://arxiv.org/abs/2511.12993)
reports confirmation precision/recall against SmartBugs-Vul and FORGE-Vul.

Every template records its `provenance` — `dataset` (with the SmartBugs paths it
derives from) or `modelled` (with a note saying why the dataset has no
equivalent, e.g. no ERC-20-fee or oracle case). A test enforces that.

`npm run check:fixtures` runs the fixture suite (needs `forge`).

## Fallback PoC library

`foundry/poc-fallbacks/` holds one working Foundry harness per scenario, organised by the [SmartBugs Curated](https://github.com/smartbugs/smartbugs-curated) DASP taxonomy. A finding starts from the harness for its detector, or — when the detector has none — the harness for its SmartBugs category. `npm run check:fallbacks` compiles every harness with Foundry; see `docs/smartbugs-alignment.md`.

## Optional Supabase summary sync

The pipeline's Supabase settings take a project URL, a publishable/legacy anon key, and an existing table name (default `kiln_batch_audits`). Secret and service-role keys cannot be used by the browser writer. The table must provide the summary columns sent by `toSupabaseBatchRow` in `src/lib/supabase.ts`, with `id` as a primary/unique key. Configure grants and RLS for your intended read, insert, and update access. A REST connection test does not create tables or prove write authorization.

Supabase sync stores lightweight completed summaries. The comprehensive archive uses the server's DATABASE_URL independently. **Load from Supabase** retrieves the latest 50 summaries; full local run recovery uses IndexedDB.
