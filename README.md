# SmartKontrakt / Kiln

EVM contract audit workbench with a batch address pipeline, comprehensive audit archive, optional Supabase summary sync, and a local RAG knowledge base.

## Large runs

- Address summaries stay lightweight. Updating one item and its progress counters takes constant time; the table renders one page at a time.
- Full inspection reports use a cache capped at 50 entries and 16 MB of serialized data. Cache keys include the chain.
- The archive writer accepts at most 50 records and 1.4 MB of serialized input per request. Its pending buffer includes in-flight records and stops producers at 100 records or 8 MB.
- A single archive write is active at a time. Transient failures retry three times with exponential backoff. Persistent failures retain the batch, show the error, and stop the producer at capacity. Use **Flush Buffer** to retry.
- Stable scan IDs make retries safe after a lost response. Each transaction bulk-upserts headers and payloads and replaces findings and RAG chunks. Replaying a batch does not append duplicate chunks.
- Supabase summary sync uses its own bounded writer: one REST request per batch, minimal responses, finite retries, and surfaced errors. Pending summary acknowledgments are checkpointed and replayed after reload, even when the main archive already saved the report. Corrected saved connection settings apply to retries.
- IndexedDB stores all address summaries and updates only changed positions during processing. On reload, interrupted or unacknowledged results return to pending with the same scan ID. Keep the browser open until pending writes drain; full report bodies are not persisted in the browser checkpoint.
- Switching between pipeline and workbench views keeps the pipeline mounted. Pausing stops after the current address and drains both writers.

## Run and verify

Requires Node.js 22.16+ or 24 and npm.

```sh
npm ci
npm run dev
npm test
npm run typecheck
npm run build
```

`npm run benchmark:batch -- --database` runs 50,000 synthetic address dossiers against a fresh in-memory Postgres instance. It makes no RPC calls and never touches a remote database. Without `--database`, it measures the queue and writer against an in-memory sink.

Measured locally on 2026-10-15 with two findings and three RAG chunks per dossier:

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

The application has no account/tenant isolation, so deploy it only with access appropriate to your audit data.

Local development can use PGLite without a database connection. On Vercel, archive writes fail clearly when no Postgres URL is present rather than acknowledging writes into a temporary in-memory database.

## AI review via OpenRouter

AI threat-model reviews run server-side through OpenRouter (`POST https://openrouter.ai/api/v1/chat/completions`, OpenAI-compatible). No vendor SDK is used — just `fetch` with a bearer key.

- Set `OPENROUTER_API_KEY` in the Vercel project's production + preview environments (server-only, never a browser variable).
- Optional: set `OPENROUTER_MODEL` to pick the model (default `openai/gpt-4o-mini`). Any OpenRouter model id works.
- Without a key, reviews fall back to the deterministic template review (`source: "template"`) — the audit still completes.

## Optional Supabase summary sync

The pipeline's Supabase settings take a project URL, a publishable/legacy anon key, and an existing table name (default `kiln_batch_audits`). Secret and service-role keys cannot be used by the browser writer. The table must provide the summary columns sent by `toSupabaseBatchRow` in `src/lib/supabase.ts`, with `id` as a primary/unique key. Configure grants and RLS for your intended read, insert, and update access. A REST connection test does not create tables or prove write authorization.

Supabase sync stores lightweight completed summaries. The comprehensive archive uses the server's DATABASE_URL independently. **Load from Supabase** retrieves the latest 50 summaries; full local run recovery uses IndexedDB.
