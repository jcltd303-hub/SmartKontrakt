# Pipeline worker — headless address pipeline that survives browser close

The browser Address Pipeline dies when the browser closes (its checkpoint
lives in IndexedDB). This worker runs the **same per-item loop** in Node on
your phone (proot Ubuntu in Termux), saves to the same Supabase tables, and
keeps running until you stop it. The browser tab becomes a monitor.

## What it does

For each address in your file, in order:

1. `analyzeAddress` (Sourcify source → else RPC bytecode → Kiln static
   analysis), retried 2x — every address is a contract, failures are
   treated as transient provider hiccups, exactly like the browser loop.
2. Best-effort `detectProxyArchitecture` + `probeContractInterfaces` in
   parallel with the analysis.
3. Optional per-item OpenRouter `secondPass` (default **off**).
4. Accumulate records and bulk-save via `writeAuditBatch` (up to 50
   records, byte-capped, retry 3x with backoff, plus a 30s max-age flush).

Rate limits come free from the reused lib modules: RPC 5/s, Sourcify 2/s,
OpenRouter 60/min.

## Setup

1. Install Node + npm + git in proot Ubuntu (once):
   ```bash
   apt update && apt install -y git nodejs npm curl gh
   ```
2. Clone the repo (private — use the `gh` device flow):
   ```bash
   gh auth login
   gh repo clone jcltd303-hub/SmartKontrakt
   cd SmartKontrakt
   ```
3. Copy the env template and fill it in:
   ```bash
   cp pipeline-worker/.env.example pipeline-worker/.env
   ```
   - `DATABASE_URL` — **required**. Supabase dashboard → your project →
     Settings → Database → **Connection string → URI, pooler mode**
     (host ends in `pooler.supabase.com`, port **6543**). The worker
     refuses to start a run without it — it never falls back to a
     bundled default, so a multi-day run can't land in the wrong database.
   - `OPENROUTER_API_KEY` — only needed if you start a run with
     `aiSecondPass: true` or `deepAgent: true`.
   - `FOUNDRY_BACKEND_URL` — optional, default `http://127.0.0.1:8787`.
     Only used when `deepAgent: true` (PoC runs). The Foundry backend
     must be running (`bash scripts/termux-start-all.sh` boots it).
4. Put your addresses file on the phone, e.g. `~/addresses.csv` (CSV or
   one address per line; first column = address, optional label column 2,
   optional chain column 3; headers and duplicates skipped).

## Run

```bash
# in Termux (keeps Android from killing the worker mid-run):
termux-wake-lock
# in proot Ubuntu:
bash pipeline-worker/start.sh
```

The worker stays alive serving its API. Start a run from the app's
Address Pipeline tab (worker monitor panel), or with curl:

```bash
curl -s -X POST http://127.0.0.1:8788/start \
  -H 'Content-Type: application/json' \
  -d '{"addressesFile": "/root/addresses.csv", "chainId": "ethereum", "delayMs": 600}'
curl -s http://127.0.0.1:8788/status | head -c 600
curl -s -X POST http://127.0.0.1:8788/pause
curl -s -X POST http://127.0.0.1:8788/resume
curl -s -X POST http://127.0.0.1:8788/stop
```

Ctrl+C stops it gracefully: finish the current item, flush pending
records, exit 0. A second Ctrl+C exits immediately.

## Deep Agent (agentic exploit search, gated)

`deepAgent: true` runs the same propose → fork-PoC → reward → deeper
loop as the workbench AI tab, but headless, per flagged address:

```bash
curl -s -X POST http://127.0.0.1:8788/start \
  -H 'Content-Type: application/json' \
  -d '{"addressesFile": "/root/addresses.csv", "chainId": "ethereum", "aiSecondPass": true, "delayMs": 600, "deepAgent": true, "deepAgentMaxItems": 250, "deepAgentMinSeverity": "high"}'
```

- **Gate:** only addresses whose static analysis found ≥ 1 finding at
  `deepAgentMinSeverity` (`"high"` default; `"critical"` or `"medium"`).
  Bytecode-only items are skipped (no source for hypotheses).
- **Per address:** at most 3 LLM rounds × 2 hypotheses; each PoC runs on
  the Foundry backend (`:8787`) against a live-net fork. Passed = a new
  finding on the record (confidence high, PoC in `exploit_solidity`).
  Refuted hypotheses steer the next round and are not persisted.
- **Budget:** `deepAgentMaxItems` caps agent addresses per run (default
  250, `0` = unlimited). Each costs up to 3 LLM calls + up to 6 PoC
  runs (each up to 120s backend cap), so leave the cap on for a 43k run.
- **Backend down:** if the PoC backend is unreachable, the agent stops
  spending LLM calls for the rest of the run (status shows
  `deepAgentBackendDown: true`) and the static pipeline keeps going.
  Restart the backend and start a new run to re-enable it.
- **Pause/stop** waits for the current item — including an in-flight
  agent loop — to finish first.
- `/status` reports `deepAgentRuns` (addresses that ran the agent) and
  `deepAgentConfirmed` (fork-confirmed findings total).

## Resume and freshness

No checkpoint file. On `/start` the worker queries Supabase for saved
`(chain, address)` pairs — the same resume semantics as the browser's
Resume-from-Supabase. Restarting after a crash or a stop re-skips what
is already done. Progress is also written to
`pipeline-worker/status.json` on every flush.

**Resume is version-aware.** Every saved record carries a stamp naming
the analyzer that produced it (`analyzer_version`, migration 0014): a
baseline string plus a fingerprint computed from the detector set and
the scoring model. A row is skipped only when its stamp matches the
current analyzer. Records written by older code — including every row
predating the column, which is NULL and therefore stale by definition —
are **re-analyzed** rather than skipped.

That is what "freshen the archive" means operationally: after any change
to detectors, scoring, value-at-risk, ABI gathering or the PoC pipeline,
start a run and the stale rows refresh themselves. There is no wipe step
and no manual list to maintain.

The `refresh` field on `/start` selects the policy:

| `refresh` | Behaviour |
| --- | --- |
| `stale` (default) | skip rows the current analyzer saved; re-analyze the rest |
| `all` | re-analyze every address in the file, ignoring the archive |
| `none` | legacy: any saved row counts as done, stale or not |

Migration 0014 must be applied first — the worker preflights for the column and
tells you how to apply it (reconnect the Supabase database in the app) rather
than failing with a raw SQL error.

Ask what a freshen would cost before committing to a long run:

```sh
curl -s http://127.0.0.1:8788/freshness
# { "total": 43157, "current": 0, "stale": 43157, "analyzer": "2026-10-21.1+..." }
```

The startup log and `/status` both report `stale` alongside `skipped`, so
you can see how much of the run is a refresh.

## Safety

- Binds `127.0.0.1` only (port `PORT`, default 8788). Nothing is exposed.
- Same rate limits and retry policy as the browser pipeline.
- `writeAuditBatch` is upsert-based: re-running an address replaces its
  dossier, never duplicates it.
- No keys are written anywhere except your own `pipeline-worker/.env`,
  which is gitignored — never commit it.
- The worker never broadcasts transactions or spends anything; analysis
  is read-only (Sourcify + `eth_getCode` + static analysis).
