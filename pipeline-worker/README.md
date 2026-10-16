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
     `aiSecondPass: true`.
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

## Resume

No checkpoint file. On `/start` the worker queries Supabase for
already-saved `(chain, address)` pairs and skips them — the same resume
semantics as the browser's Resume-from-Supabase. Restarting after a
crash or a stop re-skips everything already saved. Progress is also
written to `pipeline-worker/status.json` on every flush.

## Safety

- Binds `127.0.0.1` only (port `PORT`, default 8788). Nothing is exposed.
- Same rate limits and retry policy as the browser pipeline.
- `writeAuditBatch` is upsert-based: re-running an address replaces its
  dossier, never duplicates it.
- No keys are written anywhere except your own `pipeline-worker/.env`,
  which is gitignored — never commit it.
- The worker never broadcasts transactions or spends anything; analysis
  is read-only (Sourcify + `eth_getCode` + static analysis).
