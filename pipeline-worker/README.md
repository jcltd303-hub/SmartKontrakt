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

### ResNet1D screening (inside step 1)

Every entry also gets a ResNet1D pass over its runtime bytecode, inside
`analyzeAddress` — the worker injects the Node runner
(`src/lib/image-ml/resnet-node.server.ts`, the same ONNX model the
browser's Image ML panel runs). The result is stored on the record
(`contract_scans.resnet_json`, migration 0018), noted in the report's
inventory, and folded into the risk score as a bounded term (at most
+6, only when static analysis found something above info — see
`src/lib/audit/resnet-result.ts`). Cost: a one-time ~1s model load per
worker process, then ~0.2–0.5s per entry, serialized.

Model files resolve from `public/models/` in the repo checkout;
`SMARTKONTRAKT_RESNET_MODEL_DIR` overrides the directory. Fail-soft by
design: if the model is missing or broken, entries are analyzed and
stored exactly as before, with no `resnet_json` — screening never
fails an item.

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
     **Paste it raw.** Credentials are percent-encoded automatically at
     startup (`@`→`%40`, `#`→`%23`, `/`→`%2F`, `:`→`%3A`, space→`%20`), so a
     password with special characters works as-is; do not pre-encode it by
     hand. An already-encoded URI (what the Supabase dashboard gives you) is
     left untouched, so nothing is ever double-encoded.
   - `OPENROUTER_API_KEY` — only needed if you start a run with
     `aiSecondPass: true` or `deepAgent: true`. Auto-PoC (below) also
     uses it for PoC generation/repair when present, but runs without
     it — template/snippet PoCs still execute.
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
- **`refresh` decides how much of the archive a run re-does.** `stale` (default)
  skips rows the current analyzer wrote and re-analyses rows an older one wrote;
  `all` re-does everything; `none` treats any saved row as done, so only
  genuinely new addresses are analysed. The startup banner reports all three
  counts — `skipped`, `stale`, `new` — because the number that matters for
  planning is `new` plus whatever `stale` you are willing to pay for, not the
  file length.
- **Pause/stop** waits for the current item — including an in-flight
  agent loop — to finish first.
- `/status` reports `deepAgentRuns` (addresses that ran the agent) and
  `deepAgentConfirmed` (fork-confirmed findings total).

The full per-address pipeline — stage order, what each stage may write, the
failure behaviour of each, and the knobs — is in **`docs/pipeline.md`**.

## RPC endpoints (providers, round-robin, quota)

The analysis path takes a pluggable endpoint list. Comma-separated; an entry may be
scoped to one chain, and unscoped entries serve all of them:

```bash
RPC_URLS="https://eth-mainnet.g.alchemy.com/v2/KEY,ethereum:https://mainnet.infura.io/v3/KEY,https://rpc.ankr.com/eth"
RPC_MIN_INTERVAL_MS=50     # default 200 = 5 req/s; a keyed provider takes far more
```

Calls rotate round-robin across the configured endpoints, so several providers'
quotas are shared rather than spent in order. A `402`/`403`/`429` puts an endpoint
in a 60-second cooldown (a `5xx` or a network error, 15 seconds) and the next call
starts elsewhere; a success clears it. Cooldowns are per process, which is why
sharding multiplies throughput instead of just splitting the list. With no
`RPC_URLS` set, the built-in public endpoints are used exactly as before.

The analysis path makes ~3 RPC calls per address plus view probes, so at
`RPC_MIN_INTERVAL_MS=50` one process can sustain ~20 req/s ≈ 2–4 addresses/second
from RPC pacing alone.

## Running the list in parallel (shards)

The worker processes one address at a time — measured at ~7-20 s each, so 100k
addresses is 8-23 days of wall clock from a single process. The work is I/O-bound
and the archive keys are `(chain, address)`, so the cheapest speedup is more
processes over disjoint slices:

```bash
# four terminals, or four hosts, same DATABASE_URL and the same file
curl -s -X POST localhost:8788/start -H 'content-type: application/json' \
  -d '{"addressesFile":"new.csv","chainId":"ethereum","refresh":"none","shard":"1/4"}'
# ... shard "2/4", "3/4", "4/4" on the other workers (different ports)
```

The partition is a hash of the address, not a position in the file, so it is
deterministic: a shard restarted tomorrow owns the same addresses it had today and
`refresh: "none"` skips exactly what it already saved. Shards are disjoint and
balanced within 5% (pinned in `shard.test.ts`), and a malformed value like `"5/4"`
is rejected at `/start` rather than silently analysing the whole list four times.

Each worker needs its own port (`PORT=8789 bash pipeline-worker/start.sh`).

## Endpoints

`GET /` (or `/health`) returns the route index, and an unknown path returns
`{"error":"not found","path":…,"routes":{…}}` rather than a bare `not found` —
so a wrong port or a stale build is diagnosable from the response. Trailing
slashes are normalised (`/health/llm/` works).

| Route | Purpose |
| --- | --- |
| `GET /status` | run state, counters, LLM health |
| `GET /health/llm` | LLM verdict in one line |
| `GET /freshness` | how stale the analysed set is |
| `POST /start` `/pause` `/resume` `/stop` | run control |

## Is the LLM working? (poll without reading logs)

The worker records `aiStatus` per saved record, but that is only visible by
reading the database afterwards. `llm-health.ts` keeps a per-run tally and
`/health/llm` returns it in one line:

```bash
curl -s localhost:8788/health/llm | jq .
```

```json
{
  "verdict": { "state": "smooth", "reason": "18/18 usable replies" },
  "calls": 18, "ok": 18, "empty": 0, "error": 0, "unavailable": 0,
  "consecutiveFailures": 0, "lastError": null, "lastOkAt": "2026-10-27T18:41:02Z",
  "model": "(default)", "keyPresent": true
}
```

Four outcomes, and the distinction between the middle two is the point:

| outcome | meaning | verdict effect |
| --- | --- | --- |
| `ok` | usable text | good reply |
| `empty` | the call succeeded but produced nothing usable — a 200 with an empty body, or a narrative the output contract rejected | **counted as a failure**; this is the failure a log hides |
| `error` | the call was attempted and threw | failure |
| `unavailable` | no `OPENROUTER_API_KEY` | not a failure: `off`, static-only run |

Verdicts: `smooth` (≤20% failures), `degraded` (>20% failures, **or the second
pass is on and never called**), `dead` (3 consecutive failures — the same count the
PoC breaker uses), `off` (no key, **or `aiSecondPass` false**), `waiting` (no calls
because no item has completed yet).

`calls=0` is ambiguous on its own, so the script reads `/status` too:

| Counters | Run state | Verdict |
| --- | --- | --- |
| `calls=0`, key present | `aiSecondPass: false`, items completed | **`off`** — nothing ran; a key alone does not enable the pass |
| `calls=0`, key present | `aiSecondPass: true`, items completed | **`degraded`** — enabled and never called: the call site is unreachable |
| `calls=0` | nothing completed yet | `waiting` |

That distinction exists because the first version of this script printed
`SMOOTH — no LLM calls yet` for a run with a key present and zero calls, which is
the opposite of what a reader takes from the word "smooth".

The worker also prints one `[worker] LLM degraded|dead: …` line at the moment the
state changes, so the log and the endpoint agree.

Watching a run:

```bash
watch -n 30 'curl -s localhost:8788/health/llm | jq -c "{s:.verdict.state,r:.verdict.reason,calls,ok,empty,error}"'
```

Or let the script do the judging, with an exit code a monitor can read:

```bash
node scripts/llm-healthcheck.mjs            # exit 0 smooth/off, 1 degraded, 2 dead/unreachable
node --env-file=pipeline-worker/.env scripts/llm-healthcheck.mjs --db   # + last 24h of ai_status
node scripts/llm-healthcheck.mjs --url http://host:8788
```

`--db` is the retrospective check: the worker records `ai_status` per scan, so a
night whose narratives were all fallback text shows up as a distribution, which
is how you find out the second pass was off for a run you have already finished.

The script uses `node:http`, not `fetch`, deliberately: on Node 20 the global
fetch lazily instantiates undici's WASM llhttp parser, and where WASM allocation
is unavailable (constrained containers, some CI runners) every request fails with
`WebAssembly.instantiate(): Out of memory` — an error that reads like a network
fault and sends you debugging the wrong thing. `node:http` needs no WASM.

A run whose narratives are all fallback text with `error: 0` and `empty: 0` means
`aiSecondPass` was never turned on — check `aiSecondPass` in `/status` before
suspecting the model.

## Auto-PoC (automatic PoC for high/critical findings)

On by default (`autoPoc: false` in the `/start` body turns it off).
When an entry's saved report contains a high or critical finding, the
worker runs the adjudication chain for each eligible finding right
after the entry is persisted — the same gen → run → save machinery
as the PoC Audits page's Adjudicate button, no human tap:

- **Gate:** severity `high` or `critical`, PoC-eligible under the
  feed's rules (presence-only bytecode findings are excluded unless
  corroborated), and no verdict already stored on the finding.
  Bytecode-only entries qualify too.
- **Per finding:** PoC prepared from the finding (snippet or fallback
  template), LLM generation/repair via OpenRouter when the draft has
  no executable test or fails to compile, one Foundry backend run,
  verdict saved onto the finding row (plus the run-history row).
  Without an `OPENROUTER_API_KEY`, generation/repair return nothing
  and outcomes still save honestly — template/snippet PoCs run.
- **No attempt cap (removed 2026-10-27).** Every PoC-eligible
  finding is attempted. There used to be an `autoPocCap` (default 25
  backend attempts per run) and it was a silent recall ceiling: every
  flagged finding past the 25th kept a static-only record, which is
  precisely where a PoC is most useful. The identical-code dedupe
  below already removes the duplicate work the cap was protecting the
  backend from, and the circuit breaker still stops a broken backend.
  Size a run by how long you are willing to wait, not by a constant.
- **Identical-draft dedupe:** sibling findings of the same detector
  often prepare byte-identical PoC code. Within one entry, the code
  that would be sent to the backend is hashed (SHA-256); a repeat is
  not executed again — the sibling saves the same verdict, its run
  output names the finding whose run it shares, and the save counts
  as **shared** (`autoPocShared`), never as an attempt, so shared
  saves do not consume cap. Only verdicts about the code itself are
  shared (passed / failed / no_tests / value-guard skip / compile
  error); backend-unreachable and RPC/fork outcomes are never
  cached. The cap is checked before each finding's chain (whether a
  draft is a repeat is only known after generation), so once the
  backend budget is spent, an entry's remaining findings wait for
  the app's adjudication queue even if some would have shared.
- **Backend down:** 3 consecutive infra failures (backend unreachable
  / RPC-fork failure) trip a circuit breaker for the rest of the run
  (status shows `autoPocBackendDown: true`); the static pipeline
  keeps going. Restart the backend and start a new run to re-enable.
- `/status` reports the tally: `autoPocAttempted` (backend
  attempts), `autoPocPassed`, `autoPocFailed`, `autoPocErrors`,
  `autoPocSkipped`, `autoPocShared`.

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
