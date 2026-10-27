# The address audit pipeline

What happens to one address, in order, and what each stage is allowed to write.
Scope of this document: the **static + PoC** pipeline. The LLM narrative pass and
the agentic search are deferred (see "Deferred stages" at the end) — the code is
present and off, not deleted.

## Per address

| # | Stage | Runs | Cost | Writes |
| --- | --- | --- | --- | --- |
| 1 | **Fetch source** — Sourcify, then Blockscout | always | 1–2 HTTP | — |
| 2 | **Fetch runtime bytecode** | always, even with source | 1 RPC | `runtimeBytecode` (inventory only when source exists — bytecode findings are deliberately not merged) |
| 3 | **Balance + ABI** | always | 1 RPC + explorer | `inventory.abi`, `balance_wei`, `value_usd` |
| 4 | **4byte selectors** | when the selector cache is passed | cached lookups | selector names on ABI-less contracts |
| 5 | **Proxy detection** ∥ **view probes** | parallel with 6, best-effort, never fails the item | RPC | `proxy_info_json`, `probes_json` |
| 6 | **Static rules** (`detect.ts`, 60 detectors / 11 families) | always | CPU | findings, with reachability class, family, gate, confidence basis |
| 7 | **Initializer gate + live state** | when the source has an initializer | RPC | gate text on the findings |
| 8 | **ResNet screen** over runtime bytecode | always, verified or not | ONNX inference | bounded contribution to `riskScore` |
| 9 | **Auto-PoC** per PoC-eligible high/critical finding | `autoPoc` (default **on**) | LLM + Foundry fork, serialised | `poc_status`, `poc_code`, `poc_output`, plus a `finding_poc_runs` row |
| 10 | **Persist** | per item, batched | DB | `contract_scans` + `findings`, stamped with `analyzer_version` |

Two orderings that matter and are easy to get wrong:

- **The rules run before any model.** Every finding comes from stage 6. The model
  in stage 9 writes *exploit code*, not findings. That is why a run with the
  narrative pass off still produces a complete, ranked report.
- **Bytecode is fetched even when source exists.** Stage 2 feeds the CFG/opcode
  view and the ResNet screen; it is not a fallback for missing source. Unverified
  contracts take a separate bytecode-only path where bytecode *findings* do apply.

## What a run is made of

```
addresses file → [dedupe] → [refresh filter] → queue
   → per item: stages 1–10 → flush to DB → next item
```

The `refresh` filter is the difference between a 15-hour run and a 2-hour one:

| `refresh` | Skips | Analyses |
| --- | --- | --- |
| `stale` (default) | rows the current analyzer wrote | new + stale |
| `all` | nothing | everything in the file |
| `none` | any row that exists, current **or** stale | new only |

The banner reports all three counts (`skipped`, `stale`, `new`). Rows are stamped
with `analyzer_version`, so a rule change makes them stale and a later
`refresh: stale` re-does exactly those.

## Failure handling, stage by stage

| Failure | Behaviour |
| --- | --- |
| No verified source | bytecode-only path; findings come from bytecode + ResNet |
| RPC outage on any stage-1–4 call | retried twice with backoff; then `RpcUnavailableError` **parks the run** at that item, so resume retries it. Marking items failed here would burn the whole queue on a provider hiccup |
| ResNet inference throws | `inventory.resnetStatus.status = "error"`, the item still completes |
| Proxy detection / probes throw | ignored, the item still completes |
| PoC backend unreachable | 3 consecutive infra failures trip the circuit breaker: auto-PoC stops for the run, static records stand |
| Duplicate PoC code within an item | SHA-256 of the generated source; the sibling saves the same verdict as a `shared` run instead of re-executing |
| DB flush fails | the run parks un-advanced on that item; resume re-queues the same `scanId` as an upsert, not a duplicate row |

## Knobs (`POST /start`)

| Field | Default | Notes |
| --- | --- | --- |
| `addressesFile` | — | required |
| `chainId` | `ethereum` | |
| `refresh` | `stale` | see table above |
| `delayMs` | `600` | pause between items; `0` = none |
| `autoPoc` | `true` | **no attempt cap** — every eligible finding is attempted |
| `aiSecondPass` | `false` | deferred stage |
| `deepAgent` | `false` | deferred stage |
| `deepAgentMaxItems` / `deepAgentMinSeverity` | `250` / `high` | deferred stage |

## What the pipeline does not do

- **No source, no source rules.** An unverified contract gets bytecode and ResNet
  only. That is a different, weaker review, and the report says so.
- **No re-check of a skipped row.** With `refresh: none`, findings written by an
  older analyzer stay as they are — including bugs since fixed in the rules.
- **No cross-contract reasoning.** The pipeline sees one address at a time; a
  proxy's implementation, a hook's pool, a settlement module's caller are all
  outside the frame unless the address is in the list. `NEEDS_READ` findings are
  exactly where that boundary shows.
- **No automatic publication of money figures.** A figure with
  `economic_basis: assumption` needs a live read before it goes in a report.

## Deferred stages

Removed from the pipeline for now, code present and off:

- **Narrative** (`aiSecondPass`) — one LLM call per item to write the prose
  summary. With it off, `ai_status` is `unavailable` and the narrative is the
  deterministic fallback text.
- **Agentic search** (`deepAgent`) — per flagged address: propose an exploit, test
  it on a fork, up to 3 LLM calls and 6 fork PoCs, capped at 250 addresses.

Both share the OpenRouter key and the Foundry backend with auto-PoC, which is why
running all three on a 90k-address list starves the backend and trips the agent's
`backend_unreachable` guard. Static + PoC is the shape that survives at that size.

## Known gaps

`docs/pipeline-audit.md` reviews this pipeline for completeness and effectiveness
and lists what it does not do well. The headline: **a proxy's implementation is
never fetched or analysed** — `detectProxyArchitecture` returns the implementation
addresses, they are persisted to `proxy_info_json`, and nothing reads their source,
so a large share of a modern address set is analysed at the delegatecall shell.

## What the output is for

The findings are the input to a queue, not a verdict. Reachability classes
(`REACHABLE` / `NEEDS_READ` / `BOUNDED` / `GATED` / `INTERNAL`) decide what a human
reads first; `triage.ts` bands them; the family collapse stops one contract with
six price-plumbing notes outranking one with a reachable takeover. Measured on
SmartBugs Curated: 131 of 143 contracts caught (91.6%), with the 12 misses
itemised in `docs/detection-quality.md`.
