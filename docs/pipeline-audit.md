# Pipeline audit — completeness and effectiveness

Reviewed 2026-10-27 against the code, not the documentation. Ten stages as
described in `docs/pipeline.md`; this asks two separate questions of each — does it
run (completeness), and does it achieve what it exists for (effectiveness).

**Verdict.** The pipeline is complete as a *machine*: every stage has a defined
failure behaviour, the dangerous ones are gated, and the ordering is right (rules
before any model). It is **not** yet effective at its actual job, for one reason
that dominates everything else: **it never looks at a proxy's implementation.**

## The gap that matters: proxies are analysed at the shell

`analyzeAddress` fetches source for the address it was given. `detectProxyArchitecture`
runs alongside it, correctly identifies EIP-1967 / transparent / minimal / Gnosis
Safe proxies, and returns the implementation addresses. Those addresses are then
written to `proxy_info_json` and mentioned in the report text — and **nothing
fetches or analyses them**. `address-fetcher.ts` has exactly one call to
`fetchSourcifySource` and one to `fetchBlockscoutSource`, both for the input
address, and one `analyzeInput` on whatever source came back.

What that means per proxy:

| Proxy | Source fetched | Findings come from |
| --- | --- | --- |
| verified proxy shell | the ~50-line delegatecall contract | the shell — almost nothing |
| unverified proxy | none; runtime bytecode only | bytecode heuristics |

The logic that can be wrong lives in the implementation, which is never read. On a
modern address set a large share of contracts are proxies — upgradeable vaults,
Gnosis Safes, minimal-proxy clones, EIP-1167 factories — so this silently converts
a large fraction of the corpus into "no findings", and the record looks complete
while doing it. This is the single largest effectiveness defect in the pipeline and
it is invisible from the output.

**The fix is small, because the data is already there.** The worker holds
`proxyInfo` (line 488) and persists it (line 579). After an item completes, append
each `proxyInfo.implementations[]` address to the queue as its own entry — the
dedupe already collapses repeats, `refresh` decides whether it is re-done, and the
implementation then gets full source, the static rules, and ResNet. The proxy's own
record keeps the link. Failing that, the minimum is to mark the proxy's findings
`NEEDS_READ` with the implementation address, so triage never reports a shell as
clean.

## Second: no cross-address dedupe by bytecode

Every address is analysed independently. The only dedupe is `(chain, address)`, so
N clones of the same implementation cost N full analyses — the same fetch, parse,
60 rules and ResNet pass. `refresh: none` skips on the address key, not the code.

The pattern already exists in this repo: `auto-poc.ts` hashes the generated PoC
source with SHA-256 and serves a sibling from the cache. The same trick applies
here — hash `runtimeBytecode`, and when a clone's hash matches a stored scan on the
same chain, copy the findings with the note "identical runtime bytecode to 0x…".
On a set containing factories and clone farms this is the difference between a
day and a week of runtime.

## Third: the PoC stage currently returns almost nothing

Measured on the last run: 518 attempts, **1 passed** (0.2%). 209 were `no_tests` —
of which 139 were fork-endpoint failures, 33 compile failures and 5 unsatisfiable
pragmas, i.e. **zero were hollow runs**; the classifier was mislabelling
infrastructure as a verdict (fixed). 205 `failed` are honest negatives. 83 `error`.

So the stage is now *honest* but not yet *productive*: two-thirds of its attempts
were being killed by the fork RPC, and the yield on what did run was 1 in 518. It is
correctly off for the current run.

## Completeness gaps

| # | Gap | Consequence |
| --- | --- | --- |
| 1 | **`triage.ts` has no consumers.** `triageQueue`, `readQueue`, `triageCounts` are exported and tested, and nothing calls them. Only `sortFindingsForTriage` is wired, in the certificate table. | The read queue — a short ordered list of what a human should open — is the product's core output and it is unreachable. The reachability work exists; the queue view does not. |
| 2 | **RAG module and UI still present** (`rag.server.ts` 498 lines, `rag-knowledgebase.tsx` 480, `rag-chunks.ts`, three server functions, one workbench import) while the storage is gone (migration 0019). | ~1,000 lines of dead code that still typechecks against a dropped table. |
| 3 | **fourbyte caches absent** on the live database (`fourbyte_signatures`, `fourbyte_event_signatures` missing while 0005/0006 are recorded as applied). | Every selector lookup goes to the live 4byte.directory API: latency and rate limits across 100k contracts, no local cache. |
| 4 | **`selectAutoPocFindings` does not consider whether a PoC is writable.** It filters on severity and presence-only corroboration only. | Findings whose `exploitSolidity` cannot wrap (no contract, interface-only) still enter the PoC chain and end as `no_tests`. Cheap to exclude at selection. |
| 5 | **Two migrations share the `0012` prefix.** Harmless to the applier (it keys by basename) but makes "18 of 19 applied" ambiguous to read. | Cost a round trip to rule out. Renaming one would fix it. |

## Verified sound (so this is not only a list of faults)

- **Stage ordering.** Every finding comes from the static rules; the model only
  writes narrative and exploit code. A run with every LLM stage off still produces
  a complete, ranked report — confirmed by the current run.
- **Failure behaviour is per-stage and mostly right.** An RPC outage *parks* the
  run at the item rather than failing it; ResNet, proxy and probe failures never
  fail an item; a failed flush parks un-advanced and the resume upserts the same
  `scanId` instead of duplicating a row.
- **No false-clean rows.** An address with no deployed code *throws*, so an EOA or
  a destroyed contract lands in `failed` rather than being recorded as clean.
- **Infrastructure is no longer recorded as a verdict.** After this session's fix,
  a fork failure or compile failure saves as `error`; `no_tests` means forge
  genuinely matched nothing. It also stopped poisoning the share-cache.
- **Schema gating.** `/start` now refuses a database missing any of ten required
  columns and names the migration, instead of failing the first flush.
- **Detection quality is measured, not asserted.** 131 of 143 SmartBugs Curated
  contracts caught (91.6%) with the 12 misses itemised, and a 25-case 2026-era
  incident corpus at 100% recall with zero cross-talk.
- **60 detectors across 11 families**, each with a reachability class, a gate and a
  confidence basis; 63 PoC harnesses; the fixture-debt ratchet fails when a
  detector has no behavioural fixture.
- **Ops is real**: local-file backup with an atomic publish, a guarded wipe that
  keeps learned caches, a schema-drift check.

## Cannot be verified from here

- **Whether ResNet actually runs on your host.** The model files are present
  (`public/models/bytecode-image-v1.json`) and the code path is wired, but it
  silently degrades to `resnetStatus: error` when the runtime is missing. Check
  `select count(*) from contract_scans where resnet_json is not null` after a few
  hundred scans — 0 means the ML term is contributing nothing to any score.
- **The run's real yield.** 100k addresses at an unknown proxy share; the findings
  per scan and the share of records that are proxy shells are the numbers that
  would size the first gap.

## What I would fix, in order

1. **Follow proxies** — append `proxyInfo.implementations[]` to the queue. Biggest
   single gain, data already in hand.
2. **Surface the triage queue** — a view over `triageQueue`/`readQueue`; the
   findings exist and the banding is computed, it is simply never shown.
3. **Bytecode-hash dedupe** — one analysis per distinct runtime code, siblings
   copied with a note.
4. **Exclude unwrappable findings from the PoC chain** at selection time.
5. **Delete the RAG module and UI**, and restore the fourbyte caches from their
   migrations.
