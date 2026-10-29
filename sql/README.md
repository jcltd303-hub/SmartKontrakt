# BigQuery: turning scans into a priority queue

Four files, in the order you run them:

| File | Runs on | Purpose |
| --- | --- | --- |
| `00_export.sql` | the app's Postgres | flatten `findings` + `contract_scans` into the export shape |
| `01_load.sql` | BigQuery | DDL + load for the export |
| `02_priority_queue.sql` | BigQuery | rank contracts by likelihood of a real, reachable vulnerability |
| `03_chain_candidates.sql` | BigQuery public data | find contracts on-chain that meet the *preconditions* for our classes |
| `04_value_at_risk.sql` | BigQuery | join findings to live value and activity |
| `05_chain_wide_screen.sql` | BigQuery public data | **chain-wide**: likely-vulnerable contracts from behaviour alone, no dependency on our scans |
| `06_reentrancy_cycles.sql` | BigQuery public data | **chain-wide**: re-entry into a contract from inside its own call tree |

## Why BigQuery at all

The analyzer is good at a single contract and blind at a portfolio. BigQuery is
where the portfolio question gets answered: 60 million deployed contracts, their
traces, their balances — which of them look like the shapes we detect? The
scoring below is deliberately the *same* model the report uses, so a contract at
the top of the BigQuery queue and a contract at the top of the workbench queue
mean the same thing:

1. **Reachability decides first.** A gated or internal finding is not a finding
   (the engagement that started this: 480 hits, 1 real issue, and every false
   positive was a shape that existed but was unreachable).
2. **Evidence second.** A resolved site outranks a text-matched precondition
   outranks a file-level pattern.
3. **Mechanism, not rule count.** Score per *family* and sum the best of each, so
   one contract with six price-plumbing findings does not outrank one contract
   with a single reachable caller-identity hole.
4. **Value last.** Money at risk breaks ties; it does not create a queue entry.

## Schema notes that will bite you

- `bigquery-public-data.crypto_ethereum` tables are **partitioned on
  `block_timestamp`**. Every query here filters it. Without that filter BigQuery
  scans the full history and the query is expensive — and on `traces`, which is
  the largest table, ruinous.
- There is **no "verified source" column** in the public dataset. `contracts`
  gives you `address`, `bytecode`, `creator_address`, `block_timestamp`,
  `is_erc20`, `is_erc721`. Verification is an explorer concept; join to your own
  scans (which do record it) rather than inferring it.
- `crypto_ethereum` has a **lag** and, depending on the day, a last-updated
  cutoff. `select max(block_timestamp) from ...` before you trust a window.
- `findings.preconditions` is a **jsonb array** in Postgres and arrives in
  BigQuery as a JSON string column. Use `JSON_EXTRACT_ARRAY` to read it.
- `balance_wei` is a **string** because a balance exceeds 2^53 — keep it a
  string or a `NUMERIC`/`BIGNUMERIC` in BigQuery. Never `FLOAT64` for wei.

## Chain-wide, from public data only

`05` and `06` never touch our own tables: they work on any contract on the chain,
whether or not it has been scanned, and whether or not it has source.

### Do not screen bytecode with `LIKE '%f4%'`

The obvious filter for DELEGATECALL is a substring match on `contracts.bytecode`.
It does not work, and the arithmetic says why: bytecode is hex, so a 10 KB
contract is ~20,000 characters, and the probability that a given 1-byte opcode
pattern appears somewhere by accident is `1 - (1 - 1/256)^20000 ≈ 1`. **Every
contract matches every opcode.** And an `f4` inside PUSH32 constant data is not an
opcode at all — separating the two needs a disassembler, which SQL is not.

So both queries are behavioural, read from `traces`, where BigQuery records the
call type the EVM actually executed:

| Signal | Source | Why it matters |
| --- | --- | --- |
| `call_type = 'DELEGATECALL'` | traces | exact, not a hex guess — the proxy/upgrade surface (SWC-112) |
| value in | traces | something to take |
| value sent out | traces | a payout path exists |
| distinct callers | traces | the on-chain proxy for reachability |
| ≥3 entries in one tx | traces | the reentrancy tell (a flash loan enters twice) |
| `A → B → A` in one call tree | traces + `trace_address` | the reentrancy **shape**, not a precondition for it |

### `06` is the one to run first

A reentrancy is a cycle in the call tree. BigQuery records the tree positionally
in `trace_address`, so a cycle is an equality join between a trace and its parent
(`parent.path = child.path` minus the last index, with the addresses reversed).
That detects the attack shape directly, rather than a precondition that might
lead to one.

It also finds flash loans (pool → borrower → pool to repay) and legitimate
callbacks, which is why it returns discriminators rather than a verdict:

- **same-selector re-entry** — the inner frame calls the same entry point it came
  from (`withdraw` inside `withdraw`). That is the reentrancy tell; a flash loan
  re-enters a *different* function (borrow → repay).
- **depth ≥ 4** — three or more entries into one contract inside one transaction.
- **value on the inner frame** — the re-entrant call moving value is the drain.

Nothing here decides. Each row needs the contract read.

## The scoring model, as constants

Kept in one place in `02_priority_queue.sql` so the weights are arguable rather
than buried:

| Dimension | Values |
| --- | --- |
| reachability | `REACHABLE` 1.0 · `NEEDS_READ` 0.45 · `BOUNDED` 0.15 · `GATED` 0.10 · `INTERNAL` 0 · null 0.05 |
| confidence | `high` 1.0 · `medium` 0.6 · `low` 0.3 |
| severity | `critical` 1.0 · `high` 0.7 · `medium` 0.35 · `low` 0.1 · `info` 0 |
| family | caller-identity 1.0 · price-plumbing 0.95 · value-and-settlement 0.90 · reentrancy 0.85 · bridge-messaging 0.85 · governance 0.80 · arithmetic 0.60 · randomness 0.55 · ordering 0.40 · token-accounting 0.55 · evm-and-bytecode 0.35 · hygiene 0 · analyzer-meta 0 |

Why those family weights: the incident record. Caller-identity and price
plumbing are where the money went across 2021–2026; arithmetic is real but mostly
survives only in pre-0.8 code; ordering needs an MEV actor to be present and
rarely shows up as a contract defect on its own.

## What this cannot do

- **It ranks; it does not verify.** A high score means "read this next", and the
  PoC runner plus a human decide. Treat the score as a queue position, never as
  a finding.
- **The public dataset has no source.** For unverified contracts the analyzers
  that need source cannot run at all; those come out of `03_chain_candidates.sql`
  as *bytecode-only* targets, which is a different (weaker) review.
- **Nothing here is run in CI.** These queries need a BigQuery project and
  credentials; they are reviewed SQL, not executed SQL. Check
  `scripts/benchmark-smartbugs.ts` for the part that *is* measured.

---

# 08 and 09: choosing the window

Files 00–06 answer "which contracts look vulnerable". 08 and 09 answer the question
before it: **which contracts are worth the analysis at all.** That question turned out
to be where the pipeline was losing, so the reasoning is recorded here rather than in
a commit message.

## What went wrong first

The archive was built from "addresses holding ETH". Measured on 2026-10-28:

| observation | value |
| --- | --- |
| scans | 1,613 |
| distinct analysed bodies | 375 (4.25 copies each) |
| largest single body | a GnosisSafeProxy, 343 scans — 21% of the archive |
| proxy shells by name | 55% of all scans |
| scans carrying any critical | 29 — and they held all 177 criticals |
| ETH in the 1,596 zero-critical scans | 99.97% of the archive's total |

The contracts holding the money were wallets, shells and the beacon deposit contract.
The contracts holding the findings were 2% of the archive with a rounding error of the
value. Sorted by balance, the queue put the audit budget in exactly the place where no
finding can exist. That is the GIGO failure, and no detector change fixes it.

## Which window, and why not "the last 30 days"

Three independent datasets agree:

- **Time-to-hack** (Decurity, 2020–2025): the **>90-day** bucket holds the *most*
  exploits — vulnerabilities sit untouched for months or years; 1inch's Settlement
  contract was dormant 2+ years before its $5M loss. The ≤7-day bucket is second, and
  is unwinnable for this pipeline: the fastest 2025 exploit landed 52 minutes after
  deployment, while a scan here costs ~20s/address before any PoC mining.
- **Decurity's proxy analysis**: implementations are exploited much faster than fresh
  deployments, concentrating in the days after an update.
- **CoinGecko 2026**: 147 of 245 exploited protocols had been audited, and most attacks
  landed on newly introduced code outside the audit's scope.

So the target is not a new contract. It is **an old proxy holding real money whose
implementation changed recently** — new code, established liquidity, and none of the
fresh-deployment attention that makes bots swarm. `09_upgrade_window.sql` builds that
list from the ERC-1967 `Upgraded(address)` event, topic0
`0xbc7cd75a20ee27fd9adebab32041f755214dbc6bffa90cc0225b39da2e5c2d3b` — the same
constant solc bakes into `ERC1967Upgrade`, so transparent, UUPS and beacon upgrades all
match. `08_fodder.sql` is the alternative: behavioural candidates (callers, selectors,
multi-entry transactions) for contracts with no upgrade to key on.

## Two corrections that only a live run could produce

Both were caught by running the query, not by reading it.

1. **Implementation age zero is not an upgrade.** A transparent proxy's constructor
   calls `_upgradeToAndCall`, which emits `Upgraded` in the block the proxy is created.
   The first version filtered on implementation freshness and returned brand-new
   proxies — the exact window the research says to avoid. The discriminator is the
   **proxy's own age**: `proxy_age_days_at_upgrade >= 90`.
2. **Native ETH is the wrong value column.** The corrected run returned 166 genuine
   upgrades — median proxy age 278 days, median implementation age at upgrade 311
   hours — and **2.05 ETH between all of them**, with 154 holding none. DeFi value sits
   in ERC-20s. `crypto_ethereum.balances` only carries the native balance, so the value
   term now uses 30-day token flow over the seven majors. It is an estimate: it
   under-counts idle holdings and over-counts high-turnover routers.

The same run showed **166 proxies resolving to 88 implementations**, with 71 of the 166
being just two implementations (38 and 33 proxies). `proxies_sharing` scores an
implementation by how many deployments it carries — one audit target, 38× the exposure.

## Feed the pipeline implementations, not proxies

The last block of `09` returns one cell: implementation addresses newline-separated,
best first, ready for `POST /start`. The proxy is a forwarder; the implementation is
where the source and the logic are, and the worker follows proxy → implementation on
its own when handed a proxy.

If the newlines arrive as a literal `\n`, use `chr(10)` as the delimiter — it does not
depend on how the client parses escapes.

## What to measure afterwards

`sql/ops/after-run.sql`. The question is not how many findings came back, it is whether
the newer families fire at all on a cohort of established, audited implementations —
and whether the analyser stays quiet on the ones that are genuinely clean. Eighty known
-good protocol implementations scoring zero is the precision evidence this corpus has
never had.
