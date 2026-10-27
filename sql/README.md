# BigQuery: turning scans into a priority queue

Four files, in the order you run them:

| File | Runs on | Purpose |
| --- | --- | --- |
| `00_export.sql` | the app's Postgres | flatten `findings` + `contract_scans` into the export shape |
| `01_load.sql` | BigQuery | DDL + load for the export |
| `02_priority_queue.sql` | BigQuery | rank contracts by likelihood of a real, reachable vulnerability |
| `03_chain_candidates.sql` | BigQuery public data | find contracts on-chain that meet the *preconditions* for our classes |
| `04_value_at_risk.sql` | BigQuery | join findings to live value and activity |

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
