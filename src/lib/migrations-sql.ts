/**
 * Embedded copies of the SQL migrations in `migrations/`.
 *
 * Why embedded: in production (Vercel / Nitro) the runtime auto-migration in
 * `src/lib/db.ts` cannot rely on `import.meta.glob("/migrations/*.sql")`
 * (the `.sql` files are not part of the bundled module graph) or on
 * `process.cwd()/migrations` (that folder is not shipped in the serverless
 * function bundle). Both sources come back empty in prod, so the
 * auto-migration silently did nothing and the database never got
 * `contract_scans` — every archive read/write then failed with
 * `relation "contract_scans" does not exist`.
 *
 * Embedding the SQL in a `.ts` module guarantees it is bundled, so the first
 * database connection in prod can always create the tables.
 *
 * Keep this file in sync with `migrations/0002_scans.sql` and
 * `migrations/0003_comprehensive_records_and_rag.sql` — same filenames as
 * keys, same SQL as values. The `_migrations` bookkeeping in `db.ts` and in
 * `scripts/migrate-vercel.mjs` keys by basename, so a migration applied by
 * either path is not re-applied by the other.
 */
export const EMBEDDED_MIGRATIONS: Record<string, string> = {
  "0002_scans.sql": `-- Kiln audit archive. Rows are unowned: this app has no accounts.
-- Contract text is the audit subject, not a profile. There is no bulk delete.

create table if not exists contract_scans (
  id text primary key,
  label text not null,
  input_kind text not null,
  contract_name text,
  risk_score integer not null,
  critical_count integer not null default 0,
  high_count integer not null default 0,
  medium_count integer not null default 0,
  low_count integer not null default 0,
  info_count integer not null default 0,
  summary text not null,
  inventory_json text not null,
  ai_narrative text,
  ai_status text not null default 'unavailable',
  created_at timestamptz not null default now()
);

create index if not exists contract_scans_created_idx
  on contract_scans (created_at desc);

create table if not exists scan_payloads (
  scan_id text primary key references contract_scans (id) on delete cascade,
  body text not null
);

create table if not exists findings (
  id text primary key,
  scan_id text not null references contract_scans (id) on delete cascade,
  ord integer not null,
  severity text not null,
  swc text,
  title text not null,
  confidence text not null,
  detector text not null,
  summary text not null,
  walkthrough text not null,
  exploit_solidity text not null default '',
  remediation_solidity text not null default '',
  location_fn text,
  location_line integer,
  snippet text not null default ''
);

create index if not exists findings_scan_idx on findings (scan_id, ord);
`,
  "0003_comprehensive_records_and_rag.sql": `-- Migration 0003: Comprehensive Records and Local RAG Knowledgebase
-- Extends contract_scans with deep audit dossier metadata
-- Adds rag_knowledge_chunks table for local RAG retrieval & semantic indexing

alter table contract_scans add column if not exists target_address text;
alter table contract_scans add column if not exists chain_id text;
alter table contract_scans add column if not exists compiler_version text;
alter table contract_scans add column if not exists proxy_info_json text;
alter table contract_scans add column if not exists probes_json text;
alter table contract_scans add column if not exists ai_review_json text;
alter table contract_scans add column if not exists triage_states_json text;
alter table contract_scans add column if not exists cert_hash text;
alter table contract_scans add column if not exists source_origin text default 'workbench';
alter table contract_scans add column if not exists is_rag_indexed boolean default false;

create index if not exists contract_scans_target_idx
  on contract_scans (target_address);

create index if not exists contract_scans_risk_idx
  on contract_scans (risk_score desc);

-- RAG Knowledgebase Chunks
create table if not exists rag_knowledge_chunks (
  id text primary key,
  scan_id text references contract_scans (id) on delete set null,
  category text not null, -- 'vulnerability', 'threat_model', 'remediation', 'contract_profile', 'foundry_poc'
  title text not null,
  content text not null,
  severity text,
  swc text,
  detector text,
  contract_name text,
  target_address text,
  chain_id text,
  keywords text not null,
  vector_data text,
  metadata_json text not null,
  created_at timestamptz not null default now()
);

create index if not exists rag_chunks_scan_idx on rag_knowledge_chunks (scan_id);
create index if not exists rag_chunks_cat_idx on rag_knowledge_chunks (category);
create index if not exists rag_chunks_detector_idx on rag_knowledge_chunks (detector);
create index if not exists rag_chunks_created_idx on rag_knowledge_chunks (created_at desc);
`,
  "0004_poc_results.sql": `-- Migration 0004: Foundry fork-PoC run results on contract_scans.
-- The workbench auto-runs a generated PoC against the Termux local backend
-- (forge --fork-url) and persists the outcome here, so a scan record shows
-- whether the exploit reproduced on fork state.

alter table contract_scans add column if not exists poc_status text;
alter table contract_scans add column if not exists poc_logs text;
alter table contract_scans add column if not exists poc_duration_ms integer;
alter table contract_scans add column if not exists poc_run_at timestamptz;
`,
  "0005_fourbyte.sql": `-- Migration 0005: 4byte.directory function-selector database.
-- One row per (selector, signature) pair. A selector can map to several
-- text signatures (collisions), so the pair is the primary key — and the
-- PK's B-tree also serves lookups by selector (leftmost column).
-- Source: ethereum-lists/4bytes, the bulk dataset behind 4byte.directory,
-- imported by scripts/import-4byte.mjs. ~1.18M rows (API count 2026-10-17).

create table if not exists fourbyte_signatures (
  selector text not null, -- '0xa9059cbb'
  signature text not null, -- 'transfer(address,uint256)'
  created_at timestamptz not null default now(),
  primary key (selector, signature)
);
`,
  "0006_fourbyte_events.sql": `-- Migration 0006: 4byte.directory event-signature database (32-byte topics).
-- Same shape as 0005's function-selector table. One row per
-- (topic, signature) pair; a topic can map to several event signatures.
-- Source: ethereum-lists/4bytes \`event-signatures/\` dir, imported by
-- scripts/import-4byte.mjs.

create table if not exists fourbyte_event_signatures (
  topic text not null, -- '0xddf252ad...'
  signature text not null, -- 'Transfer(address,address,uint256)'
  created_at timestamptz not null default now(),
  primary key (topic, signature)
);
`,
  "0007_unparsed.sql": `-- Migration 0007: explicit unparsed state on contract_scans.
-- A record whose input did not parse analyzed NOTHING (e.g. a bare enum
-- pasted as source) and must render "Unparsed", never "Clean".
-- The engine computes unparsed at analysis time; both save paths write it.
-- The backfill below labels pre-existing unparsed records:
-- (a) parse-INFO-only: source input, only info findings, every finding
--     has the parse detector;
-- (b) Fragment-enum: zero findings, inventory names are all "Fragment"
--     and the inventory has no functions (a bare enum/struct paste the
--     parser wrapped in a synthetic Fragment contract).
-- The LIKE guards are fail-safe: JSON.stringify emits the keys with no
-- spaces, so they can only under-match, never error the migration.
alter table contract_scans add column if not exists unparsed boolean not null default false;

update contract_scans set unparsed = true
where input_kind = 'source' and unparsed = false
  and critical_count = 0 and high_count = 0 and medium_count = 0 and low_count = 0 and info_count > 0
  and not exists (select 1 from findings f where f.scan_id = contract_scans.id and f.detector <> 'parse');

update contract_scans set unparsed = true
where input_kind = 'source' and unparsed = false
  and critical_count = 0 and high_count = 0 and medium_count = 0 and low_count = 0 and info_count = 0
  and inventory_json like '%"contractNames":["Fragment"]%'
  and inventory_json like '%"functions":[]%';
`,
  "0008_finding_poc_runs.sql": `-- Migration 0008: Finding PoC Audits and durable results.
-- Stores automated Foundry fork PoC verification results for individual findings.

alter table findings add column if not exists poc_status text;
alter table findings add column if not exists poc_output text;
alter table findings add column if not exists poc_duration_ms integer;
alter table findings add column if not exists poc_run_at timestamptz;
alter table findings add column if not exists poc_code text;

create table if not exists finding_poc_runs (
  id text primary key,
  finding_id text not null references findings (id) on delete cascade,
  scan_id text not null references contract_scans (id) on delete cascade,
  status text not null,
  source text not null,
  output text not null,
  duration_ms integer not null default 0,
  chain_id text,
  target_address text,
  exit_code integer,
  truncated boolean default false,
  created_at timestamptz not null default now()
);

create index if not exists finding_poc_runs_finding_idx on finding_poc_runs (finding_id);
create index if not exists finding_poc_runs_scan_idx on finding_poc_runs (scan_id);
create index if not exists finding_poc_runs_created_idx on finding_poc_runs (created_at desc);
`,
  "0009_rag_fts.sql": `-- Migration 0009: real full-text search for the local knowledge base.
--
-- The previous query loaded the 150 most-recent chunks and scored them with a
-- JS tokenizer, so every chunk older than the newest 150 was silently
-- unreachable, and a semantic query only matched if the literal tokens
-- appeared. A stored tsvector column plus a GIN index moves filtering and
-- ranking into Postgres and removes the row cap. \`replaceRagChunks\` (the only
-- writer) populates \`search_vector\` on every insert; this migration backfills
-- rows written before the column existed.

alter table rag_knowledge_chunks add column if not exists search_vector tsvector;

create index if not exists rag_chunks_search_idx
  on rag_knowledge_chunks using gin (search_vector);

-- \`to_tsvector(regconfig, text)\` (the two-arg, explicitly-typed form) is
-- immutable, unlike the one-arg text form, so it is safe in a plain update.
update rag_knowledge_chunks
set search_vector = to_tsvector('english'::regconfig,
      coalesce(title, '') || ' ' || coalesce(content, '') || ' ' ||
      coalesce(keywords, '') || ' ' || coalesce(detector, '') || ' ' ||
      coalesce(swc, '') || ' ' || coalesce(contract_name, ''))
where search_vector is null;
`,
  "0010_indexes.sql": `-- Migration 0010: supporting indexes for the hot read paths.
--
-- The "recent critical/high findings" feed (getRecentHighSeverityFindings)
-- filters findings by severity and a non-empty exploit PoC. Without a partial
-- index that is a sequential scan of the whole findings table on a large
-- archive. The partial predicate matches the query exactly, so the index stays
-- small (most findings carry no exploit).
create index if not exists findings_severity_poc_idx
  on findings (severity)
  where length(trim(exploit_solidity)) > 0;

-- The pipeline worker's resume check and the Records view look contracts up by
-- (chain, address). The existing contract_scans_target_idx covers a bare
-- target_address lookup; this functional composite also serves the
-- \`lower(target_address)\` form the worker uses.
create index if not exists contract_scans_chain_address_idx
  on contract_scans (chain_id, lower(target_address));
`,
  "0011_balance.sql": `-- Migration 0011: native-coin balance of the target at analysis time.
--
-- Read over public JSON-RPC (\`eth_getBalance\`) when an address is analyzed, so a
-- record shows how much native value sits behind the contract, and so the
-- pre-run PoC guard can skip a target with nothing at stake.
--
-- Stored as a decimal wei string in \`text\`: balances exceed 2^53, so a JSON
-- number would lose precision. NULL means "not read" (no RPC answered), which is
-- deliberately distinct from '0' (a confirmed empty balance).
alter table contract_scans add column if not exists balance_wei text;
`,
  "0012_value_at_risk.sql": `-- Migration 0012: value-at-risk columns.
--
-- \`value_usd\` is the target's total USD value at analysis time (native coin plus
-- ERC-20 holdings), so the Records list can sort and filter by what is actually
-- at stake instead of by native balance alone. \`value_json\` keeps the full
-- valuation (per-holding amounts, prices, sources, completeness) for the UI.
-- \`abi_json\` + \`abi_source\` persist the target's ABI — gathered once, reused by
-- any later PoC run so a template can be tailored to the real contract surface.
--
-- \`value_usd\` is \`numeric\`, not float, so sorting is exact. NULL means "not
-- valued" and is distinct from 0 (a confirmed valueless target).
alter table contract_scans add column if not exists value_usd numeric;
alter table contract_scans add column if not exists value_json text;
alter table contract_scans add column if not exists abi_json text;
alter table contract_scans add column if not exists abi_source text;

create index if not exists contract_scans_value_usd_idx
  on contract_scans (value_usd desc nulls last);
`,
  "0013_poc_run_idempotency.sql": `-- Migration 0013: idempotent PoC runs.
--
-- \`finding_poc_runs\` used to get a fresh random UUID on every save, so re-running
-- the same proof (same finding, same executed source) appended a duplicate row
-- every time — the table grew with repeats and there was no way to ask "have we
-- already executed exactly this proof?".
--
-- \`source_digest\` is the sha3-256 of the executed source. The partial unique
-- index makes (finding_id, source_digest) the identity of a run, so a re-save
-- updates the existing row instead of appending. Rows written before this
-- migration have a NULL digest and are left alone by the partial index.
alter table finding_poc_runs add column if not exists source_digest text;

create unique index if not exists finding_poc_runs_identity_idx
  on finding_poc_runs (finding_id, source_digest)
  where source_digest is not null;
`,
  "0014_analyzer_version.sql": `-- Migration 0014: which analyzer produced a saved record.
--
-- The pipeline's resume treats a saved (chain, address) as done. That is only
-- correct while the analyzer is unchanged: after the scoring redo, the balance
-- guard, the value-at-risk pass, ABI gathering, SmartPoC and the SmartBugs
-- alignment, every earlier row describes OLDER behaviour, and skipping it keeps
-- the staleness. This column is the stamp the analyzer writes on every record
-- (baseline + a fingerprint of the detector set and scoring model), so resume
-- can skip what is current and re-analyze what is not.
--
-- Existing rows are NULL and therefore stale by definition — which is exactly
-- what makes the first run after this migration refresh the whole archive
-- instead of skipping it. No backfill is needed or wanted: the archive IS the
-- thing being refreshed.
alter table contract_scans add column if not exists analyzer_version text;

-- The freshness question is "how many of my rows are not current?", asked over
-- the whole table for the freshen report, so index the stamp itself.
create index if not exists contract_scans_analyzer_version_idx
  on contract_scans (analyzer_version);
`,
  "0015_auditor_dispositions.sql": `-- Migration 0015: auditor dispositions on findings.
--
-- The manual adjudication loop (load a finding, fetch, AI-review, run the
-- PoC, read the log) ends in a human verdict. Until now that verdict lived
-- only in the per-scan \`triage_states_json\` blob in the workbench, keyed by
-- in-memory finding ids and invisible to the PoC Audits page — so the same
-- false positive was re-adjudicated from scratch on every pass.
--
-- One row per finding (the finding id is the PK, and findings carry the
-- canonical \`\${scanId}:\${ord}\` identity), written by UPSERT: setting a
-- disposition twice updates the one row, and re-setting the same value is a
-- no-op. \`disposition\` is the auditor's word, never a machine verdict — the
-- adjudication chain may SUGGEST one from a PoC outcome, but only a human
-- tap writes here.
create table if not exists auditor_dispositions (
  finding_id text primary key references findings (id) on delete cascade,
  disposition text not null check (disposition in ('confirmed', 'false_positive', 'needs_more_info')),
  note text,
  updated_at timestamptz not null default now()
);
`,
  "0016_finding_corroborated.sql": `-- Migration 0016: corroboration marker on findings.
--
-- G3 (corroboration revival): a bytecode-presence-only finding
-- (DELEGATECALL / CALLCODE / SELFDESTRUCT opcode presence and the
-- ORIGIN / TIMESTAMP / CREATE2 / CALL+SSTORE presence titles) is
-- excluded from the PoC queues unless something corroborates it.
-- hasVulnCorroboration (src/lib/audit/adjudication.ts) reads an
-- explicit marker on the finding record first — but until now no
-- column existed for any writer to stamp one into, so the marker
-- branch was dead code and the only other branch (a source-shaped
-- snippet) can never fire for bytecode findings, whose snippets are
-- disassembly windows by construction.
--
-- This column is the marker's home. Boolean, NULL on every row that
-- predates it — NULL reads as uncorroborated, which is exactly the
-- state those rows are in — and written by the persist paths from
-- the Finding record's corroborated field. Stamping happens where a
-- producer holds both the finding and source-level evidence; the
-- eligibility read path also accepts source text supplied at call
-- time, so this column is the durable form, not the only form.
alter table findings add column if not exists corroborated boolean;`,
  "0017_fp_signatures.sql": `-- Migration 0017: FP signature layer (G7) — candidate false-positive
-- patterns derived from auditor dispositions, decided by a human.
--
-- auditor_dispositions (0015) is the source of truth: a pattern exists
-- here only because findings carrying its shape were disposed
-- 'false_positive' by a human, on at least two distinct scans (a single
-- FP is an anecdote, not a pattern). Derivation (fp-signatures.ts) is
-- re-run on read; this table stores the HUMAN'S DECISION about a
-- derived pattern — candidate (derived, undecided), confirmed, or
-- dismissed — plus the evidence snapshot the decision was made against.
--
-- The layer is annotation-only, by construction: nothing in the schema
-- lets a row here reach severity, pocAuditEligibility, or a
-- disposition. A CONFIRMED signature only earns a finding a visible
-- "matches confirmed FP pattern" note at read time. Dismissed rows are
-- kept forever: a dismissed signature key is never re-proposed as a
-- candidate, however much matching FP evidence accrues later.
create table if not exists fp_signatures (
  signature_key text primary key,
  detector text not null,
  title_pattern text not null,
  location_fn text,
  snippet_class text,
  status text not null default 'candidate'
    check (status in ('candidate', 'confirmed', 'dismissed')),
  evidence_count integer not null default 0,
  scan_count integer not null default 0,
  sample_finding_ids text not null default '[]',
  sample_titles text not null default '[]',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  decided_at timestamptz
);

create index if not exists fp_signatures_status_idx
  on fp_signatures (status);`,
  "0021_fourbyte_miss_reason.sql": `-- Migration 0021: distinguish "4byte does not know this" from "we could not ask".\n--\n-- 0020 recorded a miss whenever an upstream lookup produced nothing, with one\n-- 7-day TTL, which conflated a real absence (200 + empty result) with a timeout or\n-- 429 (we learned nothing). A transient outage could therefore poison the cache for\n-- a week.\nalter table fourbyte_misses\n  add column if not exists reason text not null default 'unknown';\n\ndo $$\nbegin\n  if not exists (\n    select 1 from pg_constraint where conname = 'fourbyte_misses_reason_check'\n  ) then\n    alter table fourbyte_misses\n      add constraint fourbyte_misses_reason_check\n      check (reason in ('unknown', 'unreachable'));\n  end if;\nend $$;\n`,
  "0020_fourbyte_misses.sql": `-- Migration 0020: remember which selectors/topics 4byte.directory does NOT know.\n--\n-- A bytecode-only contract has no ABI, so every selector is unknown and goes\n-- upstream: N selectors / 8 lanes x the per-request timeout. Only FOUND\n-- signatures were cached, so the same misses were re-fetched for every contract\n-- in a run (measured: 20 s per address, 23 days for 100k). A miss is now\n-- recorded with a 7-day TTL, because 4byte does gain signatures over time.\ncreate table if not exists fourbyte_misses (\n  kind       text        not null check (kind in ('signatures', 'event-signatures')),\n  key        text        not null,\n  checked_at timestamptz not null default now(),\n  primary key (kind, key)\n);\n\ncreate index if not exists fourbyte_misses_checked_idx on fourbyte_misses (checked_at);\n`,
  "0019_drop_rag.sql": `-- Migration 0019: drop the RAG knowledge base.\n--\n-- RAG was eliminated 2026-10-21 (chunks stopped being written); this removes\n-- the table, its full-text index, and the is_rag_indexed column nothing reads.\n-- Idempotent: safe where the table was already dropped by hand.\ndrop table if exists rag_knowledge_chunks cascade;\nalter table contract_scans drop column if exists is_rag_indexed;\n`,
  "0018_resnet_result.sql": `-- Migration 0018: ResNet1D screening result on contract_scans.\n--\n-- Every audit entry with runtime bytecode now gets a ResNet1D pass\n-- during the audit itself (analyzeAddress with an injected runner —\n-- the pipeline worker's Node runner, the browser worker for app\n-- flows — or runAndStore for pasted-bytecode saves), not only when a\n-- user opens the bytecode tab and clicks Run. The result is a small\n-- JSON verdict (model id, checkpoint hash, per-class scores against\n-- the manifest thresholds, input size, truncation flag, run time),\n-- stored here in the shape of src/lib/audit/resnet-result.ts.\n--\n-- The report's risk_score already includes the model's bounded score\n-- term (at most +6, findings required, severity floors untouched —\n-- see resnet-result.ts); this column is the durable evidence for\n-- that term, so a stored score can always be explained after the\n-- fact. Null = screening did not run for this record (no runtime\n-- bytecode, or the model was unavailable in that environment).\nalter table contract_scans add column if not exists resnet_json text;\n`,
};