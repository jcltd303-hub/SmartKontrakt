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
};
