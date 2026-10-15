-- Migration 0003: Comprehensive Records and Local RAG Knowledgebase
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
