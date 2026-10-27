-- wipe.sql — clear the scan archive, keep the schema.
--
-- Run against the project's Postgres (Supabase). NOT run by the agent: this
-- sandbox has no route to the database.
--
--   psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f wipe.sql
--
-- TAKE A DUMP FIRST. This is irreversible and there is no undo:
--   pg_dump "$DATABASE_URL" --no-owner --no-privileges -Fc -f pre-wipe-$(date +%F).dump
--
-- What goes: every scan, every finding, every PoC run and verdict, the fourbyte
-- and false-positive signature caches, the RAG chunks and the auditor
-- dispositions. What stays: the tables, indexes, constraints and the
-- migrations table, so the worker's freshness check still passes and no
-- re-migration is needed.

begin;

-- Counted before the truncate, so the transaction's output says what it removed.
select 'contract_scans' as table, count(*) from contract_scans
union all select 'findings', count(*) from findings
union all select 'finding_poc_runs', count(*) from finding_poc_runs
union all select 'scan_payloads', count(*) from scan_payloads
union all select 'rag_knowledge_chunks', count(*) from rag_knowledge_chunks
union all select 'auditor_dispositions', count(*) from auditor_dispositions
union all select 'fp_signatures', count(*) from fp_signatures
union all select 'fourbyte_signatures', count(*) from fourbyte_signatures
union all select 'fourbyte_event_signatures', count(*) from fourbyte_event_signatures;

-- RESTART IDENTITY is harmless (ids are text) and keeps any sequence honest.
-- CASCADE handles the FK order: findings -> contract_scans, poc runs -> findings.
truncate table
  finding_poc_runs,
  findings,
  scan_payloads,
  rag_knowledge_chunks,
  auditor_dispositions,
  fp_signatures,
  fourbyte_signatures,
  fourbyte_event_signatures,
  contract_scans
restart identity cascade;

commit;
