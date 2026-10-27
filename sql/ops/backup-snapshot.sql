-- backup.sql — snapshot the scan archive into a schema, using only SQL.
--
-- Run against the project's Postgres (Supabase). NOT run by the agent: this
-- sandbox has no route to the database.
--
--   psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f backup.sql
--
-- WHAT THIS IS AND IS NOT. This copies every table into a `backup_<date>` schema
-- INSIDE the same database. That is enough to undo a bad DELETE or a truncate
-- (restore.sql), and it needs nothing but psql. It is NOT a backup of the
-- project: if the Supabase project is deleted, the plan lapses, or the disk
-- fills, the copy goes with it. For that, take one off-box copy as well:
--
--   pg_dump "$DATABASE_URL" --no-owner --no-privileges -Fc \
--     -f smartkontrakt-$(date +%F).dump
--
-- SIZE: the copy doubles the archive. contract_scans carries inventory_json,
-- ai_review_json, probes_json and a body per scan, so on a 100k-row table this is
-- the expensive part. Run the size check below first; if the answer is
-- uncomfortable, snapshot only the small tables (the block is marked) and rely
-- on the pg_dump for the rest.

-- ---------------------------------------------------------------- size check
select relname                                              as table,
       to_char(pg_total_relation_size(c.oid), 'FM999,999,999,999') as bytes,
       pg_size_pretty(pg_total_relation_size(c.oid))        as pretty
from pg_class c
join pg_namespace n on n.oid = c.relnamespace
where n.nspname = 'public' and c.relkind = 'r'
order by pg_total_relation_size(c.oid) desc;

-- ------------------------------------------------------------------- snapshot
-- A snapshot is point-in-time. Re-running this with the same name must NOT
-- silently leave yesterday's copy in place while looking like a fresh backup, so
-- an existing snapshot is a hard stop: change the schema name (backup_20261028)
-- rather than dropping the only copy you have.
do $$
begin
  if exists (
    select 1
    from pg_class c
    join pg_namespace n on n.oid = c.relnamespace
    where n.nspname = 'backup_20261027' and c.relkind = 'r'
  ) then
    raise exception 'backup_20261027 already holds tables - use a new snapshot name, and keep this one unless the pg_dump is verified';
  end if;
end $$;

begin;

create schema if not exists backup_20261027;

-- Parents first, so restore.sql can insert in the same order.
create table if not exists backup_20261027.contract_scans         as table public.contract_scans;
create table if not exists backup_20261027.findings               as table public.findings;
create table if not exists backup_20261027.finding_poc_runs       as table public.finding_poc_runs;
create table if not exists backup_20261027.scan_payloads          as table public.scan_payloads;
create table if not exists backup_20261027.rag_knowledge_chunks   as table public.rag_knowledge_chunks;
create table if not exists backup_20261027.auditor_dispositions   as table public.auditor_dispositions;
create table if not exists backup_20261027.fp_signatures          as table public.fp_signatures;
create table if not exists backup_20261027.fourbyte_signatures    as table public.fourbyte_signatures;
create table if not exists backup_20261027.fourbyte_event_signatures as table public.fourbyte_event_signatures;

-- The counts that must match after a restore.
select 'contract_scans' as table, count(*) from backup_20261027.contract_scans
union all select 'findings', count(*) from backup_20261027.findings
union all select 'finding_poc_runs', count(*) from backup_20261027.finding_poc_runs
union all select 'scan_payloads', count(*) from backup_20261027.scan_payloads
union all select 'rag_knowledge_chunks', count(*) from backup_20261027.rag_knowledge_chunks
union all select 'auditor_dispositions', count(*) from backup_20261027.auditor_dispositions
union all select 'fp_signatures', count(*) from backup_20261027.fp_signatures
union all select 'fourbyte_signatures', count(*) from backup_20261027.fourbyte_signatures
union all select 'fourbyte_event_signatures', count(*) from backup_20261027.fourbyte_event_signatures
order by 1;

commit;

-- Undo a restore (or drop the snapshot once the pg_dump is verified):
--   drop schema backup_20261027 cascade;
