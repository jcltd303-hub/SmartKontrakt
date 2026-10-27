-- wipe-keep-caches.sql — clear the scan archive, keep what was learned.
--
--   psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f wipe-keep-caches.sql
--
-- Why this and not wipe.sql: three of the nine tables are not scan output.
--
--   fp_signatures              accumulated false-positive knowledge
--                              (detector + title pattern + evidence/scan counts +
--                              confirmed/dismissed decisions). This is the thing
--                              the tool gets better at over time. It survives a
--                              findings wipe intact — sample_finding_ids is a
--                              text column, not a foreign key.
--   fourbyte_signatures        selector-name cache. Re-fetchable, but re-fetching
--   fourbyte_event_signatures  thousands of selectors costs time and quota.
--
-- And one table is destroyed as a SIDE EFFECT unless you save it first:
-- auditor_dispositions.finding_id REFERENCES findings(id) ON DELETE CASCADE, so
-- truncating findings silently takes every human confirmed / false_positive /
-- needs_more_info decision with it. This script copies them out before the
-- truncate.

begin;

-- 1. Preserve human triage across the cascade. Deliberately NOT under a
--    backup_* schema: this is data you want to keep, not a snapshot to drop.
create table if not exists dispositions_archive (
  finding_id  text        not null,
  disposition text        not null,
  note        text,
  updated_at  timestamptz,
  archived_at timestamptz not null default now()
);

insert into dispositions_archive (finding_id, disposition, note, updated_at)
select d.finding_id, d.disposition, d.note, d.updated_at
from auditor_dispositions d
where not exists (
  select 1 from dispositions_archive a where a.finding_id = d.finding_id
);

-- 2. What is being removed, counted first.
select 'contract_scans' as table, count(*) from contract_scans
union all select 'findings', count(*) from findings
union all select 'finding_poc_runs', count(*) from finding_poc_runs
union all select 'scan_payloads', count(*) from scan_payloads
union all select 'rag_knowledge_chunks', count(*) from rag_knowledge_chunks
union all select 'auditor_dispositions', count(*) from auditor_dispositions
order by 1;

-- 3. Scan output only. fp_signatures and the fourbyte caches are NOT touched.
truncate table
  finding_poc_runs,
  findings,
  scan_payloads,
  rag_knowledge_chunks,
  contract_scans
restart identity cascade;

-- 4. What survived, so the transcript shows it.
select 'fp_signatures (kept)' as table, count(*) from fp_signatures
union all select 'fourbyte_signatures (kept)', count(*) from fourbyte_signatures
union all select 'fourbyte_event_signatures (kept)', count(*) from fourbyte_event_signatures
union all select 'dispositions_archive (kept)', count(*) from dispositions_archive
order by 1;

commit;
