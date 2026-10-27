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

-- 2. What is being removed, counted first. Only tables that EXIST are counted and
--    truncated: a database whose migrations drifted (or where a table was dropped
--    by hand) must not abort the wipe on a missing relation — that is what
--    happened with rag_knowledge_chunks before migration 0019 removed it.
do $$
declare
  t text;
  n bigint;
  targets text[] := array['contract_scans','findings','finding_poc_runs','scan_payloads','rag_knowledge_chunks','auditor_dispositions'];
begin
  foreach t in array targets loop
    if to_regclass('public.' || t) is not null then
      execute format('select count(*) from public.%I', t) into n;
      raise notice 'will remove  %  % rows', rpad(t, 24), n;
    else
      raise notice 'skipping      %  (does not exist)', rpad(t, 24);
    end if;
  end loop;
end $$;

-- 3. Scan output only. fp_signatures and the fourbyte caches are NOT touched.
--    Built dynamically so a missing table is skipped rather than fatal.
do $$
declare
  t text;
  targets text[] := array['finding_poc_runs','findings','scan_payloads','rag_knowledge_chunks','contract_scans'];
begin
  foreach t in array targets loop
    if to_regclass('public.' || t) is not null then
      execute format('truncate table public.%I restart identity cascade', t);
    end if;
  end loop;
end $$;

-- 4. What survived, so the transcript shows it.
do $$
declare
  t text;
  n bigint;
  keeps text[] := array['fp_signatures','fourbyte_signatures','fourbyte_event_signatures','dispositions_archive'];
begin
  foreach t in array keeps loop
    if to_regclass('public.' || t) is not null then
      execute format('select count(*) from public.%I', t) into n;
      raise notice 'kept          %  % rows', rpad(t, 24), n;
    end if;
  end loop;
end $$;

commit;
