-- check-schema.sql — does the database match what the code expects?
--
--   psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f sql/ops/check-schema.sql
--
-- Written after two surprises in one session: `rag_knowledge_chunks` was already
-- gone (migration 0019 now drops it on purpose) and the fourbyte caches were
-- missing even though migrations 0005/0006 create them. The runtime applies a
-- migration only if `_migrations` does not already record it, so a table that was
-- dropped by hand never comes back — and every lookup silently degrades to the
-- live API instead.

-- 1. Expected tables and whether they are actually there.
with expected(name) as (
  values ('contract_scans'), ('findings'), ('finding_poc_runs'), ('scan_payloads'),
         ('fp_signatures'), ('fourbyte_signatures'), ('fourbyte_event_signatures'),
         ('auditor_dispositions'), ('dispositions_archive'), ('rag_knowledge_chunks')
)
select e.name                                        as table,
       (to_regclass('public.' || e.name) is not null) as present,
       case
         when e.name = 'rag_knowledge_chunks' then 'dropped by 0019 — absence is correct'
         when e.name = 'dispositions_archive' then 'created by wipe-keep-caches.sql'
         when to_regclass('public.' || e.name) is null then 'MISSING — code expects this'
         else 'ok'
       end                                           as note
from expected e
order by present, e.name;

-- 2. Migrations recorded as applied. A table that is missing while its migration
--    is listed here will never be re-created automatically.
select * from _migrations order by 1;

-- 3. Row counts for the tables that should be small caches.
select 'fp_signatures' as table, count(*) from fp_signatures
union all select 'fourbyte_signatures', count(*) from fourbyte_signatures
union all select 'fourbyte_event_signatures', count(*) from fourbyte_event_signatures
order by 1;
