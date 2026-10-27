-- restore.sql — put the archive back from a backup_<date> snapshot.
--
--   psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -v snap=backup_20261027 -f restore.sql
--
-- One transaction: either the whole archive comes back or nothing changes.
-- Insert order follows the foreign keys (contract_scans, then findings, then
-- poc runs); truncate runs in the reverse order with CASCADE.

\if :{?snap}
\else
  \echo 'pass the snapshot schema: -v snap=backup_20261027'
  \quit
\endif

begin;

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

insert into public.contract_scans         select * from :"snap".contract_scans;
insert into public.findings               select * from :"snap".findings;
insert into public.finding_poc_runs       select * from :"snap".finding_poc_runs;
insert into public.scan_payloads          select * from :"snap".scan_payloads;
insert into public.rag_knowledge_chunks   select * from :"snap".rag_knowledge_chunks;
insert into public.auditor_dispositions   select * from :"snap".auditor_dispositions;
insert into public.fp_signatures          select * from :"snap".fp_signatures;
insert into public.fourbyte_signatures    select * from :"snap".fourbyte_signatures;
insert into public.fourbyte_event_signatures select * from :"snap".fourbyte_event_signatures;

-- Verify against the numbers backup.sql printed.
select 'contract_scans' as table, count(*) from public.contract_scans
union all select 'findings', count(*) from public.findings
union all select 'finding_poc_runs', count(*) from public.finding_poc_runs
union all select 'scan_payloads', count(*) from public.scan_payloads
union all select 'rag_knowledge_chunks', count(*) from public.rag_knowledge_chunks
union all select 'auditor_dispositions', count(*) from public.auditor_dispositions
union all select 'fp_signatures', count(*) from public.fp_signatures
union all select 'fourbyte_signatures', count(*) from public.fourbyte_signatures
union all select 'fourbyte_event_signatures', count(*) from public.fourbyte_event_signatures
order by 1;

commit;
