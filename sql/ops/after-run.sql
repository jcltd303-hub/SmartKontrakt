-- after-run.sql — did the new cohort produce anything, and did the analyser stay quiet
-- where it should?
--
-- Run in the Supabase SQL editor after a /start on a BigQuery-derived list.
-- Read-only. Plain SELECTs, no psql meta-commands.
--
-- The question is NOT "how many findings". It is whether the newer families fire on
-- established, audited implementations, and whether the analyser is silent on the ones
-- that are genuinely clean. Eighty known-good protocol implementations scoring zero is
-- precision evidence this corpus has never had; sixty of them screaming means the
-- rules are still too loose.

-- 1. What the run produced, by detector and severity.
--    Zero rows for vault-inflation-donation / signature-threshold-no-dedupe /
--    unbacked-mint is a specific, checkable answer — not necessarily a bug in them.
select
  f.detector,
  f.severity,
  count(*)                            as findings,
  count(distinct s.target_address)    as contracts,
  round(avg(case when f.confidence_basis is not null then 1 else 0 end), 2) as with_basis
from findings f
join contract_scans s on s.id = f.scan_id
where s.created_at > now() - interval '1 day'
group by 1, 2
order by 3 desc;

-- 2. Per contract: how loud is the analyser on a cohort of survivors?
--    A flat distribution around 0-3 findings is what a working detector looks like on
--    audited code. A spike means one rule is over-firing.
select
  s.contract_name,
  s.target_address,
  s.critical_count, s.high_count, s.medium_count, s.low_count,
  s.risk_score,
  s.input_kind
from contract_scans s
where s.created_at > now() - interval '1 day'
order by s.critical_count desc, s.high_count desc, s.risk_score desc
limit 100;

-- 3. The distribution, which is the number worth quoting.
select critical_count, count(*) as scans
from contract_scans
where created_at > now() - interval '1 day'
group by 1 order by 1;

-- 4. Did the dedupe earn its keep on this run?
--    A reused body means one analysis served several deployments.
select
  count(*)                                    as scans,
  count(distinct code_hash)                   as distinct_code,
  count(*) filter (where code_hash is null)   as unhashed,
  round(count(*)::numeric / greatest(count(distinct code_hash), 1), 2) as copies_per_code
from contract_scans
where created_at > now() - interval '1 day';

-- 5. Sanity: are the new detectors registered but silent, or never run?
--    A detector with no row anywhere in the archive is a rule that has never fired on
--    any input — worth one hand-read of a contract that should trigger it.
select d.detector,
       count(f.id) as findings_ever
from (
  values ('vault-inflation-donation'), ('signature-threshold-no-dedupe'),
         ('unbacked-mint'), ('oracle-spot'), ('signature-replay'),
         ('unprotected-initializer'), ('bridge-message-auth')
) as d(detector)
left join findings f on f.detector = d.detector
group by 1 order by 2 desc;
