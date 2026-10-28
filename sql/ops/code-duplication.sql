-- How much of the archive is the same code deployed many times?
--
-- Run before enabling bytecode dedupe, and again after: the point of the exercise is
-- that this ratio moves toward 1.
--
--   psql "$DATABASE_URL" -f sql/ops/code-duplication.sql

\echo '=== bodies: distinct analysed inputs vs scans ==='
select count(*)                                    as scans,
       count(distinct body)                        as distinct_bodies,
       round(count(*)::numeric / greatest(count(distinct body), 1), 2) as copies_per_body
from scan_payloads;

\echo ''
\echo '=== the biggest duplicate groups (top 15) ==='
select left(md5(body), 12) as body_hash,
       count(*)            as scans,
       min(s.target_address) as example_address
from scan_payloads p
join contract_scans s on s.id = p.scan_id
group by 1
having count(*) > 1
order by 2 desc
limit 15;

\echo ''
\echo '=== once code_hash is populated (migration 0022) ==='
-- count(distinct (chain_id, code_hash)) counts the single NULL group as one distinct
-- value, so on an archive where nothing is hashed yet it reports "1595 copies of one
-- code" — the opposite of the truth. Exclude NULL explicitly and report 0 instead.
select count(*) filter (where code_hash is not null) as hashed,
       count(distinct case when code_hash is not null
                           then chain_id || ':' || code_hash end) as distinct_code,
       count(*) as scans,
       case when count(distinct case when code_hash is not null
                                     then chain_id || ':' || code_hash end) = 0
            then null
            else round(count(*) filter (where code_hash is not null)::numeric /
                       count(distinct case when code_hash is not null
                                           then chain_id || ':' || code_hash end), 2)
       end as copies_per_code
from contract_scans;
