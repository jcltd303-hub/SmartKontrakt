-- portfolio.sql — one query, one table: what the archive holds, by distinct code.
--
-- Run in the Supabase SQL editor (no psql meta-commands). Read-only.
--
-- Why grouped by BODY and not by scan: 1,613 scans turned out to be 375 distinct
-- programs (4.25 copies each), one GnosisSafeProxy body accounting for 343 of them.
-- Per-scan rows repeat the same code 343 times and hide the thing you care about.
--
-- Sorted by CRITICALS first and money second, which is the reverse of the workbench
-- ordering — the point of this table is to show that the two disagree.

with per_scan as (
  select
    s.id,
    s.target_address,
    s.contract_name,
    s.critical_count,
    s.high_count,
    s.medium_count,
    s.risk_score,
    coalesce(nullif(s.inventory_json::jsonb ->> 'proxy', ''), '(logic)') as proxy_kind,
    coalesce((s.inventory_json::jsonb ->> 'balanceWei')::numeric, 0) / 1e18 as eth,
    p.body
  from contract_scans s
  left join scan_payloads p on p.scan_id = s.id
),
per_body as (
  select
    left(md5(coalesce(body, id)), 12)      as body_hash,
    count(*)                               as scans,
    count(distinct target_address)         as addresses,
    min(contract_name)                     as contract_name,
    min(proxy_kind)                        as proxy_kind,
    round(sum(eth), 2)                     as eth,
    sum(critical_count)                    as criticals,
    sum(high_count)                        as highs,
    sum(medium_count)                      as mediums,
    round(avg(risk_score))                 as avg_score,
    bool_or(body ~ '^0x[0-9a-fA-F]+$')     as bytecode_only
  from per_scan
  group by 1
)
select
  contract_name,
  body_hash,
  proxy_kind,
  scans,
  addresses,
  eth,
  criticals,
  highs,
  mediums,
  avg_score,
  bytecode_only,
  -- the shape of the archive in one column: shells and wallets are 'no logic'
  case
    when criticals > 0                                  then 'has findings'
    when proxy_kind <> '(logic)'                        then 'shell'
    when contract_name ~* '(wallet|safe|proxy|vault)$'   then 'wallet-like'
    else 'logic, clean'
  end as bucket
from per_body
order by criticals desc, highs desc, eth desc
limit 100;
