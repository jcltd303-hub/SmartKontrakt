-- 02_priority_queue.sql — the ranking. Run on BigQuery.
--
-- "Which contracts should a human read first?" scored with the same model the
-- report uses: reachability first, evidence second, mechanism (not rule count)
-- third, money at risk as the tie-break.
--
-- The two things that make this different from `order by risk_score desc`:
--
--   1. A finding that is GATED or INTERNAL scores ~0. It is not a finding. The
--      engagement that motivated all of this produced 480 hits and one real
--      issue, and every false positive was a shape that existed but was
--      unreachable.
--   2. The score is summed over FAMILIES, taking each family's best finding,
--      not over findings. Otherwise one contract with six price-plumbing notes
--      outranks one with a single reachable takeover.

with scored as (
  -- One row per FINDING. Only the score is computed here; aggregation happens
  -- in the CTEs below, because scoring per family needs the individual rows.
  select
    address,
    chain_id,
    contract_name,
    verified_name,
    label_check,
    balance_wei,
    value_usd,
    risk_score,
    detector,
    family,
    severity,
    confidence,
    reachability,
    title,
    poc_status,
    economic_basis,

    -- Reachability: the decisive dimension.
    (case reachability
       when 'REACHABLE' then 1.00
       when 'NEEDS_READ' then 0.45
       when 'BOUNDED'    then 0.15
       when 'GATED'      then 0.10
       when 'INTERNAL'   then 0.00
       else 0.05
     end)
    -- Evidence: a resolved site outranks text-matched, outranks file-level.
    * (case confidence
         when 'high'   then 1.0
         when 'medium' then 0.6
         when 'low'    then 0.3
         else 0.3
       end)
    * (case severity
         when 'critical' then 1.00
         when 'high'     then 0.70
         when 'medium'   then 0.35
         when 'low'      then 0.10
         else 0.00
       end)
    -- Mechanism: where the money actually went, 2021-2026.
    * (case family
         when 'caller-identity'      then 1.00
         when 'price-plumbing'       then 0.95
         when 'value-and-settlement' then 0.90
         when 'reentrancy'           then 0.85
         when 'governance'           then 0.80
         when 'arithmetic'           then 0.60
         when 'randomness'           then 0.55
         when 'token-accounting'     then 0.55
         when 'ordering'             then 0.40
         when 'evm-and-bytecode'     then 0.35
         else 0.00
       end)                                    as score
  from `smartkontract.findings`
  where date(scanned_at) >= date_sub(current_date(), interval 30 day)
    and severity != 'info'
    and family not in ('hygiene', 'analyzer-meta')
),

contract_totals as (
  select
    address,
    any_value(chain_id)                     as chain_id,
    any_value(contract_name)                as contract_name,
    any_value(verified_name)                as verified_name,
    any_value(label_check)                  as label_check,
    any_value(balance_wei)                  as balance_wei,
    max(value_usd)                          as value_usd,
    max(risk_score)                         as risk_score,
    count(*)                                as findings,
    countif(reachability = 'REACHABLE')     as reachable_findings,
    countif(confidence = 'low')             as low_confidence_findings,
    countif(poc_status = 'confirmed')       as poc_confirmed,
    countif(economic_basis = 'assumption')  as unverified_figures
  from scored
  group by address
),

-- Each family's best finding per contract: a contract is as suspicious as the
-- strongest thing in it, and breadth across mechanisms adds on top.
per_family as (
  select
    address,
    family,
    max(score)                                                   as family_score,
    array_agg(title      order by score desc limit 1)[offset(0)]  as top_title
  from scored
  group by address, family
),

rolled as (
  select
    address,
    least(count(distinct family), 4) * 0.10                       as breadth,
    sum(family_score)                                             as mechanism_score,
    string_agg(family, ', ' order by family_score desc)            as families,
    -- ARRAY_AGG (not STRING_AGG) is the aggregate that accepts LIMIT here.
    array_to_string(
      array_agg(concat(family, ': ', top_title) order by family_score desc limit 3),
      ' | '
    )                                                             as why
  from per_family
  group by address
)

select
  r.address,
  t.chain_id,
  coalesce(t.verified_name, t.contract_name)                      as contract,
  case when t.label_check like 'label_mismatch%' then 'MISMATCH'
       when t.label_check = 'label_unverified'   then 'unverified'
       else 'ok' end                                              as label,
  round(r.mechanism_score + r.breadth, 3)                         as priority,
  r.families,
  r.why,
  t.reachable_findings,
  t.findings,
  t.low_confidence_findings,
  t.poc_confirmed,
  -- Money at risk, computed only when a live balance was actually read.
  -- balance_wei is a string because wei overflows float64.
  round(safe_divide(safe_cast(t.balance_wei as bignumeric), 1e18), 4) as eth_at_risk,
  t.value_usd,
  t.unverified_figures,
  t.risk_score
from rolled r
join contract_totals t using (address)
-- The decisive filter: nothing without a reachable finding is a queue entry.
where t.reachable_findings > 0
order by priority desc, eth_at_risk desc nulls last
limit 100;
