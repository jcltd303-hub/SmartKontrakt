-- 04_value_at_risk.sql — findings joined to live value and activity.
--
-- Answers the question a client asks second: "of the reachable ones, which hold
-- money, and which are actually being used?"
--
-- The rule this enforces, from the engagement's worst error: **never publish a
-- money figure that came from a source constant**. A 400x-overstated pot (30.8
-- ETH against a 0.0775 ETH pool) and an 87x-overstated gas cost both came from
-- treating a constant as live state. So every number here is either a live read
-- (`balance_wei` from the scan's `eth_getBalance`) or explicitly marked as an
-- assumption (`economic_basis = 'assumption'`), and the two are never summed.

declare window_start timestamp default timestamp_sub(current_timestamp(), interval 30 day);

with queue as (
  select
    address,
    any_value(chain_id)                        as chain_id,
    any_value(coalesce(verified_name, contract_name)) as contract,
    any_value(balance_wei)                     as balance_wei,
    any_value(value_usd)                       as value_usd,
    countif(reachability = 'REACHABLE')        as reachable_findings,
    countif(economic_basis = 'assumption')     as assumed_figures,
    array_to_string(array_agg(distinct family), ', ') as families
  from `smartkontract.findings`
  where date(scanned_at) >= date_sub(current_date(), interval 30 day)
    and reachability = 'REACHABLE'
    and severity in ('critical', 'high', 'medium')
  group by address
),

activity as (
  select
    to_address                                  as address,
    count(*)                                    as calls_in,
    count(distinct from_address)                as distinct_callers,
    max(block_timestamp)                        as last_called
  from `bigquery-public-data.crypto_ethereum.traces`
  where block_timestamp >= window_start
    and status = 1
  group by to_address
)

select
  q.contract,
  q.address,
  q.chain_id,
  q.families,
  q.reachable_findings,

  -- Live value, from the scan's own eth_getBalance. NULL means "not read",
  -- which is deliberately different from 0.
  round(safe_divide(safe_cast(q.balance_wei as bignumeric), 1e18), 4)   as eth_at_risk,
  q.value_usd,
  q.assumed_figures,

  coalesce(a.calls_in, 0)                     as calls_30d,
  coalesce(a.distinct_callers, 0)             as callers_30d,
  a.last_called,

  -- The ranking that matters: reachable AND holding value AND being used.
  -- A reachable finding on a contract nobody calls is a curiosity; a reachable
  -- finding on a contract holding funds and taking daily calls is the job.
  round(
      q.reachable_findings
    * ln(1 + coalesce(safe_cast(safe_divide(safe_cast(q.balance_wei as bignumeric), 1e18) as float64), 0))
    * ln(1 + coalesce(a.distinct_callers, 0))
  , 3)                                                                   as urgency,

  case
    when q.balance_wei is null and a.calls_in is null then 'no live data: read balance and activity before publishing anything'
    when q.balance_wei is null                        then 'balance not read: the ETH figure would be an assumption'
    when coalesce(a.calls_in, 0) = 0                  then 'reachable but dormant in the window'
    when coalesce(safe_cast(q.balance_wei as bignumeric), 0) = 0 then 'reachable, nothing at stake right now'
    else 'reachable, funded, and in use'
  end                                                                    as verdict
from queue q
left join activity a on a.address = q.address
order by urgency desc nulls last
limit 200;
