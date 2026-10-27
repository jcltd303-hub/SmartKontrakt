-- 03_chain_candidates.sql — candidate generation from public chain data.
--
-- The analyzer answers "is this contract vulnerable". This answers the question
-- before it: "out of every deployed contract, which few hundred are worth
-- spending an analysis on?" It uses only on-chain behaviour, so it works for
-- contracts with no source.
--
-- The signals are the preconditions of the classes this repo detects, not
-- vulnerability itself:
--
--   * VALUE IN      — the contract receives native value (there is something to
--                     steal, and `locked-ether`/payout paths matter).
--   * CALLS OUT     — it makes external calls. A contract that never calls out
--                     cannot have a reentrancy or a calldata-dispatch bug.
--   * DELEGATECALL  — it delegatecalls, which is the proxy/upgrade surface
--                     (SWC-112) and the highest-severity class in the record.
--   * MANY CALLERS  — distinct senders is the on-chain proxy for reachability:
--                     a function only one bot calls is not a public entry point.
--   * FRESH         — deployed inside the window; new code is where new bugs are.
--
-- Cost: `traces` is the largest table in the dataset. The partition filter is
-- mandatory, the aggregation is per-contract, and the final LIMIT is small. Run
-- it for one chain at a time and expect it to be the most expensive query here.

declare window_start timestamp default timestamp_sub(current_timestamp(), interval 90 day);

with recent_traces as (
  select
    from_address,
    to_address,
    value,
    call_type,
    status,
    block_timestamp
  from `bigquery-public-data.crypto_ethereum.traces`
  where block_timestamp >= window_start
    -- Only successful calls: a reverted delegatecall moved no value and proves
    -- nothing about the deployed behaviour.
    and status = 1
    and to_address is not null
),

inbound as (
  select
    to_address                                    as address,
    count(*)                                      as calls_in,
    count(distinct from_address)                   as distinct_callers,
    sum(safe_cast(value as bignumeric))            as wei_in
  from recent_traces
  group by to_address
),

outbound as (
  select
    from_address                                  as address,
    countif(to_address is not null)                as calls_out,
    countif(call_type = 'DELEGATECALL')            as delegatecalls,
    countif(call_type = 'CALLCODE')                as callcodes,
    sum(safe_cast(value as bignumeric))            as wei_out
  from recent_traces
  group by from_address
),

deployed as (
  select
    address,
    block_timestamp                               as deployed_at,
    is_erc20,
    is_erc721,
    creator_address,
    length(bytecode)                              as bytecode_len
  from `bigquery-public-data.crypto_ethereum.contracts`
  where block_timestamp >= window_start
)

select
  d.address,
  d.deployed_at,
  d.is_erc20,
  d.is_erc721,
  d.bytecode_len,
  i.calls_in,
  i.distinct_callers,
  o.calls_out,
  o.delegatecalls,
  o.callcodes,
  -- Net native value the contract has taken in over the window. Not a balance
  -- (the dataset has no live balance column); a floor on what passed through.
  round(safe_divide(coalesce(i.wei_in, 0) - coalesce(o.wei_out, 0), 1e18), 4) as net_eth_through,

  -- Precondition score. Weights say what makes a contract worth a scan, in the
  -- order the incident record supports: delegatecall first (proxy takeover),
  -- then value in, then reachability, then freshness.
  round(
      least(coalesce(o.delegatecalls, 0), 10) * 0.25
    + least(safe_divide(coalesce(i.wei_in, 0), 1e18), 100) * 0.02
    + least(coalesce(i.distinct_callers, 0), 500) * 0.004
    + least(coalesce(o.calls_out, 0), 200) * 0.002
    + least(coalesce(d.bytecode_len, 0) / 24000.0, 1) * 0.10
  , 3)                                                                            as candidate_score,

  case
    when coalesce(o.delegatecalls, 0) > 0 and coalesce(i.wei_in, 0) > 0
      then 'delegatecall + value: proxy/upgrade surface holding funds'
    when coalesce(o.delegatecalls, 0) > 0
      then 'delegatecall: untrusted-callee surface (SWC-112)'
    when coalesce(i.wei_in, 0) > 0 and coalesce(o.calls_out, 0) > 0
      then 'holds value and calls out: payout / reentrancy surface'
    when coalesce(i.distinct_callers, 0) > 100
      then 'many distinct callers: public entry points worth a reachability pass'
    else 'low-signal'
  end                                                                             as why
from deployed d
join inbound  i on i.address = d.address
left join outbound o on o.address = d.address
where coalesce(i.wei_in, 0) > 0                       -- must have had value in
   or coalesce(o.delegatecalls, 0) > 0                -- or be a delegatecall surface
order by candidate_score desc, net_eth_through desc
limit 500;
