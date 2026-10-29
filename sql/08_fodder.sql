-- 08_fodder.sql — chain-wide pipeline fodder: contracts that contain LOGIC.
--
-- The archive this replaces was 55% proxy shells and wallets, because it was built
-- from "addresses holding ETH". That is garbage in. This builds the list from what a
-- contract IS and DOES instead:
--
--   * real runtime code, not a forwarder  (structural test, not an opcode guess)
--   * one row per distinct program        (343 Safe proxies are one program)
--   * a payout path or value at risk      (something to take)
--   * reachable                           (distinct callers, from traces)
--
-- Query A costs almost nothing (contracts + balances). Query B adds traces and is the
-- expensive one — read the cost note above it before running.
--
-- Schema rules this obeys (see sql/README.md):
--   * bytecode is hex TEXT; length/2 is runtime bytes. No LIKE on opcodes — a 10 KB
--     contract matches every 1-byte pattern by accident, and `f4` inside PUSH data is
--     not an instruction.
--   * wei is BIGNUMERIC, never FLOAT64.
--   * every table is partitioned on block_timestamp and every query filters it.


-- ===========================================================================
-- QUERY A — cheap first pass: new logic contracts holding value.
-- Scans `contracts` (partition-filtered) and `balances` only. No traces.
-- ===========================================================================
declare window_start timestamp default timestamp_sub(current_timestamp(), interval 180 day);

with src as (
  select
    address,
    creator_address,
    block_timestamp,
    is_erc20,
    is_erc721,
    -- normalise the 0x prefix defensively: the dataset has shipped both forms
    regexp_replace(bytecode, r'^0[xX]', '') as bc
  from `bigquery-public-data.crypto_ethereum.contracts`
  where block_timestamp >= window_start
    and bytecode is not null
    and bytecode != ''
),

shaped as (
  select
    address, creator_address, block_timestamp, is_erc20, is_erc721,
    bc,
    div(length(bc), 2)                                    as runtime_bytes,
    to_hex(sha256(bc))                                    as code_hash,
    -- A forwarder, by structure only. EIP-1167 is an exact 45-byte template with a
    -- fixed prefix; the small-forwarder bound catches GnosisSafeProxy (~200 bytes),
    -- OZ ERC1967Proxy and beacon proxies, which are a few hundred bytes of assembly
    -- and hold no logic. Real logic is far larger.
    starts_with(bc, '363d3d373d3d3d363d73')                as is_eip1167,
    div(length(bc), 2) <= 1000                            as is_small_forwarder,
    -- how widely this exact body is deployed: a tie-break, not a verdict. Counted
    -- here rather than in a second pass over `contracts`.
    count(*) over (partition by to_hex(sha256(bc)))        as deployments
  from src
),

-- One row per distinct program. Without this, a body deployed 343 times produces 343
-- candidates and the analyser spends its budget re-reading the same code.
deduped as (
  select *
  from shaped
  where not is_eip1167
    and not is_small_forwarder
    -- solc's ceiling is 24576 bytes; anything at the cap is a generated megacontract
    and runtime_bytes between 1001 and 24576
  qualify row_number() over (partition by code_hash order by block_timestamp) = 1
),

balances as (
  select address, safe_cast(eth_balance as bignumeric) as wei
  from `bigquery-public-data.crypto_ethereum.balances`
  where block_timestamp >= timestamp_sub(current_timestamp(), interval 2 day)
  qualify row_number() over (partition by address order by block_timestamp desc) = 1
)
select
  d.address,
  d.runtime_bytes,
  d.is_erc20,
  d.is_erc721,
  d.block_timestamp                                        as deployed_at,
  round(coalesce(b.wei, 0) / 1e18, 4)                      as eth,
  d.deployments,
  left(d.code_hash, 12)                                    as code_hash12,
  'logic contract, new, holds value'                       as why
from deduped d
left join balances b on b.address = d.address
where coalesce(b.wei, 0) > 0
order by b.wei desc
limit 2000;


-- ===========================================================================
-- QUERY B — behavioural. This is the one that produces real fodder.
--
-- COST WARNING: `traces` is the largest table in the dataset. The block_timestamp
-- filter is mandatory and is the only thing standing between you and a scan of the
-- full history. Start with 30 days, one chain, and check the dry-run bytes before
-- running it wide. Narrow `window_start` first, not the LIMIT — the LIMIT does not
-- reduce the scan.
-- ===========================================================================
declare win_start timestamp default timestamp_sub(current_timestamp(), interval 30 day);

with src as (
  select
    address, block_timestamp, is_erc20, is_erc721,
    regexp_replace(bytecode, r'^0[xX]', '') as bc
  from `bigquery-public-data.crypto_ethereum.contracts`
  where block_timestamp >= win_start
    and bytecode is not null and bytecode != ''
),

logic as (
  select
    address, block_timestamp, is_erc20, is_erc721,
    div(length(bc), 2)                as runtime_bytes,
    to_hex(sha256(bc))                as code_hash,
    starts_with(bc, '363d3d373d3d3d363d73') as is_eip1167,
    div(length(bc), 2) <= 1000        as is_small_forwarder
  from src
),

candidates as (
  select *
  from logic
  where not is_eip1167
    and not is_small_forwarder
    and runtime_bytes between 1001 and 24576
  qualify row_number() over (partition by code_hash order by block_timestamp) = 1
),

-- One pass over traces, aggregated per contract. `input` gives the selector, so
-- distinct selectors is a direct measure of API surface — the thing a reader has to
-- get through, and the denominator for "how much of this is reachable".
t as (
  select
    to_address                                     as address,
    count(distinct from_address)                   as distinct_callers,
    count(*)                                       as calls_in,
    count(distinct substr(input, 1, 10))           as distinct_selectors,
    countif(call_type = 'DELEGATECALL')            as delegatecalls,
    countif(call_type = 'CALLCODE')                as callcodes,
    sum(safe_cast(value as bignumeric))            as wei_in
  from `bigquery-public-data.crypto_ethereum.traces`
  where block_timestamp >= win_start
    and status = 1
    and to_address is not null
  group by to_address
),

out as (
  select
    from_address                                   as address,
    count(*)                                       as calls_out,
    countif(to_address is not null and safe_cast(value as bignumeric) > 0) as value_sends,
    sum(safe_cast(value as bignumeric))            as wei_out
  from `bigquery-public-data.crypto_ethereum.traces`
  where block_timestamp >= win_start
    and status = 1
    and from_address is not null
  group by from_address
),

-- The reentrancy tell: a contract entered three or more times inside one
-- transaction. A flash loan enters a pool twice (borrow, repay) and a reentrant
-- attacker enters the victim twice; either way it is worth a look, and it is the
-- cheapest behavioural proxy for the shape.
reentry as (
  select address, count(*) as hot_txs
  from (
    select to_address as address, transaction_hash, count(*) as entries
    from `bigquery-public-data.crypto_ethereum.traces`
    where block_timestamp >= win_start and status = 1 and to_address is not null
    group by to_address, transaction_hash
    having count(*) >= 3
  )
  group by address
),

balances as (
  select address, safe_cast(eth_balance as bignumeric) as wei
  from `bigquery-public-data.crypto_ethereum.balances`
  where block_timestamp >= timestamp_sub(current_timestamp(), interval 2 day)
  qualify row_number() over (partition by address order by block_timestamp desc) = 1
)

select
  c.address,
  c.runtime_bytes,
  c.is_erc20,
  c.is_erc721,
  c.block_timestamp                              as deployed_at,
  round(coalesce(b.wei, 0) / 1e18, 4)            as eth,
  coalesce(t.distinct_callers, 0)                as distinct_callers,
  coalesce(t.distinct_selectors, 0)              as selectors,
  coalesce(t.calls_in, 0)                        as calls_in,
  coalesce(t.delegatecalls, 0)                   as delegatecalls,
  coalesce(o.value_sends, 0)                     as value_sends,
  coalesce(r.hot_txs, 0)                         as multi_entry_txs,
  round(coalesce(t.wei_in, 0) / 1e18, 4)         as eth_in,
  round(coalesce(o.wei_out, 0) / 1e18, 4)        as eth_out,
  -- Score the PRECONDITIONS, not a verdict. Reachability dominates: a contract
  -- nobody calls is not a target. Value breaks ties, it does not create an entry.
  round(
      least(coalesce(t.distinct_callers, 0) / 200.0, 1)          * 0.30   -- reachable
    + least(coalesce(t.distinct_selectors, 0) / 20.0, 1)         * 0.20   -- surface
    + least(coalesce(r.hot_txs, 0) / 5.0, 1)                     * 0.20   -- re-entry
    + least(coalesce(t.delegatecalls, 0) / 3.0, 1)               * 0.15   -- dispatch
    + least(coalesce(o.value_sends, 0) / 10.0, 1)                * 0.15   -- payout path
  , 3)                                                          as fodder_score,
  concat(
    if(coalesce(r.hot_txs,0) > 0, 're-entry ', ''),
    if(coalesce(t.delegatecalls,0) > 0, 'delegatecall ', ''),
    if(coalesce(o.value_sends,0) > 0, 'payout ', ''),
    if(coalesce(t.distinct_callers,0) >= 10, 'reachable ', ''),
    if(coalesce(b.wei,0) > 0, 'holds value', '')
  )                                                             as why
from candidates c
left join t        on t.address = c.address
left join o        on o.address = c.address
left join reentry r on r.address = c.address
left join balances b on b.address = c.address
where coalesce(t.distinct_callers, 0) >= 3        -- somebody actually calls it
  and (coalesce(o.value_sends, 0) > 0             -- it pays out
    or coalesce(b.wei, 0) > 0                     -- or it holds value
    or coalesce(r.hot_txs, 0) > 0)                -- or it is re-entered
order by fodder_score desc, coalesce(b.wei, 0) desc
limit 500;
