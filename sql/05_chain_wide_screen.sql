-- 05_chain_wide_screen.sql — find likely-vulnerable contracts across the whole
-- chain, using NOTHING but public data. No join to our own scans, no dependency
-- on having analysed anything before.
--
-- WHY THIS DOES NOT MATCH BYTECODE PATTERNS
--
-- The obvious screen is `bytecode LIKE '%f4%'` for DELEGATECALL. It does not
-- work, and it is worth writing down why so nobody re-adds it: bytecode is hex,
-- so a 10 KB contract is ~20,000 hex characters, and the chance that any given
-- 1-byte opcode pattern appears somewhere in it by accident is
-- 1 - (1 - 1/256)^20000 ≈ 1. Every contract matches every opcode. Worse, an
-- `f4` inside PUSH32 constant data is not an opcode at all, and SQL cannot tell
-- the difference — that needs a real disassembler.
--
-- So every signal below is BEHAVIOURAL, read from `traces`, where BigQuery
-- records the actual call type the EVM executed:
--
--   DELEGATECALL / CALLCODE   exact, from `call_type` — the proxy/upgrade
--                             surface (SWC-112), the highest-severity class in
--                             the 2021-2026 record
--   value in                  there is something to take
--   value out to the caller   a payout path that returns value to msg.sender
--                             (the drain shape, and the refund-option shape)
--   distinct callers          the on-chain proxy for reachability: a function
--                             only one bot calls is not a public entry point
--   repeated entry            the same caller hitting the same contract many
--                             times in one transaction — the reentrancy tell
--
-- Cost: `traces` is the largest table in the dataset. Keep the partition filter,
-- run one window at a time, and expect this to be the most expensive query here.

declare window_start timestamp default timestamp_sub(current_timestamp(), interval 90 day);

with calls as (
  select
    transaction_hash,
    from_address,
    to_address,
    safe_cast(value as bignumeric)   as wei,
    call_type,
    to_hex(substr(input, 1, 4))       as selector,   -- 4-byte selector as hex
    block_timestamp
  from `bigquery-public-data.crypto_ethereum.traces`
  where block_timestamp >= window_start
    and status = 1                    -- successful only: a revert proves nothing
    and to_address is not null
    and from_address is not null
),

-- What each contract RECEIVES.
inbound as (
  select
    to_address                        as address,
    count(*)                          as calls_in,
    count(distinct from_address)      as distinct_callers,
    sum(wei)                          as wei_in,
    count(distinct transaction_hash)  as txs_in
  from calls
  group by to_address
),

-- What each contract DOES.
outbound as (
  select
    from_address                                          as address,
    countif(call_type in ('DELEGATECALL', 'CALLCODE'))     as delegatecalls,
    -- Value sent out at all: the payout/drain path exists. Whether the
    -- recipient is the caller needs the parent trace, which this CTE does not
    -- join; 06 does that for the re-entry case.
    countif(wei > 0)                                       as value_sends,
    count(*)                                               as calls_out,
    sum(wei)                                               as wei_out
  from calls
  group by from_address
),

-- The reentrancy tell: one caller entering the same contract repeatedly inside a
-- single transaction. A normal integration calls a contract once per tx.
repeat_entry as (
  select
    to_address                                   as address,
    countif(entries >= 3)                        as txs_with_repeats,
    max(entries)                                 as max_entries_in_tx
  from (
    select to_address, transaction_hash, count(*) as entries
    from calls
    where to_address is not null
    group by to_address, transaction_hash
  )
  group by to_address
),

deployed as (
  select
    address,
    block_timestamp as deployed_at,
    creator_address,
    is_erc20,
    is_erc721,
    length(regexp_replace(bytecode, r'^0x', '')) / 2 as bytecode_bytes
  from `bigquery-public-data.crypto_ethereum.contracts`
  where block_timestamp >= window_start
    and bytecode is not null
)

select
  d.address,
  d.deployed_at,
  d.is_erc20,
  d.is_erc721,
  d.bytecode_bytes,
  i.calls_in,
  i.distinct_callers,
  i.txs_in,
  o.calls_out,
  o.delegatecalls,
  o.value_sends,
  r.max_entries_in_tx,
  r.txs_with_repeats,
  round(safe_divide(coalesce(i.wei_in, 0) - coalesce(o.wei_out, 0), cast(1e18 as bignumeric)), 4) as net_eth_through,

  -- The screen. Behaviour only; each term is capped so one huge number cannot
  -- carry a contract on its own, and the weights follow the incident record:
  -- proxy/upgrade first, then a payout path, then reachability.
  round(
      least(coalesce(o.delegatecalls, 0), 20) * 0.20
    + least(coalesce(r.max_entries_in_tx, 0), 10) * 0.20
    + least(coalesce(o.value_sends, 0), 20) * 0.05
    + least(safe_cast(safe_divide(coalesce(i.wei_in, 0), cast(1e18 as bignumeric)) as float64), 100) * 0.03
    + least(coalesce(i.distinct_callers, 0), 500) * 0.005
    + least(coalesce(d.bytecode_bytes, 0) / 24576.0, 1) * 0.15
  , 3)                                                                    as screen_score,

  -- One line saying what to look at, in the order the score weights it.
  concat(
    if(coalesce(o.delegatecalls, 0) > 0, 'delegatecall surface (SWC-112); ', ''),
    if(coalesce(r.max_entries_in_tx, 0) >= 3, concat('repeated re-entry (max ', cast(r.max_entries_in_tx as string), ' per tx); '), ''),
    if(coalesce(o.value_sends, 0) > 0, 'sends value out (payout path); ', ''),
    if(coalesce(i.wei_in, 0) > 0, concat(cast(round(safe_divide(coalesce(i.wei_in, 0), cast(1e18 as bignumeric)), 3) as string), ' ETH in; '), ''),
    if(coalesce(i.distinct_callers, 0) >= 100, 'public entry points; ', '')
  )                                                                       as why
from deployed d
join inbound i         on i.address = d.address
left join outbound o   on o.address = d.address
left join repeat_entry r on r.address = d.address
where
  -- Must have SOMETHING at stake or a genuine proxy surface. Everything else is
  -- a contract that does nothing, which is most of them.
  coalesce(i.wei_in, 0) > 0
  or coalesce(o.delegatecalls, 0) > 0
order by screen_score desc, net_eth_through desc
limit 1000;
