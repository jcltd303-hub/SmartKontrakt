-- 06_reentrancy_cycles.sql — find re-entry into a contract from inside its own
-- call tree, chain-wide, from public traces only.
--
-- This is the highest-signal query in the directory, because it detects the
-- SHAPE of the attack rather than a precondition for it. A reentrancy is a cycle
-- in the call tree: A calls B, and B calls back into A before A's frame returns.
-- BigQuery records the call tree positionally in `trace_address` — the path of
-- child indices from the transaction root — so a cycle is an equality join
-- between a trace and its parent:
--
--     parent:  from = A, to = B, path = "0.3"
--     child:   from = B, to = A, path = "0.3.1"     <-- parent.path + one index
--
-- and `parent.from = child.to` and `parent.to = child.from` closes the cycle.
--
-- WHAT THIS ALSO FINDS (and why the discriminators below matter)
--
-- A→B→A is also the shape of a flash loan (pool → borrower → pool to repay) and
-- of any legitimate callback (router → token → router). Those are not bugs. The
-- discriminators that survive that noise:
--
--   * repeats        — three or more entries into the same contract inside one
--                      transaction. A flash loan enters twice, by construction.
--   * selector pair  — the outer and inner function selectors. A callback
--                      usually re-enters the SAME entry point it came from
--                      (`withdraw` inside `withdraw`), which is the reentrancy
--                      tell; a flash loan re-enters a different one (borrow →
--                      repay).
--   * value on the inner call — the re-entrant frame moving value is the drain.
--
-- So this returns candidates with those three columns exposed, ranked by value,
-- and it does NOT pretend to decide. Every row needs a read of the contract.

declare window_start timestamp default timestamp_sub(current_timestamp(), interval 90 day);

with t as (
  select
    transaction_hash,
    block_timestamp,
    trace_address,
    array_length(trace_address)          as depth,
    array_to_string(trace_address, '.')  as path,
    from_address,
    to_address,
    safe_cast(value as bignumeric)       as wei,
    to_hex(substr(input, 1, 4))          as selector,
    call_type
  from `bigquery-public-data.crypto_ethereum.traces`
  where block_timestamp >= window_start
    and status = 1
    and from_address is not null
    and to_address is not null
    and array_length(trace_address) >= 1
),

-- A cycle is a child trace whose parent is the reverse edge.
cycles as (
  select
    child.transaction_hash,
    child.block_timestamp,
    parent.from_address                  as victim,          -- A
    parent.to_address                    as intermediary,    -- B
    parent.selector                      as outer_selector,
    child.selector                       as inner_selector,
    child.wei                            as inner_wei,
    parent.wei                           as outer_wei,
    child.depth,
    child.path
  from t child
  join t parent
    on parent.transaction_hash = child.transaction_hash
   -- parent's path is the child's path minus its last index
   and parent.path = regexp_replace(child.path, r'\.[0-9]+$', '')
   -- the cycle closes: A -> B -> A
   and parent.from_address = child.to_address
   and parent.to_address   = child.from_address
  where child.depth >= 2
)

select
  c.victim,
  count(*)                                                          as reentries,
  count(distinct c.intermediary)                                    as distinct_intermediaries,
  count(distinct c.transaction_hash)                                as transactions,
  max(c.depth)                                                      as deepest_reentry,
  round(safe_divide(max(c.inner_wei), cast(1e18 as bignumeric)), 6)  as max_eth_reentered,
  round(safe_divide(sum(c.inner_wei), cast(1e18 as bignumeric)), 6)  as total_eth_reentered,

  -- The reentrancy tell: the inner call re-enters the SAME function it left.
  countif(c.inner_selector = c.outer_selector)                      as same_selector_reentries,
  -- The strongest single row: same entry point, value on the inner frame.
  countif(c.inner_selector = c.outer_selector and c.inner_wei > 0)   as same_selector_with_value,

  -- Three or more entries into one contract inside one transaction. A flash
  -- loan enters twice; a reentrancy loop enters many times.
  countif(c.depth >= 4)                                             as deep_reentries,

  array_agg(distinct c.outer_selector ignore nulls limit 5)          as outer_selectors,
  array_agg(distinct c.intermediary     limit 3)                     as intermediaries,
  max(c.block_timestamp)                                             as last_seen
from cycles c
group by c.victim
-- Rank by what makes it worth a read: same-selector re-entry with value first,
-- then depth, then money.
order by same_selector_with_value desc, deep_reentries desc, total_eth_reentered desc
limit 500;
