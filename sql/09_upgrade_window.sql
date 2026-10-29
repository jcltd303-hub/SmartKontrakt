-- 09_upgrade_window.sql — new code, old money: proxies whose implementation just changed.
--
-- WHY THIS WINDOW, AND NOT "LAST 30 DAYS OF DEPLOYMENTS"
--
-- The evidence, from three independent datasets:
--
--   * Time-to-hack (Decurity, 2020-2025, real incidents): the >90-day bucket holds the
--     MOST exploits — vulnerabilities sit untouched for months or years, 1inch's
--     Settlement contract included, at 2+ years. The <=7-day bucket is second, but it
--     is unwinnable for us: the fastest 2025 exploit was 52 minutes after deployment.
--     A pipeline that spends ~20s per address on fetch and probe, then mines 250
--     blocks for a PoC, cannot compete with a bot that acts in minutes.
--   * Decurity's proxy analysis: implementations are exploited far faster than fresh
--     deployments, concentrating in the days after an update.
--   * CoinGecko 2026: 147 of 245 exploited protocols had been audited, and most
--     attacks landed on newly introduced code outside the audit's scope. Hacken
--     independently describes "old, battle-tested codebases exploited".
--
-- So the target is not a new contract. It is an OLD proxy holding REAL money whose
-- implementation changed RECENTLY: new code, established liquidity, and none of the
-- fresh-deployment attention that makes bots swarm. That is the one window where a
-- human-paced analysis pipeline still has time to act.
--
-- The signal is the ERC-1967 `Upgraded(address)` event, emitted by the proxy. Its
-- topic0 is 0xbc7cd75a20ee27fd9adebab32041f755214dbc6bffa90cc0225b39da2e5c2d3b —
-- the same constant solc bakes into ERC1967Upgrade, so it identifies transparent,
-- UUPS and beacon-style upgrades alike.
--
-- COST: `logs` is a large table. The block_timestamp filter is mandatory. 30 days is
-- a lot of logs; start at 7 and widen once you have seen the dry-run bytes. The
-- topic filter does not reduce the scan — only the partition filter does.

declare win_start timestamp default timestamp_sub(current_timestamp(), interval 30 day);
declare upgraded_sig string default '0xbc7cd75a20ee27fd9adebab32041f755214dbc6bffa90cc0225b39da2e5c2d3b';

with upgrades as (
  select
    -- The proxy emits the event, because ERC1967Upgrade runs in its storage context.
    address                                     as proxy,
    -- `implementation` is indexed in OZ, so it is topics[1]; some forks emit it
    -- unindexed in `data`. Take whichever is populated, then keep the low 20 bytes.
    lower(concat('0x', right(coalesce(
      nullif(topics[SAFE_OFFSET(1)], ''),
      data
    ), 40)))                                   as impl,
    block_timestamp,
    transaction_hash
  from `bigquery-public-data.crypto_ethereum.logs`
  where block_timestamp >= win_start
    and topics[SAFE_OFFSET(0)] = upgraded_sig
),

-- One row per proxy: the most recent upgrade, plus how much churn there was. Churn
-- is a proxy for "actively developed", which is where new bugs arrive.
latest as (
  select
    proxy, impl, block_timestamp as upgraded_at, transaction_hash,
    count(*) over (partition by proxy) as upgrades_in_window
  from upgrades
  where impl is not null
    and impl != '0x0000000000000000000000000000000000000000'
  qualify row_number() over (partition by proxy order by block_timestamp desc) = 1
),

impl_code as (
  select
    address,
    div(length(regexp_replace(bytecode, r'^0[xX]', '')), 2) as impl_bytes,
    block_timestamp                                          as impl_deployed
  from `bigquery-public-data.crypto_ethereum.contracts`
  where address in (select impl from latest)
),

balances as (
  select address, safe_cast(eth_balance as bignumeric) as wei
  from `bigquery-public-data.crypto_ethereum.balances`
  where block_timestamp >= timestamp_sub(current_timestamp(), interval 2 day)
  qualify row_number() over (partition by address order by block_timestamp desc) = 1
)

select
  l.proxy,
  l.impl,
  l.upgraded_at,
  l.upgrades_in_window,
  round(coalesce(b.wei, 0) / 1e18, 4)                     as proxy_eth,
  i.impl_bytes,
  i.impl_deployed,
  timestamp_diff(l.upgraded_at, i.impl_deployed, hour)    as impl_age_hours_at_upgrade,
  -- Score what the research says predicts loss: money at risk, real logic in the new
  -- implementation, and fresh code. Money alone does not create a row — a funded
  -- proxy that upgraded to a 200-byte forwarder is another shell.
  round(
      least(coalesce(b.wei, 0) / 1e21, 1)                       * 0.45   -- >= 1000 ETH
    + least(coalesce(i.impl_bytes, 0) / 12000.0, 1)             * 0.30   -- real logic
    + least(l.upgrades_in_window / 5.0, 1)                      * 0.15   -- active dev
    + if(timestamp_diff(l.upgraded_at, i.impl_deployed, hour) <= 24, 1, 0) * 0.10
  , 3)                                                          as upgrade_score,
  concat(
    if(coalesce(b.wei, 0) > 0, 'funded ', ''),
    if(coalesce(i.impl_bytes, 0) > 1000, 'real logic ', ''),
    if(l.upgrades_in_window > 1, 'active ', ''),
    if(timestamp_diff(l.upgraded_at, i.impl_deployed, hour) <= 24, 'impl deployed with the upgrade', '')
  )                                                             as why
from latest l
left join impl_code i on i.address = l.impl
left join balances  b on b.address = l.proxy
where coalesce(i.impl_bytes, 0) > 1000          -- the new code must be more than a forwarder
order by upgrade_score desc, coalesce(b.wei, 0) desc
limit 500;
