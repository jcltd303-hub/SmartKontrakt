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

-- Both sides of the pair: the implementation's size, and — the column the first
-- version of this query was missing — the PROXY's own deployment date.
--
-- Without it the query returns brand-new proxies: a transparent proxy's constructor
-- calls _upgradeToAndCall, which emits Upgraded in the same block the proxy is
-- created, so implementation age 0 means "fresh deployment", not "upgrade". Measured
-- on a live run 2026-10-28: every row came back with impl_age_hours = 0 and
-- proxy_eth ~ 0, i.e. the fresh-deployment window this whole exercise avoids.
codes as (
  select
    address,
    div(length(regexp_replace(bytecode, r'^0[xX]', '')), 2) as runtime_bytes,
    block_timestamp                                          as deployed_at
  from `bigquery-public-data.crypto_ethereum.contracts`
  where address in (select impl from latest)
     or address in (select proxy from latest)
),

-- VALUE. Native ETH is the wrong measure for DeFi: measured on the first live run
-- 2026-10-28, 166 established-and-upgraded proxies held 2.05 ETH BETWEEN THEM, and 154
-- of them held none. A lending pool holds USDC and WETH tokens, not raw ETH, so
-- `crypto_ethereum.balances` could never see it.
--
-- There is no public "current token balance" table, so this uses 30-day token FLOW as
-- the value proxy: how much recognised value moved through the contract. It
-- under-counts idle holdings and over-counts high-turnover routers, and it is an
-- estimate — but it is the right order of magnitude, which native ETH is not.
--
-- Prices are the approximate 2026 majors; they only need to rank, not to account.
flows as (
  select
    to_address as address,
    sum(
      safe_cast(value as bignumeric) / pow(10, decimals) *
      case lower(token_address)
        when '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48' then 1.0      -- USDC
        when '0xdac17f958d2ee523a2206206994597c13d831ec7' then 1.0      -- USDT
        when '0x6b175474e89094c44da98b954eedeac495271d0f' then 1.0      -- DAI
        when '0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2' then 2330.0   -- WETH
        when '0x2260fac5e5542a773aa44fbcfedf7c193bc2c599' then 60000.0  -- WBTC
        when '0xae7ab96520de3a18e5e111b5eaab095312d7fe84' then 2330.0   -- stETH
        when '0x7f39c581f595b53c5cb19bd0b3f8da6c935e2ca0' then 2600.0   -- wstETH
        else 0.0
      end
    ) as usd_flow
  from `bigquery-public-data.crypto_ethereum.token_transfers`
  where block_timestamp >= timestamp_sub(current_timestamp(), interval 30 day)
    and lower(token_address) in (
      '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48',
      '0xdac17f958d2ee523a2206206994597c13d831ec7',
      '0x6b175474e89094c44da98b954eedeac495271d0f',
      '0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2',
      '0x2260fac5e5542a773aa44fbcfedf7c193bc2c599',
      '0xae7ab96520de3a18e5e111b5eaab095312d7fe84',
      '0x7f39c581f595b53c5cb19bd0b3f8da6c935e2ca0'
    )
  group by to_address
),

balances as (
  select address, safe_cast(eth_balance as bignumeric) as wei
  from `bigquery-public-data.crypto_ethereum.balances`
  where block_timestamp >= timestamp_sub(current_timestamp(), interval 2 day)
  qualify row_number() over (partition by address order by block_timestamp desc) = 1
),

-- How many proxies share this implementation. Measured: 71 of 166 rows were TWO
-- implementations, so one audit target can carry 38 deployments' worth of exposure.
impl_share as (
  select impl, count(*) as proxies_sharing
  from latest
  group by impl
)

select
  l.proxy,
  l.impl,
  l.upgraded_at,
  l.upgrades_in_window,
  round(coalesce(b.wei, 0) / 1e18, 4)                     as proxy_eth,
  round(coalesce(f.usd_flow, 0), 0)                       as usd_flow_30d,
  s.proxies_sharing,
  i.runtime_bytes                                          as impl_bytes,
  i.deployed_at                                            as impl_deployed,
  timestamp_diff(l.upgraded_at, i.deployed_at, hour)       as impl_age_hours_at_upgrade,
  -- THE discriminator: how old the proxy itself was when it was upgraded. A number in
  -- the hundreds is an established contract gaining new code; a zero is a new deploy.
  timestamp_diff(l.upgraded_at, p.deployed_at, day)        as proxy_age_days_at_upgrade,
  -- Score what the research says predicts loss: money at risk, real logic in the new
  -- implementation, and fresh code. Money alone does not create a row — a funded
  -- proxy that upgraded to a 200-byte forwarder is another shell.
  round(
      least(coalesce(b.wei, 0) / 1e21, 1)                       * 0.35   -- >= 1000 ETH
    + least(timestamp_diff(l.upgraded_at, p.deployed_at, day) / 365.0, 1) * 0.25 -- established
    + least(coalesce(i.runtime_bytes, 0) / 12000.0, 1)          * 0.20   -- real logic
    + least(l.upgrades_in_window / 5.0, 1)                      * 0.20   -- active dev
  , 3)                                                          as upgrade_score,
  concat(
    if(coalesce(f.usd_flow, 0) > 1e5, 'value flowing ', ''),
    if(s.proxies_sharing > 1, concat('shared impl x', cast(s.proxies_sharing as string), ' '), ''),
    if(timestamp_diff(l.upgraded_at, p.deployed_at, day) >= 180, 'established ', ''),
    if(coalesce(i.runtime_bytes, 0) > 1000, 'real logic ', ''),
    if(l.upgrades_in_window > 1, 'active dev', '')
  )                                                             as why
from latest l
left join codes    i on i.address = l.impl
left join codes    p on p.address = l.proxy
left join flows      f on f.address = l.proxy
left join impl_share s on s.impl = l.impl
left join balances   b on b.address = l.proxy
where coalesce(i.runtime_bytes, 0) > 1000        -- the new code must be more than a forwarder
  -- An established proxy gaining new code. 90 days is the floor from the maturity
  -- tiers (the documented loss record concentrates in 0-6 months); 180 scores higher.
  and timestamp_diff(l.upgraded_at, p.deployed_at, day) >= 90
order by upgrade_score desc, coalesce(b.wei, 0) desc
limit 500;


-- ===========================================================================
-- THE PASTE-READY LIST — self-contained, run this whole block in BigQuery.
--
-- Not the Supabase editor: this reads bigquery-public-data.crypto_ethereum, and
-- Postgres answers `relation "latest" does not exist` because the CTEs below do not
-- exist there. One statement, all CTEs included, so it can be pasted on its own.
--
-- Implementations, not proxies: the proxy is a forwarder, the implementation is where
-- the source and the logic are, and the pipeline follows proxy -> implementation by
-- itself when handed a proxy. Measured 2026-10-28: 166 proxies -> 88 implementations,
-- ~30 minutes at 20s/address.
--
-- Returns ONE cell: addresses newline-separated, best first. Paste into POST /start.
-- ===========================================================================
with upgrades as (
  select
    address                                     as proxy,
    lower(concat('0x', right(coalesce(
      nullif(topics[SAFE_OFFSET(1)], ''),
      data
    ), 40)))                                   as impl,
    block_timestamp
  from `bigquery-public-data.crypto_ethereum.logs`
  where block_timestamp >= timestamp_sub(current_timestamp(), interval 7 day)
    and topics[SAFE_OFFSET(0)] = '0xbc7cd75a20ee27fd9adebab32041f755214dbc6bffa90cc0225b39da2e5c2d3b'
),

latest as (
  select proxy, impl, block_timestamp as upgraded_at
  from upgrades
  where impl is not null
    and impl != '0x0000000000000000000000000000000000000000'
  qualify row_number() over (partition by proxy order by block_timestamp desc) = 1
),

codes as (
  select
    address,
    div(length(regexp_replace(bytecode, r'^0[xX]', '')), 2) as runtime_bytes,
    block_timestamp                                          as deployed_at
  from `bigquery-public-data.crypto_ethereum.contracts`
  where address in (select impl from latest)
     or address in (select proxy from latest)
),

flows as (
  select
    to_address as address,
    sum(
      safe_cast(value as bignumeric) / pow(10, decimals) *
      case lower(token_address)
        when '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48' then 1.0
        when '0xdac17f958d2ee523a2206206994597c13d831ec7' then 1.0
        when '0x6b175474e89094c44da98b954eedeac495271d0f' then 1.0
        when '0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2' then 2330.0
        when '0x2260fac5e5542a773aa44fbcfedf7c193bc2c599' then 60000.0
        when '0xae7ab96520de3a18e5e111b5eaab095312d7fe84' then 2330.0
        when '0x7f39c581f595b53c5cb19bd0b3f8da6c935e2ca0' then 2600.0
        else 0.0
      end
    ) as usd_flow
  from `bigquery-public-data.crypto_ethereum.token_transfers`
  where block_timestamp >= timestamp_sub(current_timestamp(), interval 30 day)
    and lower(token_address) in (
      '0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48',
      '0xdac17f958d2ee523a2206206994597c13d831ec7',
      '0x6b175474e89094c44da98b954eedeac495271d0f',
      '0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2',
      '0x2260fac5e5542a773aa44fbcfedf7c193bc2c599',
      '0xae7ab96520de3a18e5e111b5eaab095312d7fe84',
      '0x7f39c581f595b53c5cb19bd0b3f8da6c935e2ca0'
    )
  group by to_address
)

select string_agg(impl, '\n' order by score desc, usd_flow_30d desc) as addresses
from (
  select
    l.impl,
    max(
      least(coalesce(f.usd_flow, 0) / 1e7, 1)                              * 0.30
    + least(timestamp_diff(l.upgraded_at, p.deployed_at, day) / 365.0, 1)  * 0.25
    + least(coalesce(i.runtime_bytes, 0) / 12000.0, 1)                     * 0.20
    + least(least(count(*), 5) / 5.0, 1)                                   * 0.20
    )                                        as score,
    sum(coalesce(f.usd_flow, 0))             as usd_flow_30d,
    count(*)                                 as proxies
  from latest l
  left join codes i on i.address = l.impl
  left join codes p on p.address = l.proxy
  left join flows f on f.address = l.proxy
  where coalesce(i.runtime_bytes, 0) > 1000
    and timestamp_diff(l.upgraded_at, p.deployed_at, day) >= 90
  group by l.impl, i.runtime_bytes
);
