-- Migration 0020: remember which selectors/topics 4byte.directory does NOT know.
--
-- Measured 2026-10-27 on a live run: 54 scans in 18 minutes, 20 s per address,
-- 242 resolved signatures (~4.5 per contract). The cost was not the hits.
--
-- A bytecode-only contract has no ABI, so EVERY selector is unknown and goes
-- upstream: N selectors / 8 lanes x up to the 5 s per-request timeout. At ~30
-- selectors that is ~20 s per contract — which is exactly the observed rate.
--
-- Worse, only FOUND signatures were cached. A miss is the common case (4byte is
-- slow or silent for most selectors on old contracts), so the same misses were
-- re-fetched for every contract in the run, forever, and the cache could never
-- help with them.
--
-- A miss is now recorded, so the second attempt for a selector costs one indexed
-- row read instead of a network timeout. checked_at carries a TTL: 4byte.directory
-- does gain signatures over time, so a miss is re-checked after a week rather than
-- being permanent.

create table if not exists fourbyte_misses (
  kind       text        not null check (kind in ('signatures', 'event-signatures')),
  key        text        not null,
  checked_at timestamptz not null default now(),
  primary key (kind, key)
);

create index if not exists fourbyte_misses_checked_idx on fourbyte_misses (checked_at);
