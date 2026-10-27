-- Migration 0021: distinguish "4byte does not know this" from "we could not ask".
--
-- Migration 0020 recorded a miss whenever an upstream lookup produced nothing,
-- with a single 7-day TTL. That conflates two very different facts:
--
--   unknown      the API answered 200 with an empty result set. The signature
--                genuinely is not in the database. Caching it for a week is right.
--   unreachable  a timeout, a 429, a 5xx, a dropped connection. We learned nothing
--                about the selector at all. Caching that for a week is a lie that
--                survives a transient outage and poisons the cache for a run that
--                would otherwise have resolved it.
--
-- Measured: the first 20 minutes of a restarted run recorded 144 misses against
-- 251 hits. Nothing in the schema could say which of those were real.

alter table fourbyte_misses
  add column if not exists reason text not null default 'unknown';

do $$
begin
  if not exists (
    select 1 from pg_constraint where conname = 'fourbyte_misses_reason_check'
  ) then
    alter table fourbyte_misses
      add constraint fourbyte_misses_reason_check
      check (reason in ('unknown', 'unreachable'));
  end if;
end $$;
