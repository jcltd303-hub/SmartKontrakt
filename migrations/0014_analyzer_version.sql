-- Migration 0014: which analyzer produced a saved record.
--
-- The pipeline's resume treats a saved (chain, address) as done. That is only
-- correct while the analyzer is unchanged: after the scoring redo, the balance
-- guard, the value-at-risk pass, ABI gathering, SmartPoC and the SmartBugs
-- alignment, every earlier row describes OLDER behaviour, and skipping it keeps
-- the staleness. This column is the stamp the analyzer writes on every record
-- (baseline + a fingerprint of the detector set and scoring model), so resume
-- can skip what is current and re-analyze what is not.
--
-- Existing rows are NULL and therefore stale by definition — which is exactly
-- what makes the first run after this migration refresh the whole archive
-- instead of skipping it. No backfill is needed or wanted: the archive IS the
-- thing being refreshed.
alter table contract_scans add column if not exists analyzer_version text;

-- The freshness question is "how many of my rows are not current?", asked over
-- the whole table for the freshen report, so index the stamp itself.
create index if not exists contract_scans_analyzer_version_idx
  on contract_scans (analyzer_version);
