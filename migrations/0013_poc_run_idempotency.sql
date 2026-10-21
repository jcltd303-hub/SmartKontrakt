-- Migration 0013: idempotent PoC runs.
--
-- `finding_poc_runs` used to get a fresh random UUID on every save, so re-running
-- the same proof (same finding, same executed source) appended a duplicate row
-- every time — the table grew with repeats and there was no way to ask "have we
-- already executed exactly this proof?".
--
-- `source_digest` is the sha3-256 of the executed source. The partial unique
-- index makes (finding_id, source_digest) the identity of a run, so a re-save
-- updates the existing row instead of appending. Rows written before this
-- migration have a NULL digest and are left alone by the partial index.
alter table finding_poc_runs add column if not exists source_digest text;

create unique index if not exists finding_poc_runs_identity_idx
  on finding_poc_runs (finding_id, source_digest)
  where source_digest is not null;
