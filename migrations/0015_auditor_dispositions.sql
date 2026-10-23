-- Migration 0015: auditor dispositions on findings.
--
-- The manual adjudication loop (load a finding, fetch, AI-review, run the
-- PoC, read the log) ends in a human verdict. Until now that verdict lived
-- only in the per-scan `triage_states_json` blob in the workbench, keyed by
-- in-memory finding ids and invisible to the PoC Audits page — so the same
-- false positive was re-adjudicated from scratch on every pass.
--
-- One row per finding (the finding id is the PK, and findings carry the
-- canonical `${scanId}:${ord}` identity), written by UPSERT: setting a
-- disposition twice updates the one row, and re-setting the same value is a
-- no-op. `disposition` is the auditor's word, never a machine verdict — the
-- adjudication chain may SUGGEST one from a PoC outcome, but only a human
-- tap writes here.
create table if not exists auditor_dispositions (
  finding_id text primary key references findings (id) on delete cascade,
  disposition text not null check (disposition in ('confirmed', 'false_positive', 'needs_more_info')),
  note text,
  updated_at timestamptz not null default now()
);
