-- Migration 0017: FP signature layer (G7) — candidate false-positive
-- patterns derived from auditor dispositions, decided by a human.
--
-- auditor_dispositions (0015) is the source of truth: a pattern exists
-- here only because findings carrying its shape were disposed
-- 'false_positive' by a human, on at least two distinct scans (a single
-- FP is an anecdote, not a pattern). Derivation (fp-signatures.ts) is
-- re-run on read; this table stores the HUMAN'S DECISION about a
-- derived pattern — candidate (derived, undecided), confirmed, or
-- dismissed — plus the evidence snapshot the decision was made against.
--
-- The layer is annotation-only, by construction: nothing in the schema
-- lets a row here reach severity, pocAuditEligibility, or a
-- disposition. A CONFIRMED signature only earns a finding a visible
-- "matches confirmed FP pattern" note at read time. Dismissed rows are
-- kept forever: a dismissed signature key is never re-proposed as a
-- candidate, however much matching FP evidence accrues later.
create table if not exists fp_signatures (
  signature_key text primary key,
  detector text not null,
  title_pattern text not null,
  location_fn text,
  snippet_class text,
  status text not null default 'candidate'
    check (status in ('candidate', 'confirmed', 'dismissed')),
  evidence_count integer not null default 0,
  scan_count integer not null default 0,
  sample_finding_ids text not null default '[]',
  sample_titles text not null default '[]',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  decided_at timestamptz
);

create index if not exists fp_signatures_status_idx
  on fp_signatures (status);
