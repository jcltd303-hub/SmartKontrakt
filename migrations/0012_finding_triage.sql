-- Migration 0012: the triage fields on findings.
--
-- The 2026-10-27 detection work put four things on every Finding that the
-- `findings` table never stored: the mechanism family, the reachability class
-- (and the gate that produced it), the precondition text, why the confidence is
-- what it is, and whether the summary carries a money figure that is only an
-- assumption. Without these columns the whole reachability/triage layer lives
-- only in the in-memory report, so a saved scan cannot be ranked, filtered or
-- exported — which is exactly what a BigQuery priority query needs.
--
-- `preconditions` is a jsonb array of short strings (the D1 gate text). A
-- separate table would be more relational; an array is the right shape for a
-- bounded, always-read-together list, and BigQuery reads it as a JSON column.

alter table findings add column if not exists family text;
alter table findings add column if not exists reachability text;
alter table findings add column if not exists gate text;
alter table findings add column if not exists preconditions jsonb;
alter table findings add column if not exists confidence_basis text;
alter table findings add column if not exists economic_figure text;
alter table findings add column if not exists economic_basis text;

-- The queue's access path: reachable findings in a scan, strongest first.
create index if not exists findings_reachability_idx
  on findings (scan_id, reachability, confidence);

-- Cross-scan ranking (which contracts are worth looking at) reads by family.
create index if not exists findings_family_idx
  on findings (family, severity);
