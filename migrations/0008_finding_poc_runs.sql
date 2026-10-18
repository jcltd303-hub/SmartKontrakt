-- Migration 0008: Finding PoC Audits and durable results.
-- Stores automated Foundry fork PoC verification results for individual findings.

alter table findings add column if not exists poc_status text;
alter table findings add column if not exists poc_output text;
alter table findings add column if not exists poc_duration_ms integer;
alter table findings add column if not exists poc_run_at timestamptz;
alter table findings add column if not exists poc_code text;

create table if not exists finding_poc_runs (
  id text primary key,
  finding_id text not null references findings (id) on delete cascade,
  scan_id text not null references contract_scans (id) on delete cascade,
  status text not null,
  source text not null,
  output text not null,
  duration_ms integer not null default 0,
  chain_id text,
  target_address text,
  exit_code integer,
  truncated boolean default false,
  created_at timestamptz not null default now()
);

create index if not exists finding_poc_runs_finding_idx on finding_poc_runs (finding_id);
create index if not exists finding_poc_runs_scan_idx on finding_poc_runs (scan_id);
create index if not exists finding_poc_runs_created_idx on finding_poc_runs (created_at desc);
