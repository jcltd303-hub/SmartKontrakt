-- Kiln audit archive. Rows are unowned: this app has no accounts.
-- Contract text is the audit subject, not a profile. There is no bulk delete.

create table if not exists contract_scans (
  id text primary key,
  label text not null,
  input_kind text not null,
  contract_name text,
  risk_score integer not null,
  critical_count integer not null default 0,
  high_count integer not null default 0,
  medium_count integer not null default 0,
  low_count integer not null default 0,
  info_count integer not null default 0,
  summary text not null,
  inventory_json text not null,
  ai_narrative text,
  ai_status text not null default 'unavailable',
  created_at timestamptz not null default now()
);

create index if not exists contract_scans_created_idx
  on contract_scans (created_at desc);

create table if not exists scan_payloads (
  scan_id text primary key references contract_scans (id) on delete cascade,
  body text not null
);

create table if not exists findings (
  id text primary key,
  scan_id text not null references contract_scans (id) on delete cascade,
  ord integer not null,
  severity text not null,
  swc text,
  title text not null,
  confidence text not null,
  detector text not null,
  summary text not null,
  walkthrough text not null,
  exploit_solidity text not null default '',
  remediation_solidity text not null default '',
  location_fn text,
  location_line integer,
  snippet text not null default ''
);

create index if not exists findings_scan_idx on findings (scan_id, ord);
