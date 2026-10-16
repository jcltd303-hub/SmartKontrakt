-- Migration 0004: Foundry fork-PoC run results on contract_scans.
-- The workbench auto-runs a generated PoC against the Termux local backend
-- (forge --fork-url) and persists the outcome here, so a scan record shows
-- whether the exploit reproduced on fork state.

alter table contract_scans add column if not exists poc_status text;
alter table contract_scans add column if not exists poc_logs text;
alter table contract_scans add column if not exists poc_duration_ms integer;
alter table contract_scans add column if not exists poc_run_at timestamptz;
