-- Migration 0012: value-at-risk columns.
--
-- `value_usd` is the target's total USD value at analysis time (native coin plus
-- ERC-20 holdings), so the Records list can sort and filter by what is actually
-- at stake instead of by native balance alone. `value_json` keeps the full
-- valuation (per-holding amounts, prices, sources, completeness) for the UI.
-- `abi_json` + `abi_source` persist the target's ABI — gathered once, reused by
-- any later PoC run so a template can be tailored to the real contract surface.
--
-- `value_usd` is `numeric`, not float, so sorting is exact. NULL means "not
-- valued" and is distinct from 0 (a confirmed valueless target).
alter table contract_scans add column if not exists value_usd numeric;
alter table contract_scans add column if not exists value_json text;
alter table contract_scans add column if not exists abi_json text;
alter table contract_scans add column if not exists abi_source text;

create index if not exists contract_scans_value_usd_idx
  on contract_scans (value_usd desc nulls last);
