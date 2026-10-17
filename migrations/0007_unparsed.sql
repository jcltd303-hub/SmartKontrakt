-- Migration 0007: explicit unparsed state on contract_scans.
-- A record whose input did not parse analyzed NOTHING (e.g. a bare enum
-- pasted as source) and must render "Unparsed", never "Clean".
-- The engine computes unparsed at analysis time; both save paths write it.
-- The backfill below labels pre-existing unparsed records:
-- (a) parse-INFO-only: source input, only info findings, every finding
--     has the parse detector;
-- (b) Fragment-enum: zero findings, inventory names are all "Fragment"
--     and the inventory has no functions (a bare enum/struct paste the
--     parser wrapped in a synthetic Fragment contract).
-- The LIKE guards are fail-safe: JSON.stringify emits the keys with no
-- spaces, so they can only under-match, never error the migration.
alter table contract_scans add column if not exists unparsed boolean not null default false;

update contract_scans set unparsed = true
where input_kind = 'source' and unparsed = false
  and critical_count = 0 and high_count = 0 and medium_count = 0 and low_count = 0 and info_count > 0
  and not exists (select 1 from findings f where f.scan_id = contract_scans.id and f.detector <> 'parse');

update contract_scans set unparsed = true
where input_kind = 'source' and unparsed = false
  and critical_count = 0 and high_count = 0 and medium_count = 0 and low_count = 0 and info_count = 0
  and inventory_json like '%"contractNames":["Fragment"]%'
  and inventory_json like '%"functions":[]%';
