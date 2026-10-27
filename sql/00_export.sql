-- 00_export.sql — runs on the APP'S POSTGRES (not BigQuery).
--
-- Flattens findings + contract_scans into the shape 01_load.sql expects. Write
-- the result out as newline-delimited JSON and load that; do not try to load a
-- CSV, because `preconditions` and the snippets contain newlines.
--
--   psql "$DATABASE_URL" -At -f sql/00_export.sql > findings_export.jsonl
--
-- One row per finding. The contract-level facts (address, chain, balance) are
-- denormalised onto every row so BigQuery can aggregate without a second table.

select json_build_object(
  'scan_id',           s.id,
  'finding_id',        f.id,
  'chain_id',          s.chain_id,
  'address',           lower(s.target_address),
  'contract_name',     s.contract_name,
  'label',             s.label,
  'label_check',       (s.inventory_json::jsonb ->> 'labelCheck'),
  'verified_name',     (s.inventory_json::jsonb ->> 'verifiedName'),
  'analyzer_version',  s.analyzer_version,
  'scanned_at',        s.created_at,
  'risk_score',        s.risk_score,
  'balance_wei',       s.balance_wei,          -- string: wei overflows float64
  'value_usd',         s.value_usd,
  'input_kind',        s.input_kind,
  'ai_status',         s.ai_status,

  'detector',          f.detector,
  'family',            f.family,
  'severity',          f.severity,
  'confidence',        f.confidence,
  'confidence_basis',  f.confidence_basis,
  'reachability',      f.reachability,
  'gate',              f.gate,
  'preconditions',     coalesce(f.preconditions, '[]'::jsonb),
  'economic_figure',   f.economic_figure,
  'economic_basis',    f.economic_basis,
  'swc',               f.swc,
  'location_fn',       f.location_fn,
  'location_line',     f.location_line,
  'title',             f.title,
  'poc_status',        f.poc_status,
  'corroborated',      f.corroborated
)
from findings f
join contract_scans s on s.id = f.scan_id
where s.analyzer_version is not null
  -- Only the current analyzer: an older stamp scored with different rules and
  -- different reachability, and mixing them makes the ranking incoherent.
  and s.analyzer_version = (select analyzer_version
                            from contract_scans
                            where analyzer_version is not null
                            order by created_at desc
                            limit 1)
order by s.created_at desc;
