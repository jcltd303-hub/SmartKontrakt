-- 01_load.sql — BigQuery DDL + load.
--
--   bq mk --dataset "$PROJECT:smartkontrakt"
--   bq query --use_legacy_sql=false < sql/01_load.sql
--   bq load --source_format=NEWLINE_DELIMITED_JSON \
--     "$PROJECT:smartkontrakt.findings" findings_export.jsonl
--
-- `balance_wei` stays a STRING: a balance in wei exceeds 2^53 and FLOAT64 would
-- silently round it. The scoring casts to BIGNUMERIC where it needs arithmetic.

create table if not exists `smartkontrakt.findings`
(
  scan_id           string,
  finding_id        string,
  chain_id          string,
  address           string,
  contract_name     string,
  label             string,
  label_check       string,
  verified_name     string,
  analyzer_version  string,
  scanned_at        timestamp,
  risk_score        int64,
  balance_wei       string,
  value_usd         numeric,
  input_kind        string,
  ai_status         string,

  detector          string,
  family            string,
  severity          string,
  confidence        string,
  confidence_basis  string,
  reachability      string,
  gate              string,
  preconditions     json,
  economic_figure   string,
  economic_basis    string,
  swc               string,
  location_fn       string,
  location_line     int64,
  title             string,
  poc_status        string,
  corroborated      bool
)
partition by date(scanned_at)
cluster by address, family, reachability;
