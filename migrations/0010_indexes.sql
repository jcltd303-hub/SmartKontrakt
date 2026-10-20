-- Migration 0010: supporting indexes for the hot read paths.
--
-- The "recent critical/high findings" feed (getRecentHighSeverityFindings)
-- filters findings by severity and a non-empty exploit PoC. Without a partial
-- index that is a sequential scan of the whole findings table on a large
-- archive. The partial predicate matches the query exactly, so the index stays
-- small (most findings carry no exploit).
create index if not exists findings_severity_poc_idx
  on findings (severity)
  where length(trim(exploit_solidity)) > 0;

-- The pipeline worker's resume check and the Records view look contracts up by
-- (chain, address). The existing contract_scans_target_idx covers a bare
-- target_address lookup; this functional composite also serves the
-- `lower(target_address)` form the worker uses.
create index if not exists contract_scans_chain_address_idx
  on contract_scans (chain_id, lower(target_address));
