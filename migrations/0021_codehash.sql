-- Migration 0021: runtime codehash on contract_scans.
--
-- The codehash verdict cache: clone contracts (one body accounting for
-- 341 of 1595 scans in the 2026-10-28 measurement) share one runtime
-- codehash. Persisting the keccak256 of the deployed runtime code on
-- every save lets a new scan find its siblings — earlier scans of
-- identical code — so their bodies can be reused (the pipeline worker's
-- code-reuse lookup) and their auditor dispositions inherited instead
-- of re-derived by hand for every clone. Null when the analysis had no
-- runtime bytecode (pasted source), and on every row saved before this
-- migration; the sibling lookup falls back to hashing stored bytecode
-- bodies for those legacy rows.

alter table contract_scans add column if not exists codehash text;

create index if not exists contract_scans_codehash_idx
  on contract_scans (chain_id, codehash)
  where codehash is not null;
