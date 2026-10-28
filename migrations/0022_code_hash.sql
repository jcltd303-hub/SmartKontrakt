-- Migration 0022: the runtime code hash, so identical bytecode is analysed once.
--
-- Measured 2026-10-28 on a 24-contract sample and again on a 40-title PoC census:
-- 543 findings across 393 contract-instances, where `execTransaction sends ether with
-- no access check` alone appeared on 27 contracts (27 Gnosis Safe proxies, one
-- implementation) and `fallback ignores the delegatecall result` on 59. Those are
-- deployments, not distinct code. Every duplicate pays the full fetch cost again —
-- Sourcify, the RPC probe, 4byte lookups, ResNet — for a contract whose analysis is
-- already in the archive.
--
-- code_hash is sha3-256 of the runtime bytecode (the same bytes eth_getCode returns),
-- lowercased and 0x-prefixed, or NULL when the scan never had bytecode. Indexed with
-- chain_id because the same code on a different chain is a different analysis (the
-- probes and balances differ even when the code does not).
--
-- Nullable on purpose: existing rows have no hash, and a scan whose bytecode fetch
-- failed must not pretend to be dedupeable.

alter table contract_scans
  add column if not exists code_hash text;

comment on column contract_scans.code_hash is
  'sha3-256 of runtime bytecode (0x-prefixed, lowercase), NULL when unavailable. Identical code on the same chain needs one analysis, not one per deployment.';

create index if not exists contract_scans_chain_code_hash_idx
  on contract_scans (chain_id, code_hash)
  where code_hash is not null;
