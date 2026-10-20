-- Migration 0011: native-coin balance of the target at analysis time.
--
-- Read over public JSON-RPC (`eth_getBalance`) when an address is analyzed, so a
-- record shows how much native value sits behind the contract, and so the
-- pre-run PoC guard can skip a target with nothing at stake.
--
-- Stored as a decimal wei string in `text`: balances exceed 2^53, so a JSON
-- number would lose precision. NULL means "not read" (no RPC answered), which is
-- deliberately distinct from '0' (a confirmed empty balance).
alter table contract_scans add column if not exists balance_wei text;
