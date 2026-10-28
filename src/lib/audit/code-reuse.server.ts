// src/lib/audit/code-reuse.server.ts
//
// Identical runtime code is analysed once (2026-10-28).
//
// Measured twice in one day: a 24-contract sample where five proxy rows carried 145 of
// 171 criticals, and a 40-title PoC census where 543 findings spanned 393
// contract-instances — `execTransaction` on 27 contracts (27 Gnosis Safe proxies, one
// implementation), `fallback ignores the delegatecall result` on 59. Those are
// deployments, not distinct code, and each duplicate pays the whole fetch again:
// Sourcify, the RPC probe, the 4byte lookups, ResNet.
//
// The hash is sha3-256 of the runtime bytecode exactly as eth_getCode returns it,
// lowercased. Two deployments of the same implementation share it; a proxy and its
// implementation do not, which is correct — they are different code and the proxy
// shell analysis is what Gate 4 now discounts rather than what we skip.

import { sha3_256 } from "js-sha3";

import type { Sql } from "../sql-client.ts";

/** sha3-256 of runtime bytecode, 0x-prefixed and lowercased. Null for no code. */
export function codeHashOf(runtimeBytecode: string | null | undefined): string | null {
  if (!runtimeBytecode) return null;
  const hex = runtimeBytecode.trim().toLowerCase().replace(/^0x/, "");
  // An EOA, or a failed read: nothing to hash and nothing to reuse.
  if (hex.length === 0 || /^0+$/.test(hex)) return null;
  return "0x" + sha3_256(Buffer.from(hex, "hex"));
}

export type SiblingScan = {
  scanId: string;
  address: string | null;
  contractName: string | null;
  /** The analysed body, so the same code can be re-analysed without a fetch. */
  body: string | null;
};

/**
 * Find an earlier scan of the same runtime code on the same chain.
 *
 * Returns the sibling's stored body so a caller can re-analyse it locally instead of
 * paying for the network fetch. The findings themselves are not copied: analysis is
 * local CPU, and a copied report would carry the sibling's address, label, probes and
 * balances into a different deployment — a subtle way to be wrong.
 */
export async function findSiblingScan(
  sql: Sql,
  chainId: string,
  codeHash: string,
  excludeAddress: string,
): Promise<SiblingScan | null> {
  const rows = await sql<{
    id: string;
    target_address: string | null;
    contract_name: string | null;
    body: string | null;
  }>`
    select s.id, s.target_address, s.contract_name, p.body
    from contract_scans s
    left join scan_payloads p on p.scan_id = s.id
    where s.chain_id = ${chainId}
      and s.code_hash = ${codeHash}
      and s.target_address is distinct from ${excludeAddress}
    order by s.created_at asc
    limit 1`;
  const row = rows[0];
  if (!row) return null;
  return {
    scanId: row.id,
    address: row.target_address,
    contractName: row.contract_name,
    body: row.body,
  };
}

/** How many scans share each distinct code hash — the dedupe ratio, per chain. */
export async function codeDuplication(
  sql: Sql,
): Promise<{ scans: number; hashed: number; distinctCode: number; copiesPerCode: number }> {
  const rows = await sql<{ scans: string; hashed: string; distinct_code: string }>`
    select count(*)::text as scans,
           count(*) filter (where code_hash is not null)::text as hashed,
           count(distinct (chain_id, code_hash))::text as distinct_code
    from contract_scans`;
  const r = rows[0];
  const scans = Number(r?.scans ?? 0);
  const hashed = Number(r?.hashed ?? 0);
  const distinctCode = Number(r?.distinct_code ?? 0);
  return {
    scans,
    hashed,
    distinctCode,
    copiesPerCode: distinctCode > 0 ? Number((hashed / distinctCode).toFixed(2)) : 0,
  };
}
