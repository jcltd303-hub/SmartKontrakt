// src/lib/audit/code-reuse.server.ts
//
// The codehash verdict cache. Clone contracts share one runtime
// codehash — the 2026-10-28 archive measurement counted 1,595 scans
// over 375 distinct bodies, one body accounting for 341 scans. Two
// mechanisms hang off the hash:
//
// - findSiblingScan: the pipeline worker fetches an item's live runtime
//   code (one eth_getCode), hashes it, and asks for an earlier scan of
//   identical code; the sibling's stored body then replaces the
//   registry fetch + source analysis for this deployment (probes,
//   value and ABI still run — those describe THIS deployment).
// - inheritSiblingDispositions: when a scan is saved, findings that
//   match a sibling's findings (same detector + function) inherit the
//   sibling's auditor disposition, so a verdict reached once — by hand
//   or by fork proof — covers every clone instead of being re-derived
//   per address. The inherited note names the source scan, so the
//   provenance is auditable and a wrong inheritance is one click to
//   override (a human disposition set later simply replaces the row).
//
// Sibling matching, in order:
// 1. contract_scans.codehash (migration 0021) — written on every save
//    whose analysis saw runtime bytecode.
// 2. Legacy fallback for pre-0021 rows: a stored body that IS bytecode
//    (hex) hashes to the same value. Source bodies cannot be matched
//    this way — source text does not determine runtime code — so a
//    legacy source-analyzed sibling joins the cache only when it is
//    next re-saved. Bounded to the newest 200 hex bodies per chain so
//    the fallback can never become a full-archive scan.
//
// The Sql handle is injected, like dispositions.server.ts, so the
// semantics are testable against PGlite (code-reuse.test.ts).
import { keccak256 } from "js-sha3";
import type { Sql } from "../sql-client.ts";

/**
 * keccak256 of runtime bytecode (hex, with or without the 0x prefix),
 * as a 0x-prefixed hash — the chain's own notion of a codehash, and the
 * same convention the initializer gate uses. Empty code (an EOA, a
 * self-destructed husk) and non-hex input return null: no code, no
 * siblings.
 */
export function codeHashOf(code: string | null | undefined): string | null {
  if (!code) return null;
  const hex = code.trim().toLowerCase().replace(/^0x/, "");
  if (!hex || !/^[0-9a-f]+$/.test(hex) || hex.length % 2 !== 0) return null;
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return `0x${keccak256(bytes)}`;
}

export type SiblingScan = {
  scanId: string;
  address: string | null;
  body: string;
};

/**
 * The newest earlier scan on the same chain whose runtime codehash
 * matches, with its stored body — or null when no sibling is known.
 * `excludeAddress` is the item being analyzed (its own earlier scans
 * are not siblings; the freshness skip owns those).
 */
export async function findSiblingScan(
  sql: Sql,
  chainId: string,
  codeHash: string,
  excludeAddress: string,
): Promise<SiblingScan | null> {
  const chain = (chainId || "ethereum").toLowerCase();
  const exclude = (excludeAddress ?? "").toLowerCase();
  const byHash = await sql<{ scan_id: string; address: string | null; body: string }>`
    select s.id as scan_id, s.target_address as address, p.body as body
    from contract_scans s
    join scan_payloads p on p.scan_id = s.id
    where lower(s.chain_id) = ${chain}
      and s.codehash = ${codeHash}
      and lower(coalesce(s.target_address, '')) <> ${exclude}
      and p.body <> ''
    order by s.created_at desc
    limit 1`;
  if (byHash[0]) {
    return { scanId: byHash[0].scan_id, address: byHash[0].address, body: byHash[0].body };
  }
  // Legacy fallback: pre-0021 rows carry no codehash, but a stored body
  // that is itself bytecode hashes directly. Newest 200 hex bodies on
  // the chain bound the work.
  const legacy = await sql<{ scan_id: string; address: string | null; body: string }>`
    select s.id as scan_id, s.target_address as address, p.body as body
    from contract_scans s
    join scan_payloads p on p.scan_id = s.id
    where lower(s.chain_id) = ${chain}
      and s.codehash is null
      and lower(coalesce(s.target_address, '')) <> ${exclude}
      and p.body like '0x%'
    order by s.created_at desc
    limit 200`;
  for (const row of legacy) {
    if (codeHashOf(row.body) === codeHash) {
      return { scanId: row.scan_id, address: row.address, body: row.body };
    }
  }
  return null;
}

/**
 * Copy auditor dispositions from each scan's newest verdict-bearing
 * sibling onto that scan's findings — ONE statement for the whole batch
 * (the bulk writer's statement-count contract is load-bearing). A
 * finding matches a sibling finding on (detector, location_fn);
 * findings that already carry a disposition are never overwritten, and
 * only sibling findings WITH a disposition contribute. The note names
 * the source scan's address, so the provenance is auditable. Returns
 * how many dispositions were inherited.
 */
export async function inheritDispositionsForScans(
  sql: Sql,
  scanIds: string[],
): Promise<number> {
  if (scanIds.length === 0) return 0;
  const inserted = await sql<{ finding_id: string }>`
    insert into auditor_dispositions (finding_id, disposition, note)
    select nf.id, d.disposition,
      'inherited from ' || coalesce(sib.target_address, sib.id) ||
      ' — identical runtime code (codehash ' || left(me.codehash, 10) ||
      '…); override by setting a disposition here'
    from contract_scans me
    join lateral (
      select s.id, s.target_address
      from contract_scans s
      where lower(s.chain_id) = lower(coalesce(me.chain_id, 'ethereum'))
        and s.codehash = me.codehash
        and s.id <> me.id
        and exists (
          select 1 from findings f
          join auditor_dispositions dd on dd.finding_id = f.id
          where f.scan_id = s.id
        )
      order by s.created_at desc
      limit 1
    ) sib on true
    join findings nf on nf.scan_id = me.id
    join findings sf
      on sf.scan_id = sib.id
      and sf.detector = nf.detector
      and coalesce(sf.location_fn, '') = coalesce(nf.location_fn, '')
    join auditor_dispositions d on d.finding_id = sf.id
    where me.id = any(${scanIds}::text[])
      and me.codehash is not null
    on conflict (finding_id) do nothing
    returning finding_id`;
  return inserted.length;
}
