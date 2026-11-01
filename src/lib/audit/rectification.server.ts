// src/lib/audit/rectification.server.ts
//
// One-click rectification (improvement #7): findings the auditor has
// dispositioned false_positive are proven false — the verdict is of
// record — yet they keep their detector severity in the archive until
// someone runs SQL by hand. Rectification closes that loop in the app:
// for one detector class, every false_positive-dispositioned finding
// still carrying a real severity is set to 'info', in one statement,
// with the count previewed before and reported after.
//
// The disposition is the ONLY proof accepted here — no detector name,
// no matter how FP-prone its class, rectifies a finding nobody
// verdicted. (The hand-run class-wide downgrades of 2026-10-25 were
// fork-proof exercises; their in-app equivalent is reaching the same
// verdicts through dispositions, including inherited ones.)
// Sql injected, like the other archive modules, for PGlite testing.
import type { Sql } from "../sql-client.ts";

export type RectifiableClass = {
  detector: string;
  /** FP-dispositioned findings still carrying a non-info severity. */
  rectifiable: number;
};

/** Per-detector counts of findings a rectification would change. */
export async function rectifiableCounts(sql: Sql): Promise<RectifiableClass[]> {
  const rows = await sql<{ detector: string; n: string }>`
    select f.detector as detector, count(*) as n
    from findings f
    join auditor_dispositions d on d.finding_id = f.id
    where d.disposition = 'false_positive'
      and f.severity <> 'info'
    group by f.detector
    order by f.detector`;
  return rows.map((r) => ({
    detector: r.detector,
    rectifiable: Number.parseInt(r.n, 10) || 0,
  }));
}

/**
 * Set every false_positive-dispositioned finding of one detector to
 * severity 'info'. Returns how many findings changed. Records-tab
 * counts derive from findings at read, so the archive's headlines move
 * with this update — no stored counter needs chasing.
 */
export async function rectifyFalsePositives(sql: Sql, detector: string): Promise<number> {
  const name = detector?.trim();
  if (!name) throw new Error("A detector name is required to rectify.");
  const rows = await sql<{ id: string }>`
    update findings f
    set severity = 'info'
    from auditor_dispositions d
    where d.finding_id = f.id
      and d.disposition = 'false_positive'
      and f.detector = ${name}
      and f.severity <> 'info'
    returning f.id`;
  return rows.length;
}
