// src/lib/audit/detector-scoreboard.server.ts
//
// The SQL half of the detector scoreboard: per-detector counts of the
// auditor's dispositions over the whole archive. Sql injected, like
// dispositions.server.ts, so the aggregation is testable against
// PGlite (detector-scoreboard.test.ts).
import type { Sql } from "../sql-client.ts";
import {
  isDemotionFlagged,
  type DetectorStats,
} from "./detector-scoreboard.ts";

/** Every detector that has at least one dispositioned finding, by name. */
export async function detectorScoreboard(sql: Sql): Promise<DetectorStats[]> {
  const rows = await sql<{ detector: string; confirmed: string; fp: string; nmi: string }>`
    select f.detector as detector,
           count(*) filter (where d.disposition = 'confirmed') as confirmed,
           count(*) filter (where d.disposition = 'false_positive') as fp,
           count(*) filter (where d.disposition = 'needs_more_info') as nmi
    from findings f
    join auditor_dispositions d on d.finding_id = f.id
    group by f.detector
    order by f.detector`;
  return rows.map((r) => {
    const confirmed = Number.parseInt(r.confirmed, 10) || 0;
    const falsePositive = Number.parseInt(r.fp, 10) || 0;
    const needsMoreInfo = Number.parseInt(r.nmi, 10) || 0;
    const dispositioned = confirmed + falsePositive + needsMoreInfo;
    return {
      detector: r.detector,
      confirmed,
      falsePositive,
      needsMoreInfo,
      dispositioned,
      fpRate: dispositioned > 0 ? falsePositive / dispositioned : 0,
    };
  });
}

/** Only the demotion-flagged detectors, keyed by name — the analysis-time input. */
export async function demotionMap(sql: Sql): Promise<Map<string, DetectorStats>> {
  const all = await detectorScoreboard(sql);
  return new Map(all.filter(isDemotionFlagged).map((s) => [s.detector, s]));
}
