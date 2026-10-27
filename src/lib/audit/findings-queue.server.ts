// src/lib/audit/findings-queue.server.ts
//
// The read queue, as data (2026-10-27).
//
// `triage.ts` computes the banding — reachable first, then evidence, then
// severity — and until now had NO consumer outside its own test. Only
// `sortFindingsForTriage` was wired, into the certificate's table order. So the
// thing the reachability work exists for, a short ordered list of what a human
// should open next, was computed and thrown away.
//
// This exposes it server-side. No React, so it is testable here; a view can
// consume it without another round of logic.

import type { Sql } from "../db.ts";
import { readQueue, triageCounts, type TriagedFinding } from "./triage.ts";
import type { Finding } from "./types.ts";

export type FindingsQueueRow = {
  scanId: string;
  address: string | null;
  chainId: string | null;
  band: TriagedFinding["band"];
  reason: string;
  family: TriagedFinding["family"];
  detector: string;
  severity: string;
  confidence: string;
  reachability: string | null;
  title: string;
  locationFn: string | null;
  locationLine: number | null;
};

export type FindingsQueueResult = {
  rows: FindingsQueueRow[];
  counts: ReturnType<typeof triageCounts>;
  /** Records considered. The queue is the head of this, not all of it. */
  scanned: number;
};

type Row = {
  scan_id: string;
  target_address: string | null;
  chain_id: string | null;
  detector: string;
  family: string | null;
  severity: string;
  confidence: string;
  confidence_basis: string | null;
  reachability: string | null;
  gate: string | null;
  preconditions: unknown;
  economic_figure: string | null;
  economic_basis: string | null;
  title: string;
  location_fn: string | null;
  location_line: number | null;
  snippet: string | null;
};

/** A stored row, reshaped into the Finding fields triage.ts reads. */
function toFinding(r: Row): Finding {
  const preconditions = Array.isArray(r.preconditions)
    ? (r.preconditions as string[])
    : typeof r.preconditions === "string"
      ? (JSON.parse(r.preconditions) as string[])
      : [];
  return {
    id: `${r.scan_id}:${r.detector}:${r.location_line ?? 0}`,
    severity: r.severity as Finding["severity"],
    title: r.title,
    confidence: r.confidence as Finding["confidence"],
    detector: r.detector,
    summary: "",
    walkthrough: "",
    exploitSolidity: "",
    remediationSolidity: "",
    locationFn: r.location_fn,
    locationLine: r.location_line,
    snippet: r.snippet ?? "",
    family: (r.family ?? undefined) as Finding["family"],
    reachability: (r.reachability ?? null) as Finding["reachability"],
    gate: r.gate,
    preconditions,
    confidenceBasis: r.confidence_basis,
    economicClaim: r.economic_figure
      ? { figure: r.economic_figure, basis: (r.economic_basis ?? "assumption") as "assumption" | "live" }
      : undefined,
  } as Finding;
}

/**
 * The queue for the most recent scans, newest first.
 *
 * `limit` bounds the SCANS considered, not the rows returned: a queue built from
 * the newest 200 scans is the "what came in recently" question, and bounding rows
 * instead would return a truncated queue that looks complete.
 */
export async function findingsQueue(sql: Sql, limit = 200): Promise<FindingsQueueResult> {
  const rows = await sql<Row>`
    select f.scan_id, s.target_address, s.chain_id, f.detector, f.family, f.severity,
           f.confidence, f.confidence_basis, f.reachability, f.gate, f.preconditions,
           f.economic_figure, f.economic_basis, f.title, f.location_fn, f.location_line, f.snippet
    from findings f
    join contract_scans s on s.id = f.scan_id
    where f.scan_id in (
      select id from contract_scans order by created_at desc limit ${limit}
    )`;

  const findings = rows.map(toFinding);
  const queue = readQueue(findings);
  const meta = new Map(findings.map((f) => [f.id, f]));
  void meta;
  const byId = new Map(rows.map((r) => [toFinding(r).id, r]));

  return {
    counts: triageCounts(findings),
    scanned: rows.length,
    rows: queue.map((t) => {
      const r = byId.get(t.finding.id)!;
      return {
        scanId: r.scan_id,
        address: r.target_address,
        chainId: r.chain_id,
        band: t.band,
        reason: t.reason,
        family: t.family,
        detector: t.finding.detector,
        severity: t.finding.severity,
        confidence: t.finding.confidence,
        reachability: t.finding.reachability ?? null,
        title: t.finding.title,
        locationFn: t.finding.locationFn ?? null,
        locationLine: t.finding.locationLine ?? null,
      };
    }),
  };
}
