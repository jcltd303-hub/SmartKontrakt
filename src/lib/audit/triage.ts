// src/lib/audit/triage.ts
//
// The read queue (2026-10-27).
//
// The recall-first loosening left low-confidence findings with nowhere to go:
// they are real signals with weaker evidence, and the point of dropping the
// gates was to catch what tightness was missing — not to bury it in the same
// list as the criticals. This module is the overflow valve.
//
// Three questions decide where a finding goes, in this order:
//
//   1. Can anyone reach it?      REACHABLE first, then NEEDS_READ (a guard the
//                                analyzer could not resolve), then the gated
//                                and bounded classes, then INTERNAL.
//   2. How strong is the evidence? high > medium > low, with `confidenceBasis`
//                                saying WHY (resolved site, unresolved gate,
//                                precondition text, file-level pattern).
//   3. How bad is it if true?    severity, as the tie-break.
//
// The queue is deliberately NOT "everything sorted by score". It is the subset
// a human has to read, with the reason attached, because the engagement that
// started all this measured 480 hits producing one real issue — and the fix for
// that is a short, ordered queue, not a better sort of a long one.

import type { Finding } from "./types.ts";
import type { DetectorFamily } from "./detector-registry.ts";
import { familyForDetector } from "./detector-registry.ts";

export type TriageBand = "read-now" | "read-next" | "needs-live-state" | "background";

export type TriagedFinding<T extends Finding = Finding> = {
  finding: T;
  band: TriageBand;
  /** Why this band, in one line a reviewer can act on. */
  reason: string;
  family: DetectorFamily;
};

const SEVERITY_RANK: Record<Finding["severity"], number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

const CONFIDENCE_RANK: Record<Finding["confidence"], number> = { high: 0, medium: 1, low: 2 };

const REACHABILITY_RANK: Record<string, number> = {
  REACHABLE: 0,
  NEEDS_READ: 1,
  BOUNDED: 2,
  GATED: 3,
  INTERNAL: 4,
};

/**
 * Band a finding.
 *
 * `read-now`     reachable with high or medium confidence — the ones that can
 *                cost money today.
 * `read-next`    reachable but low confidence (the loosened rules), or a
 *                NEEDS_READ site: a real signal whose evidence is incomplete.
 * `needs-live-state`  the finding's magnitude depends on a live read (a money
 *                figure marked as an assumption, or a live-threshold
 *                precondition). Reading the code cannot settle it.
 * `background`   gated, bounded, internal, or info: not a queue item.
 */
export function triageFinding<T extends Finding>(finding: T): TriagedFinding<T> {
  const family = familyForDetector(finding.detector);
  const reach = finding.reachability ?? null;
  const basis = finding.confidenceBasis ?? null;

  // Info severity first: a reachable info finding (an unchecked increment, a
  // metadata note) is still a note and must not enter the read queue just
  // because anyone can call the function.
  if (finding.severity === "info") {
    return {
      finding,
      band: "background",
      reason: "info severity: a note, not a finding",
      family,
    };
  }

  // A published figure with no live source cannot be settled by reading code.
  if (finding.economicClaim?.basis === "assumption" && reach !== "GATED" && reach !== "INTERNAL") {
    return {
      finding,
      band: "needs-live-state",
      reason: `carries the figure "${finding.economicClaim.figure}" with basis "assumption" — fetch the live value before publishing or dismissing it`,
      family,
    };
  }

  if (reach === "REACHABLE") {
    if (finding.confidence === "low") {
      return {
        finding,
        band: "read-next",
        reason: `reachable, low confidence${basis ? ` (${basis})` : ""} — loosened evidence, read it before believing it`,
        family,
      };
    }
    return {
      finding,
      band: "read-now",
      reason: `reachable, ${finding.confidence} confidence${basis ? ` (${basis})` : ""}`,
      family,
    };
  }

  if (reach === "NEEDS_READ") {
    return {
      finding,
      band: "read-next",
      reason: "the guard could not be resolved (an imported or generated modifier), so reachability is unknown",
      family,
    };
  }

  return {
    finding,
    band: "background",
    reason: reach
      ? `${reach.toLowerCase()}${finding.gate ? ` via ${finding.gate}` : ""}${finding.preconditions?.length ? ` (${finding.preconditions.join("; ")})` : ""}`
      : "no reachability class (internal helper or a pre-tag record)",
    family,
  };
}

/**
 * The read queue, ordered: read-now, read-next, needs-live-state, background —
 * and inside each band by confidence, then severity, then line.
 */
export function triageQueue<T extends Finding>(findings: readonly T[]): TriagedFinding<T>[] {
  const bandRank: Record<TriageBand, number> = {
    "read-now": 0,
    "read-next": 1,
    "needs-live-state": 2,
    background: 3,
  };
  return findings
    .map((f) => triageFinding(f))
    .sort((a, b) => {
      const band = bandRank[a.band] - bandRank[b.band];
      if (band !== 0) return band;
      const conf = CONFIDENCE_RANK[a.finding.confidence] - CONFIDENCE_RANK[b.finding.confidence];
      if (conf !== 0) return conf;
      const sev = SEVERITY_RANK[a.finding.severity] - SEVERITY_RANK[b.finding.severity];
      if (sev !== 0) return sev;
      const reach =
        (REACHABILITY_RANK[a.finding.reachability ?? ""] ?? 5) -
        (REACHABILITY_RANK[b.finding.reachability ?? ""] ?? 5);
      if (reach !== 0) return reach;
      return (a.finding.locationLine ?? 0) - (b.finding.locationLine ?? 0);
    });
}

/** The findings a human actually has to read — the first three bands. */
export function readQueue<T extends Finding>(findings: readonly T[]): TriagedFinding<T>[] {
  return triageQueue(findings).filter((t) => t.band !== "background");
}

export type TriageCounts = {
  total: number;
  readNow: number;
  readNext: number;
  needsLiveState: number;
  background: number;
  /** Reachable findings that are high/medium confidence — the headline number. */
  actionable: number;
  /** How many families the queue spans; a queue across many families is noise. */
  familiesInQueue: number;
};

export function triageCounts(findings: readonly T[]): TriageCounts {
  const queue = triageQueue(findings);
  const inQueue = queue.filter((t) => t.band !== "background");
  return {
    total: findings.length,
    readNow: queue.filter((t) => t.band === "read-now").length,
    readNext: queue.filter((t) => t.band === "read-next").length,
    needsLiveState: queue.filter((t) => t.band === "needs-live-state").length,
    background: queue.filter((t) => t.band === "background").length,
    actionable: queue.filter((t) => t.band === "read-now").length,
    familiesInQueue: new Set(inQueue.map((t) => t.family)).size,
  };
}
