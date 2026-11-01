// src/lib/audit/live-gates.ts
//
// Live-state gates: the generalization of the initializer gate's lesson
// (Fix 37) — a finding whose claim depends on mutable chain state
// should carry the LIVE value of that state, read at analysis time,
// instead of leaving the adjudicator to re-derive it per clone.
//
// Two passes, both pure report mutations run by the address fetcher
// after value/ABI attachment (and after the live-state probe on the
// verified-source path):
//
// - applyValueExposure: for value-extraction detectors, the finding's
//   economicClaim becomes the address's LIVE value (basis "live"),
//   replacing the text-figure guess the detector tagged as an
//   assumption. A completely-read $0 is stated as $0 — a real
//   mechanism in an empty room (the Curve adapter shape) is a
//   different triage object from the same mechanism holding $2M, and
//   the claim should say which one this is.
//
// - applyLiveStateAnnotations: decisive live reads the fetcher already
//   probed (owner, paused) are written into the confidenceBasis of the
//   findings they bear on. ANNOTATION ONLY — the live-state module's
//   doctrine stands (evidence, not re-scoring); severity moves only
//   through probe gates like the initializer's, never through a
//   getter's value alone.
import type { Report } from "./types.ts";
import { formatUsd } from "./value.ts";

/** Detectors whose payoff is bounded by what the address actually holds. */
export const VALUE_BOUND_DETECTORS: ReadonlySet<string> = new Set([
  "unprotected-ether",
  "selfdestruct",
  "token-drain",
]);

/** Detectors a live `paused() = true` read directly bears on. */
const PAUSED_RELEVANT_DETECTORS: ReadonlySet<string> = new Set([
  ...VALUE_BOUND_DETECTORS,
  "reentrancy",
  "read-only-reentrancy",
]);

function appendBasis(report: Report, index: number, note: string): void {
  const f = report.findings[index]!;
  f.confidenceBasis = f.confidenceBasis ? `${f.confidenceBasis} · ${note}` : note;
}

/**
 * Stamp value-bound findings with the live value at the address.
 * Returns how many findings were stamped.
 */
export function applyValueExposure(report: Report): number {
  const value = report.inventory.value;
  if (!value) return 0;
  // An incomplete zero is unknown, not empty — never state it as $0.
  if (value.totalUsd <= 0 && !value.complete) return 0;
  const usd = formatUsd(value.totalUsd);
  if (!usd) return 0;
  const figure =
    value.totalUsd > 0
      ? `${usd} live value at this address (${value.priced} priced holding${value.priced === 1 ? "" : "s"}${value.complete ? "" : ", incomplete read"})`
      : "$0.00 live value at this address (complete read — nothing to extract)";
  let stamped = 0;
  for (const f of report.findings) {
    if (!VALUE_BOUND_DETECTORS.has(f.detector)) continue;
    if (f.economicClaim?.basis === "live") continue;
    f.economicClaim = { figure, basis: "live" };
    stamped++;
  }
  return stamped;
}

/**
 * Attach decisive live reads to the findings they bear on, as
 * confidenceBasis notes. Returns how many findings were annotated.
 */
export function applyLiveStateAnnotations(report: Report): number {
  const live = report.inventory.liveState;
  if (!live || live.reads.length === 0) return 0;
  const block = live.blockNumber !== null ? ` at block ${live.blockNumber}` : "";
  const owner = live.reads.find((r) => r.kind === "address" && /owner/i.test(r.name));
  const paused = live.reads.find((r) => r.kind === "bool" && r.name === "paused");
  let annotated = 0;
  report.findings.forEach((f, i) => {
    if (owner && f.detector === "unprotected-admin") {
      appendBasis(report, i, `live ${owner.name}() = ${owner.value}${block}`);
      annotated++;
    }
    if (
      paused &&
      paused.value === "true" &&
      (f.severity === "critical" || f.severity === "high") &&
      PAUSED_RELEVANT_DETECTORS.has(f.detector)
    ) {
      appendBasis(report, i, `live paused() = true${block} — the extraction path is paused on-chain`);
      annotated++;
    }
  });
  return annotated;
}

/** Both live-gate passes, in order. Safe on any report (no-ops without data). */
export function applyLiveGates(report: Report): void {
  applyValueExposure(report);
  applyLiveStateAnnotations(report);
}
