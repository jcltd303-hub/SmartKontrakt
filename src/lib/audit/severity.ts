/**
 * The severity vocabulary — one place, so nothing re-derives the order.
 *
 * `Severity` is declared in types.ts; the ORDER lived twice (a `RANK` map in
 * risk.ts and a separate `SEVERITY_ORDER` array in rag.server.ts) and two
 * orderings for one vocabulary drift. The display labels live with the UI
 * (components/workbench/presentation.ts owns the tones), but the canonical
 * uppercase label belongs here so a report and a knowledge-base chunk name the
 * same severity the same way.
 */
import type { Severity } from "./types.ts";

export type { Severity } from "./types.ts";

/** Most severe first. The single ordering for the whole app. */
export const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"] as const;

/** 0 = most severe. Unknown values sort last rather than throwing. */
export function severityRank(severity: Severity): number {
  const i = (SEVERITY_ORDER as readonly string[]).indexOf(severity);
  return i === -1 ? SEVERITY_ORDER.length : i;
}

/** Most severe first — the comparator every list should sort by. */
export function bySeverity(a: { severity: Severity }, b: { severity: Severity }): number {
  return severityRank(a.severity) - severityRank(b.severity);
}

export const SEVERITY_LABEL: Record<Severity, string> = {
  critical: "CRITICAL",
  high: "HIGH",
  medium: "MEDIUM",
  low: "LOW",
  info: "INFO",
};

export function isSeverity(value: unknown): value is Severity {
  return typeof value === "string" && (SEVERITY_ORDER as readonly string[]).includes(value);
}
