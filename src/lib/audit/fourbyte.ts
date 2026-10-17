/**
 * 4byte.directory resolution: function selectors (4-byte) and event
 * topics (32-byte) against the Supabase tables imported by
 * scripts/import-4byte.mjs (migrations 0005 + 0006).
 *
 * The sync bundled list in ./selectors.ts stays the fast path for the
 * ~100 common signatures — analyzeBytecode fills those inline. This
 * module resolves everything else: unknown selectors get their
 * signature from the DB, and PUSH32 immediates are matched against
 * known event topics.
 *
 * Callers with no DB (the browser workbench) do NOT call this module —
 * they use the resolveFourbyte server fn (fourbyte.functions.ts),
 * which runs the DB lookup server-side and returns plain maps.
 */
import type { Report } from "./types";
import type { Sql } from "../sql-client";

/** One batched DB lookup for selectors and topics. Keys are '0x'-prefixed hex. */
export type FourbyteLookup = {
  selectors(selectors: string[]): Promise<Map<string, string[]>>;
  topics(topics: string[]): Promise<Map<string, string[]>>;
};

/** Plain-map form of a lookup result — what the resolveFourbyte server fn returns. */
export type FourbyteResults = {
  selectors: Record<string, string[]>;
  topics: Record<string, string[]>;
};

/** Cap per lookup: a contract's dispatcher + PUSH32s stay well under this. */
const MAX_KEYS = 500;

export function createDbFourbyteLookup(sql: Sql): FourbyteLookup {
  return {
    selectors: async (keys) => {
      const out = new Map<string, string[]>();
      const uniq = [...new Set(keys.map((k) => k.toLowerCase()))].slice(0, MAX_KEYS);
      if (uniq.length === 0) return out;
      const rows = await sql<{ selector: string; signature: string }>`
        select selector, signature from fourbyte_signatures where selector = any(${uniq})`;
      for (const r of rows) {
        const arr = out.get(r.selector) ?? [];
        arr.push(r.signature);
        out.set(r.selector, arr);
      }
      return out;
    },
    topics: async (keys) => {
      const out = new Map<string, string[]>();
      const uniq = [...new Set(keys.map((k) => k.toLowerCase()))].slice(0, MAX_KEYS);
      if (uniq.length === 0) return out;
      const rows = await sql<{ topic: string; signature: string }>`
        select topic, signature from fourbyte_event_signatures where topic = any(${uniq})`;
      for (const r of rows) {
        const arr = out.get(r.topic) ?? [];
        arr.push(r.signature);
        out.set(r.topic, arr);
      }
      return out;
    },
  };
}

/**
 * Merge lookup results into a report: fill unknown selector signatures
 * (first signature wins for display; `signatures` keeps all collisions)
 * and fill unresolved event topics. Pure + synchronous, so the browser
 * can apply server-fn results with it.
 */
export function applyFourbyteResults(report: Report, results: FourbyteResults): { resolvedSelectors: number; resolvedTopics: number } {
  let resolvedSelectors = 0;
  let resolvedTopics = 0;
  const inv = report.inventory;
  for (const s of inv.selectors) {
    if (s.signature) continue;
    const sigs = results.selectors[s.selector.toLowerCase()];
    if (sigs && sigs.length > 0) {
      s.signature = sigs[0]!;
      s.signatures = sigs;
      resolvedSelectors++;
    }
  }
  for (const t of inv.topics ?? []) {
    if (t.signature) continue;
    const sigs = results.topics[t.topic.toLowerCase()];
    if (sigs && sigs.length > 0) {
      t.signature = sigs[0]!;
      resolvedTopics++;
    }
  }
  return { resolvedSelectors, resolvedTopics };
}

/**
 * Full enrichment: look up unknown selectors + topic candidates and
 * merge. Never throws — enrichment failure leaves the report as-is,
 * because the audit stands without it.
 */
export async function enrichReportFourbyte(
  report: Report,
  lookup: FourbyteLookup,
): Promise<{ resolvedSelectors: number; resolvedTopics: number }> {
  try {
    const inv = report.inventory;
    const unknown = inv.selectors.filter((s) => !s.signature).map((s) => s.selector);
    const unresolvedTopics = (inv.topics ?? []).filter((t) => !t.signature).map((t) => t.topic);
    const [sel, top] = await Promise.all([lookup.selectors(unknown), lookup.topics(unresolvedTopics)]);
    return applyFourbyteResults(report, {
      selectors: Object.fromEntries(sel),
      topics: Object.fromEntries(top),
    });
  } catch {
    return { resolvedSelectors: 0, resolvedTopics: 0 };
  }
}

/** Build the server-fn payload shape from a report's resolved names. */
export function fourbyteResultsFromReport(report: Report): FourbyteResults {
  const selectors: Record<string, string[]> = {};
  for (const s of report.inventory.selectors) {
    if (s.signature) selectors[s.selector.toLowerCase()] = [s.signature];
  }
  const topics: Record<string, string[]> = {};
  for (const t of report.inventory.topics ?? []) {
    if (t.signature) topics[t.topic.toLowerCase()] = [t.signature];
  }
  return { selectors, topics };
}

/** Prompt-sized rendering of resolved names, for AI + Deep Agent. */
export function formatFourbyteResultsForPrompt(results: FourbyteResults, maxSelectors = 40, maxTopics = 20): string {
  const selEntries = Object.entries(results.selectors).slice(0, maxSelectors);
  const topEntries = Object.entries(results.topics).slice(0, maxTopics);
  if (selEntries.length === 0 && topEntries.length === 0) return "";
  const lines = ["\nKNOWN FUNCTIONS + EVENTS (4byte.directory — resolved from the target's bytecode; these exist on the target, prefer them over invented interfaces):"];
  if (selEntries.length > 0) {
    lines.push("Functions:");
    for (const [sel, sigs] of selEntries) lines.push(`- ${sigs[0]} — ${sel}`);
  }
  if (topEntries.length > 0) {
    lines.push("Events:");
    for (const [topic, sigs] of topEntries) lines.push(`- ${sigs[0]} — ${topic}`);
  }
  return lines.join("\n");
}

/** Prompt-sized rendering of a report's resolved names, for AI + Deep Agent. */
export function formatFourbyteForPrompt(report: Report, maxSelectors = 40, maxTopics = 20): string {
  return formatFourbyteResultsForPrompt(fourbyteResultsFromReport(report), maxSelectors, maxTopics);
}
