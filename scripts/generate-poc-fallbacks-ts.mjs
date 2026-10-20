#!/usr/bin/env node
/**
 * Generate src/lib/audit/poc-fallbacks.ts from the fallback PoC library.
 *
 * Source of truth: foundry/poc-fallbacks/*.t.sol + index.json.
 * The generated module embeds the template sources as strings so the
 * server-only AI review (TanStack Start server fn) can inject the
 * matching template(s) into the AI prompt as the starting point — no
 * runtime file reads, no GitHub fetch, nothing in the browser bundle.
 *
 * Usage (from repo root):
 *   node scripts/generate-poc-fallbacks-ts.mjs
 *   node scripts/generate-poc-fallbacks-ts.mjs --src foundry/poc-fallbacks --out src/lib/audit/poc-fallbacks.ts
 */
import fs from "node:fs";
import path from "node:path";

const args = process.argv.slice(2);
const getArg = (name, fallback) => {
  const i = args.indexOf(`--${name}`);
  return i >= 0 && args[i + 1] ? args[i + 1] : fallback;
};
const srcDir = getArg("src", "foundry/poc-fallbacks");
const outFile = getArg("out", "src/lib/audit/poc-fallbacks.ts");

const index = JSON.parse(fs.readFileSync(path.join(srcDir, "index.json"), "utf8"));

const templates = {};
for (const f of index.fallbacks) {
  const source = fs.readFileSync(path.join(srcDir, f.file), "utf8");
  templates[f.file] = source;
}

const byDetector = {};
for (const f of index.fallbacks) {
  for (const d of f.detectors) {
    if (!byDetector[d]) byDetector[d] = [];
    if (!byDetector[d].includes(f.file)) byDetector[d].push(f.file);
  }
}

// Full catalog (file -> scenario + detectors + SmartBugs category) so the agent
// knows which template shapes exist when it proposes a hypothesis for a new
// detector. `smartbugs` is the DASP / SmartBugs-Curated category of the template
// (see src/lib/audit/smartbugs.ts), which keeps the fallback library aligned
// with the reference dataset's taxonomy.
const catalog = index.fallbacks.map((f) => ({
  file: f.file,
  scenario: f.scenario,
  detectors: f.detectors,
  smartbugs: f.smartbugs ?? "other",
}));

// SmartBugs category -> template file(s).
const bySmartbugs = {};
for (const f of index.fallbacks) {
  const c = f.smartbugs ?? "other";
  if (!bySmartbugs[c]) bySmartbugs[c] = [];
  if (!bySmartbugs[c].includes(f.file)) bySmartbugs[c].push(f.file);
}

const header = `// GENERATED — do not edit by hand.
// Regenerate: node scripts/generate-poc-fallbacks-ts.mjs
// Source of truth: foundry/poc-fallbacks/*.t.sol + index.json
// The fallback library is organised by the SmartBugs-Curated (DASP) taxonomy
// (src/lib/audit/smartbugs.ts).
// The AI review (ai-review.server.ts) injects the matching template(s)
// into the model prompt as the STARTING POINT for the generated PoC —
// the model adapts the template's TODOs to the target's real ABI instead
// of inventing a harness from scratch. The no-AI template fallback also
// returns the best-matching template instead of a hollow sanity check.

import { smartbugsCategoryForDetector } from "./smartbugs.ts";

/** Fallback PoC template sources, keyed by library file name. */
export const POC_FALLBACK_TEMPLATES: Record<string, string> = ${JSON.stringify(templates, null, 2)};

/** Detector id -> fallback template file(s), from the library index. */
export const POC_FALLBACK_BY_DETECTOR: Record<string, string[]> = ${JSON.stringify(byDetector, null, 2)};

/** Full fallback catalog: file -> scenario + detectors + SmartBugs category. */
export const POC_FALLBACK_CATALOG: Array<{ file: string; scenario: string; detectors: string[]; smartbugs: string }> = ${JSON.stringify(catalog, null, 2)};

/** SmartBugs-Curated (DASP) category -> fallback template file(s). */
export const POC_FALLBACK_BY_SMARTBUGS: Record<string, string[]> = ${JSON.stringify(bySmartbugs, null, 2)};

const SEVERITY_RANK: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

export type PocFindingRef = { detector: string; severity: string };

/**
 * Pick distinct starting-point templates for the top findings, most
 * severe first. Capped so the AI prompt stays lean — 3 templates is
 * ~10KB of prompt for a 262k-context model.
 */
export function selectPocFallbacks(
  findings: PocFindingRef[],
  maxTemplates = 3,
): Array<{ file: string; source: string }> {
  const sorted = [...findings].sort(
    (a, b) => (SEVERITY_RANK[a.severity] ?? 5) - (SEVERITY_RANK[b.severity] ?? 5),
  );
  const seen = new Set<string>();
  const out: Array<{ file: string; source: string }> = [];
  for (const f of sorted) {
    // Detector-specific harnesses first; if the detector has none, fall back to
    // the harnesses for its SmartBugs-Curated (DASP) category, so a finding
    // still starts from a working template for the right vulnerability class.
    const byDetector = POC_FALLBACK_BY_DETECTOR[f.detector] ?? [];
    const files = byDetector.length
      ? byDetector
      : POC_FALLBACK_BY_SMARTBUGS[smartbugsCategoryForDetector(f.detector)] ?? [];
    for (const file of files) {
      if (seen.has(file)) continue;
      seen.add(file);
      const source = POC_FALLBACK_TEMPLATES[file];
      if (!source) continue;
      out.push({ file, source });
      if (out.length >= maxTemplates) return out;
    }
  }
  return out;
}

/**
 * Pick fallback templates for a SmartBugs-Curated (DASP) category. Use when a
 * finding maps to a category but no detector-specific template exists, so the
 * model still starts from a working harness for the right vulnerability class.
 */
export function selectPocFallbacksBySmartbugs(
  category: string,
  maxTemplates = 3,
): Array<{ file: string; source: string }> {
  const out: Array<{ file: string; source: string }> = [];
  for (const file of POC_FALLBACK_BY_SMARTBUGS[category] ?? []) {
    const source = POC_FALLBACK_TEMPLATES[file];
    if (!source) continue;
    out.push({ file, source });
    if (out.length >= maxTemplates) return out;
  }
  return out;
}
`;

fs.mkdirSync(path.dirname(outFile), { recursive: true });
fs.writeFileSync(outFile, header);
console.log(`wrote ${outFile}: ${Object.keys(templates).length} templates, ${Object.keys(byDetector).length} detectors`);
