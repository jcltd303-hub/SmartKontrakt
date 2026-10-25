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

// Detectors with NO applicable harness (index.json `notPocable`, a list of
// { detectors, reason } groups). Flattened + sorted for a stable generated
// module. Selection must honor this set explicitly: without the check, an
// unmapped detector silently inherits its SmartBugs-category templates,
// which manufactures verdicts for findings that have no exploit at all.
const notPocable = [
  ...new Set((index.notPocable ?? []).flatMap((entry) => entry.detectors ?? [])),
].sort();

// Per-template TODO preconditions (index.json `todo`): the names of the
// template constants an adapter MUST fill before the harness can judge a
// target. As shipped they hold zero values and the template aborts on its
// own require before testing anything, so a direct-path run of the
// unadapted template is a scaffold abort, not a verdict. The run paths
// consult this map (via poc-outcome.ts) BEFORE spending a backend run.
const todoRequirements = {};
for (const f of index.fallbacks) {
  if (Array.isArray(f.todo) && f.todo.length > 0) todoRequirements[f.file] = f.todo;
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
  // Where the harness comes from: a SmartBugs Curated port ("dataset", with the
  // dataset paths) or a modelled class with no dataset equivalent.
  provenance: f.provenance ?? { kind: "modelled", category: f.smartbugs ?? "other", sources: [] },
}));

// SmartBugs category -> template file(s), built from the DETECTOR side:
// a template belongs to a category when one of its home detectors
// (index.json `detectors`) belongs to that category in the SmartBugs
// registry (src/lib/audit/smartbugs.ts SMARTBUGS_BY_DETECTOR). The old
// build grouped by each template's own index `smartbugs` label, which
// stranded templates whose label disagreed with their detectors'
// categories (a DoS-class template labelled "other" never reached the
// denial_of_service list an unmapped DoS detector inherits). A template
// with detectors spanning categories appears in each of them; index
// order is preserved inside every list. Templates with no home
// detectors (37, catalog-only) join no category.
//
// The generator is plain node and cannot import the TS registry, so
// the literal is extracted from the smartbugs.ts source and parsed
// entry by entry. Fail loudly if the registry moves or shrinks — a
// silent thin parse would quietly empty the category lists.
const smartbugsSource = fs.readFileSync(
  path.resolve(srcDir, "..", "..", "src", "lib", "audit", "smartbugs.ts"),
  "utf8",
);
const registryMatch = smartbugsSource.match(/SMARTBUGS_BY_DETECTOR[^=]*=\s*\{([\s\S]*?)\n\};/);
if (!registryMatch) {
  throw new Error("generate-poc-fallbacks-ts: SMARTBUGS_BY_DETECTOR literal not found in src/lib/audit/smartbugs.ts");
}
const detectorCategory = {};
for (const m of registryMatch[1].matchAll(/^\s*(?:"([^"]+)"|([A-Za-z0-9_-]+))\s*:\s*"([^"]+)"/gm)) {
  detectorCategory[m[1] ?? m[2]] = m[3];
}
if (Object.keys(detectorCategory).length < 50) {
  throw new Error(
    `generate-poc-fallbacks-ts: only ${Object.keys(detectorCategory).length} SMARTBUGS_BY_DETECTOR entries parsed (< 50) — registry format changed?`,
  );
}
const bySmartbugs = {};
for (const f of index.fallbacks) {
  const cats = new Set(
    (f.detectors ?? []).map((d) => detectorCategory[d]).filter((c) => typeof c === "string"),
  );
  for (const c of cats) {
    if (!bySmartbugs[c]) bySmartbugs[c] = [];
    if (!bySmartbugs[c].includes(f.file)) bySmartbugs[c].push(f.file);
  }
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

import { SMARTBUGS_BY_DETECTOR, smartbugsCategoryForDetector } from "./smartbugs.ts";

/** Fallback PoC template sources, keyed by library file name. */
export const POC_FALLBACK_TEMPLATES: Record<string, string> = ${JSON.stringify(templates, null, 2)};

/** Detector id -> fallback template file(s), from the library index. */
export const POC_FALLBACK_BY_DETECTOR: Record<string, string[]> = ${JSON.stringify(byDetector, null, 2)};

/**
 * Detectors with NO applicable PoC harness (index.json \`notPocable\`):
 * code-quality / hygiene findings, bytecode-shape signals, and analyzer
 * meta-findings. selectPocFallbacks returns nothing for them — borrowing a
 * SmartBugs-category harness for a finding with no exploit would manufacture
 * a verdict the finding never earned.
 */
export const POC_NOT_POCABLE_DETECTORS: string[] = ${JSON.stringify(notPocable, null, 2)};

/**
 * Fallback template file -> the TODO constants an adapter must fill
 * before the harness can judge a target (index.json \`todo\`). Templates
 * absent from this map run unadapted. A direct-path run whose constants
 * are still zero is filed "unadapted" (poc-outcome.ts) — never as a
 * verdict or an infra error.
 */
export const POC_FALLBACK_TODO_REQUIREMENTS: Record<string, string[]> = ${JSON.stringify(todoRequirements, null, 2)};

/** Full fallback catalog: file -> scenario + detectors + category + provenance. */
export const POC_FALLBACK_CATALOG: Array<{
  file: string;
  scenario: string;
  detectors: string[];
  smartbugs: string;
  provenance: { kind: "dataset" | "modelled"; category: string; sources: string[]; note?: string };
}> = ${JSON.stringify(catalog, null, 2)};

/** SmartBugs-Curated (DASP) category -> fallback template file(s),
 *  built from the detector side: a template is listed under every
 *  category one of its home detectors belongs to in the SmartBugs
 *  registry (SMARTBUGS_BY_DETECTOR). */
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
    // Not-PoC-able detectors get NO template — not even a category fallback.
    // The finding has no on-chain exploit (or is an analyzer meta-finding),
    // so any harness verdict attached to it would be unearned.
    if (POC_NOT_POCABLE_DETECTORS.includes(f.detector)) continue;
    if (!Object.hasOwn(SMARTBUGS_BY_DETECTOR, f.detector) && !Object.hasOwn(POC_FALLBACK_BY_DETECTOR, f.detector)) continue;
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
