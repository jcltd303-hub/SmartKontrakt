#!/usr/bin/env node
/**
 * Detection benchmark against SmartBugs Curated.
 *
 * This is the measurement the detection work never had: 143 contracts with
 * hand-annotated vulnerability categories, run through the analyzer, scored
 * per category. Everything else in this repo — the incident corpora, the
 * reachability classifier, the confidence post-passes — is only as good as
 * these numbers.
 *
 * Usage:
 *   node --experimental-strip-types scripts/benchmark-smartbugs.ts
 *       score, compare against scripts/smartbugs-baseline.json, exit 1 on
 *       any regression (recall down, precision down, or noise up)
 *   node --experimental-strip-types scripts/benchmark-smartbugs.ts --write
 *       re-baseline (use when a change is a deliberate trade, and say so in
 *       the commit message)
 *   ... --report docs/smartbugs-benchmark.md
 *       also write the markdown report
 *
 * Definitions, because they decide the numbers:
 *
 *   A category is PREDICTED for a file when any finding on that file maps to
 *   it (smartbugs.ts). A file is a TRUE POSITIVE for category C when C is in
 *   both the expected and the predicted set. It is a FALSE NEGATIVE when C is
 *   expected and not predicted. It is a FALSE POSITIVE when C is predicted and
 *   not expected.
 *
 *   That makes precision a measure of cross-category noise: a reentrancy rule
 *   that also fires on an arithmetic contract costs precision on
 *   `reentrancy` (it was predicted where it was not expected) and gains
 *   nothing. Recall is the per-category hit rate.
 *
 *   File-level, not line-level: the dataset annotates lines, this analyzer
 *   reports sites, and a line-number join across 0.4.x pragmas and a parser
 *   that normalises whitespace would measure the join, not the detector.
 */
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { analyzeInput } from "../src/lib/audit/engine.ts";
import { SMARTBUGS_CATEGORIES, smartbugsCategoryForDetector } from "../src/lib/audit/smartbugs.ts";

/**
 * Hygiene detectors are excluded from CATEGORY scoring. They are real findings,
 * but they are not vulnerability classes: `floating-pragma` and `old-compiler`
 * fire on essentially every pre-0.8 contract, so counting them would mark all
 * 143 files as "predicted: other" and make the `other` column meaningless
 * (measured: precision 0.021, and it buried every real signal in the table).
 * They stay in the findings and in the noise count — they just do not vote on
 * which vulnerability class a contract belongs to.
 */
const HYGIENE_DETECTORS = new Set([
  "floating-pragma",
  "old-compiler",
  "missing-event",
  "rtl-override",
  "parse",
  "report-cap",
  "bytecode-metadata",
  // Presence notes, added 2026-10-27 after they were measured: eth-gas-stipend
  // fires on 146 of 143 contracts (a .transfer()/.send() stipend is not a
  // vulnerability class) and locked-ether on 41. Both are real observations and
  // both are now info severity; neither says which DASP class a contract
  // belongs to, so neither votes in the category table. Leaving them in made
  // denial_of_service read 0.029 precision and then made "other" the dumping
  // ground when they were moved there — the noise follows the category, so the
  // category vote is what has to stop.
  "eth-gas-stipend",
  "locked-ether",
]);

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const FIXTURES = path.join(ROOT, "test/fixtures/smartbugs-curated");
const BASELINE = path.join(ROOT, "scripts/smartbugs-baseline.json");

type DatasetEntry = {
  name: string;
  path: string;
  pragma?: string;
  vulnerabilities: { lines?: number[]; category: string }[];
};

export type CategoryScore = {
  category: string;
  expected: number;
  predicted: number;
  truePositives: number;
  falseNegatives: number;
  falsePositives: number;
  recall: number;
  precision: number;
};

export type BenchmarkResult = {
  files: number;
  parsed: number;
  parseFailures: string[];
  totalFindings: number;
  filesWithFindings: number;
  findingsPerFile: number;
  categories: CategoryScore[];
  /** Detectors that fired at least once, and those that never did. */
  detectorsFired: string[];
  detectorsIdle: string[];
  /** detector -> files it fired on, and of those, how many were labelled with
   *  its own category. The second number is the noise leader board. */
  detectorFiles: Record<string, { fired: number; onExpectedCategory: number }>;
};

const round = (n: number) => Math.round(n * 1000) / 1000;

export function runBenchmark(): BenchmarkResult {
  const entries = JSON.parse(
    readFileSync(path.join(FIXTURES, "vulnerabilities.json"), "utf8"),
  ) as DatasetEntry[];

  const expectedByCategory = new Map<string, number>();
  const predictedByCategory = new Map<string, number>();
  const tp = new Map<string, number>();
  const fn = new Map<string, number>();
  const fp = new Map<string, number>();
  const detectorsFired = new Set<string>();
  const detectorFiles = new Map<string, { fired: number; onExpectedCategory: number }>();
  const parseFailures: string[] = [];
  let totalFindings = 0;
  let filesWithFindings = 0;
  let parsed = 0;

  const bump = (m: Map<string, number>, k: string) => m.set(k, (m.get(k) ?? 0) + 1);

  for (const entry of entries) {
    const file = path.join(FIXTURES, entry.path);
    if (!existsSync(file)) {
      parseFailures.push(`${entry.path} (missing)`);
      continue;
    }
    const source = readFileSync(file, "utf8");
    const report = analyzeInput(source, entry.name);
    if (report.inventory.kindNote && /could not|parse/i.test(report.inventory.kindNote) && report.findings.length === 0) {
      // A parse failure is not a detector miss — it is a corpus limitation, and
      // counting it as a false negative would flatter or punish the rules for
      // the parser's behaviour. Recorded separately.
      parseFailures.push(entry.path);
      continue;
    }
    parsed += 1;
    const expected = [...new Set(entry.vulnerabilities.map((v) => v.category))];
    const predicted = new Set(
      report.findings
        .filter((f) => !HYGIENE_DETECTORS.has(f.detector))
        .map((f) => smartbugsCategoryForDetector(f.detector)),
    );
    for (const f of report.findings) {
      detectorsFired.add(f.detector);
      const row = detectorFiles.get(f.detector) ?? { fired: 0, onExpectedCategory: 0 };
      row.fired += 1;
      if (expected.includes(smartbugsCategoryForDetector(f.detector))) row.onExpectedCategory += 1;
      detectorFiles.set(f.detector, row);
    }
    totalFindings += report.findings.length;
    if (report.findings.length > 0) filesWithFindings += 1;

    for (const c of expected) bump(expectedByCategory, c);
    for (const c of predicted) bump(predictedByCategory, c);
    for (const c of expected) {
      if (predicted.has(c)) bump(tp, c);
      else bump(fn, c);
    }
    for (const c of predicted) {
      if (!expected.includes(c)) bump(fp, c);
    }
  }

  const categories: CategoryScore[] = SMARTBUGS_CATEGORIES.map((meta) => {
    const t = tp.get(meta.id) ?? 0;
    const f = fn.get(meta.id) ?? 0;
    const p = fp.get(meta.id) ?? 0;
    return {
      category: meta.id,
      expected: expectedByCategory.get(meta.id) ?? 0,
      predicted: predictedByCategory.get(meta.id) ?? 0,
      truePositives: t,
      falseNegatives: f,
      falsePositives: p,
      recall: t + f === 0 ? 0 : round(t / (t + f)),
      precision: t + p === 0 ? 0 : round(t / (t + p)),
    };
  });

  return {
    files: entries.length,
    parsed,
    parseFailures,
    totalFindings,
    filesWithFindings,
    findingsPerFile: parsed === 0 ? 0 : round(totalFindings / parsed),
    categories,
    detectorsFired: [...detectorsFired].sort(),
    detectorsIdle: [],
    detectorFiles: Object.fromEntries([...detectorFiles.entries()].sort((a, b) => b[1].fired - a[1].fired)),
  };
}

function markdown(result: BenchmarkResult, previous?: BenchmarkResult): string {
  const lines: string[] = [];
  lines.push("# Detection benchmark — SmartBugs Curated");
  lines.push("");
  lines.push(
    `Generated by \`scripts/benchmark-smartbugs.ts\` over the vendored corpus in \`test/fixtures/smartbugs-curated\` (${result.files} annotated contracts, ${result.parsed} analysed, ${result.parseFailures.length} not analysed).`,
  );
  lines.push("");
  lines.push("File-level scoring: a category counts as predicted for a contract when any finding on it maps to that category. Precision therefore measures cross-category noise — a rule firing on a contract it was not expected to fire on costs precision and gains nothing.");
  lines.push("");
  lines.push(`Total findings: **${result.totalFindings}** across ${result.parsed} contracts (**${result.findingsPerFile}** per contract). ${result.filesWithFindings} contracts produced at least one finding.`);
  lines.push("");
  lines.push("| Category | Contracts | Predicted | TP | FN | FP | Recall | Precision |");
  lines.push("| --- | --- | --- | --- | --- | --- | --- | --- |");
  for (const c of result.categories) {
    const delta = previous?.categories.find((p) => p.category === c.category);
    const mark = (now: number, before?: number) =>
      before === undefined || now === before ? `${now}` : now > before ? `${now} ↑` : `${now} ↓`;
    lines.push(
      `| ${c.category} | ${c.expected} | ${c.predicted} | ${c.truePositives} | ${c.falseNegatives} | ${c.falsePositives} | ${mark(c.recall, delta?.recall)} | ${mark(c.precision, delta?.precision)} |`,
    );
  }
  lines.push("");
  lines.push("## Noise leaders");
  lines.push("");
  lines.push("Detectors that fired most often, and how often the contract they fired on was actually labelled with that detector's category. A low second number is a rule spending a reviewer's attention on the wrong contracts — the 47%-false-positive problem from the engagement, measured.");
  lines.push("");
  lines.push("| Detector | Files fired | On expected category | Signal rate |");
  lines.push("| --- | --- | --- | --- |");
  const leaders = Object.entries(result.detectorFiles)
    .filter(([, v]) => v.fired >= 3)
    .slice(0, 14);
  for (const [det, v] of leaders) {
    lines.push(`| \`${det}\` | ${v.fired} | ${v.onExpectedCategory} | ${(v.onExpectedCategory / v.fired).toFixed(2)} |`);
  }
  lines.push("");
  lines.push("## What this does and does not say");
  lines.push("");
  lines.push("- These are 2018-era contracts on Solidity 0.4.x/0.5.x. A detector that needs a modern construct (a Uniswap v4 hook, an EIP-7702 guard, a `latestRoundData` feed) cannot fire here; it is absent from the table rather than scored as a miss.");
  lines.push("- The dataset annotates *lines*; this analyzer reports *sites*. The join would measure whitespace normalisation, not detection, so scoring is file-level per category.");
  lines.push("- A category with zero expected contracts (`other`, mostly) has no recall to measure and shows 0.");
  lines.push("");
  return lines.join("\n");
}

function main() {
  const args = process.argv.slice(2);
  const write = args.includes("--write");
  const reportIdx = args.indexOf("--report");
  const reportPath = reportIdx >= 0 ? args[reportIdx + 1] : null;

  const previous: BenchmarkResult | undefined = existsSync(BASELINE)
    ? (JSON.parse(readFileSync(BASELINE, "utf8")) as BenchmarkResult)
    : undefined;

  const result = runBenchmark();

  for (const c of result.categories) {
    if (c.expected === 0 && c.predicted === 0) continue;
    console.log(
      `${c.category.padEnd(26)} expected ${String(c.expected).padStart(3)}  predicted ${String(c.predicted).padStart(3)}  recall ${c.recall.toFixed(3)}  precision ${c.precision.toFixed(3)}`,
    );
  }
  console.log(
    `\n${result.totalFindings} findings over ${result.parsed} contracts (${result.findingsPerFile}/contract); ${result.parseFailures.length} not analysed`,
  );

  if (reportPath) {
    writeFileSync(path.join(ROOT, reportPath), markdown(result, previous));
    console.log(`report -> ${reportPath}`);
  }

  if (write) {
    writeFileSync(BASELINE, `${JSON.stringify(result, null, 2)}\n`);
    console.log(`baseline -> ${path.relative(ROOT, BASELINE)}`);
    return;
  }

  if (!previous) {
    console.log("no baseline yet — run with --write to set one");
    return;
  }

  const regressions: string[] = [];
  for (const c of result.categories) {
    const p = previous.categories.find((x) => x.category === c.category);
    if (!p) continue;
    if (c.recall < p.recall) regressions.push(`${c.category}: recall ${p.recall} -> ${c.recall}`);
    if (c.precision < p.precision) regressions.push(`${c.category}: precision ${p.precision} -> ${c.precision}`);
  }
  if (result.findingsPerFile > previous.findingsPerFile) {
    regressions.push(
      `noise: ${previous.findingsPerFile} -> ${result.findingsPerFile} findings per contract`,
    );
  }
  if (regressions.length > 0) {
    console.error("\nBENCHMARK REGRESSION");
    for (const r of regressions) console.error(`  ${r}`);
    process.exit(1);
  }
  console.log("no regression against the committed baseline");
}

// Run only as an entry point. The NODE_TEST_CONTEXT check matters: under a
// bundler the module IS argv[1], so the path comparison alone runs main() from
// inside the test that imports runBenchmark — which then calls process.exit(1)
// and reports the whole test file as failed. `node --test` sets the env var, so
// the test import stays inert.
if (
  process.argv[1] &&
  path.resolve(process.argv[1]) === path.resolve(fileURLToPath(import.meta.url)) &&
  !process.env.NODE_TEST_CONTEXT
) {
  main();
}
