// src/lib/audit/detector-scoreboard.test.ts
import assert from "node:assert/strict";
import test from "node:test";
import { readFile } from "node:fs/promises";
import { PGlite } from "@electric-sql/pglite";
import { createSqlClient } from "../sql-client.ts";
import {
  applyScoreboardDemotions,
  isDemotionFlagged,
  type DetectorStats,
} from "./detector-scoreboard.ts";
import { demotionMap, detectorScoreboard } from "./detector-scoreboard.server.ts";
import type { Finding, Report } from "./types.ts";

function finding(partial: Partial<Finding>): Finding {
  return {
    severity: "critical",
    swc: null,
    title: "t",
    confidence: "high",
    detector: "bridge-message-auth",
    summary: "s",
    walkthrough: "w",
    exploitSolidity: "",
    remediationSolidity: "",
    locationFn: "f",
    locationLine: 1,
    snippet: "",
    ...partial,
  } as Finding;
}

function report(findings: Finding[]): Report {
  return {
    label: "L",
    inputKind: "address",
    riskScore: 0,
    summary: "s",
    inventory: { notes: [] },
    findings,
    aiNarrative: null,
    aiStatus: "unavailable",
  } as unknown as Report;
}

const FLAGGED: DetectorStats = {
  detector: "bridge-message-auth",
  confirmed: 1,
  falsePositive: 24,
  needsMoreInfo: 0,
  dispositioned: 25,
  fpRate: 24 / 25,
};

test("the demotion bar: ≥20 dispositioned and ≥90% FP", () => {
  assert.equal(isDemotionFlagged(FLAGGED), true);
  assert.equal(isDemotionFlagged({ ...FLAGGED, dispositioned: 19, falsePositive: 19, fpRate: 1 }), false);
  assert.equal(isDemotionFlagged({ ...FLAGGED, fpRate: 0.89 }), false);
  assert.equal(isDemotionFlagged({ ...FLAGGED, dispositioned: 0, fpRate: 0 }), false);
});

test("demotion caps critical at high, drops high confidence, and explains itself", () => {
  const r = report([
    finding({}),
    finding({ severity: "high", confidence: "medium", locationFn: "g" }),
    finding({ detector: "reentrancy", locationFn: "h" }),
  ]);
  const stats = new Map([["bridge-message-auth", FLAGGED]]);
  assert.equal(applyScoreboardDemotions(r, stats), 2);
  assert.equal(r.findings[0]!.severity, "high");
  assert.equal(r.findings[0]!.confidence, "medium");
  assert.match(r.findings[0]!.confidenceBasis ?? "", /scoreboard demotion: bridge-message-auth is 96% false-positive over 25/);
  // High severity is not pushed lower; only the confidence moves when high.
  assert.equal(r.findings[1]!.severity, "high");
  assert.equal(r.findings[1]!.confidence, "medium");
  // Unflagged detectors are untouched.
  assert.equal(r.findings[2]!.severity, "critical");
  assert.equal(r.findings[2]!.confidenceBasis, undefined);
  // Idempotent: the persist seam can run over the fetcher's output safely.
  assert.equal(applyScoreboardDemotions(r, stats), 0);
});

const MIGRATIONS = [
  "0002_scans.sql",
  "0003_comprehensive_records_and_rag.sql",
  "0004_poc_results.sql",
  "0007_unparsed.sql",
  "0011_balance.sql",
  "0012_value_at_risk.sql",
  "0014_analyzer_version.sql",
  "0015_auditor_dispositions.sql",
];

test("the scoreboard aggregates dispositions per detector; demotionMap keeps only flagged classes", async () => {
  const pg = new PGlite();
  await pg.waitReady;
  try {
    for (const f of MIGRATIONS) {
      await pg.exec(await readFile(new URL(`../../../migrations/${f}`, import.meta.url), "utf8"));
    }
    const sql = createSqlClient(
      async <T>(text: string, params: unknown[]) => (await pg.query<T>(text, params)).rows,
      (work) => pg.transaction((tx) => work(async <T>(text: string, params: unknown[]) => (await tx.query<T>(text, params)).rows)),
    );
    await pg.query(
      `insert into contract_scans (id, label, input_kind, contract_name, summary, inventory_json, risk_score)
       values ('s1', 'L', 'address', 'C', 's', '{}', 0)`,
    );
    const add = async (ord: number, detector: string, disposition: string | null) => {
      const id = `s1:${ord}`;
      await pg.query(
        `insert into findings (id, scan_id, ord, severity, title, confidence, detector, summary, walkthrough)
         values ($1, 's1', $2, 'high', 't', 'high', $3, 's', 'w')`,
        [id, ord, detector],
      );
      if (disposition) {
        await pg.query(`insert into auditor_dispositions (finding_id, disposition) values ($1, $2)`, [id, disposition]);
      }
    };
    for (let i = 0; i < 22; i++) await add(i, "noisy-detector", "false_positive");
    await add(22, "noisy-detector", "confirmed");
    await add(23, "quiet-detector", "confirmed");
    await add(24, "quiet-detector", null); // undispositioned — invisible to the scoreboard

    const board = await detectorScoreboard(sql);
    const noisy = board.find((b) => b.detector === "noisy-detector")!;
    assert.equal(noisy.dispositioned, 23);
    assert.equal(noisy.falsePositive, 22);
    assert.ok(Math.abs(noisy.fpRate - 22 / 23) < 1e-9);
    const quiet = board.find((b) => b.detector === "quiet-detector")!;
    assert.equal(quiet.dispositioned, 1);

    const map = await demotionMap(sql);
    assert.equal(map.has("noisy-detector"), true);
    assert.equal(map.has("quiet-detector"), false);
  } finally {
    await pg.close();
  }
});
