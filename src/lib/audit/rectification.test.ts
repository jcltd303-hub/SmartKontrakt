// src/lib/audit/rectification.test.ts
import assert from "node:assert/strict";
import test from "node:test";
import { readFile } from "node:fs/promises";
import { PGlite } from "@electric-sql/pglite";
import { createSqlClient } from "../sql-client.ts";
import { rectifiableCounts, rectifyFalsePositives } from "./rectification.server.ts";

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

test("rectification moves only FP-dispositioned findings of the named detector to info", async () => {
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
    const add = async (ord: number, detector: string, severity: string, disposition: string | null) => {
      const id = `s1:${ord}`;
      await pg.query(
        `insert into findings (id, scan_id, ord, severity, title, confidence, detector, summary, walkthrough)
         values ($1, 's1', $2, $3, 't', 'high', $4, 's', 'w')`,
        [id, ord, severity, detector],
      );
      if (disposition) {
        await pg.query(`insert into auditor_dispositions (finding_id, disposition) values ($1, $2)`, [id, disposition]);
      }
    };
    await add(0, "noisy", "critical", "false_positive"); // rectified
    await add(1, "noisy", "high", "false_positive"); // rectified
    await add(2, "noisy", "info", "false_positive"); // already info — not counted
    await add(3, "noisy", "critical", "confirmed"); // a real one — untouchable
    await add(4, "noisy", "critical", null); // no verdict — untouchable
    await add(5, "other", "critical", "false_positive"); // different class

    assert.deepEqual(await rectifiableCounts(sql), [
      { detector: "noisy", rectifiable: 2 },
      { detector: "other", rectifiable: 1 },
    ]);
    assert.equal(await rectifyFalsePositives(sql, "noisy"), 2);
    const severities = await pg.query<{ id: string; severity: string }>(
      `select id, severity from findings order by id`,
    );
    assert.deepEqual(
      severities.rows.map((r) => [r.id, r.severity]),
      [
        ["s1:0", "info"],
        ["s1:1", "info"],
        ["s1:2", "info"],
        ["s1:3", "critical"],
        ["s1:4", "critical"],
        ["s1:5", "critical"],
      ],
    );
    // Second run is a no-op; an empty detector name is refused.
    assert.equal(await rectifyFalsePositives(sql, "noisy"), 0);
    await assert.rejects(() => rectifyFalsePositives(sql, "  "), /detector name is required/);
  } finally {
    await pg.close();
  }
});
