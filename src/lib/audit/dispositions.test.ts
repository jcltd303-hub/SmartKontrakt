// src/lib/audit/dispositions.test.ts
import assert from "node:assert/strict";
import test from "node:test";
import { readFile } from "node:fs/promises";
import { PGlite } from "@electric-sql/pglite";
import { createSqlClient } from "../sql-client.ts";
import {
  dispositionsByFindingId,
  getDispositionRowsForFindings,
  getDispositionRowsForScan,
  setDispositionRow,
} from "./dispositions.server.ts";

const MIGRATIONS = [
  "0002_scans.sql",
  "0003_comprehensive_records_and_rag.sql",
  "0004_poc_results.sql",
  "0005_fourbyte.sql",
  "0006_fourbyte_events.sql",
  "0007_unparsed.sql",
  "0008_finding_poc_runs.sql",
  "0009_rag_fts.sql",
  "0010_indexes.sql",
  "0011_balance.sql",
  "0012_value_at_risk.sql",
  "0013_poc_run_idempotency.sql",
  "0014_analyzer_version.sql",
  "0015_auditor_dispositions.sql",
];

async function database() {
  const pg = new PGlite();
  await pg.waitReady;
  for (const f of MIGRATIONS) {
    await pg.exec(await readFile(new URL(`../../../migrations/${f}`, import.meta.url), "utf8"));
  }
  const sql = createSqlClient(
    async <T>(text: string, params: unknown[]) => (await pg.query<T>(text, params)).rows,
    (work) => pg.transaction((tx) => work(async <T>(text: string, params: unknown[]) => (await tx.query<T>(text, params)).rows)),
  );
  // One scan with two findings (canonical `${scanId}:${ord}` ids).
  await pg.query(
    `insert into contract_scans (id, label, input_kind, risk_score, summary, inventory_json)
     values ('scan-1', 'Vault', 'source', 90, 'summary', '{}')`,
  );
  await pg.query(
    `insert into findings (id, scan_id, ord, severity, title, confidence, detector, summary, walkthrough)
     values ('scan-1:0', 'scan-1', 0, 'critical', 'Reentrant withdraw', 'high', 'reentrancy', 's', 'w'),
            ('scan-1:1', 'scan-1', 1, 'high', 'Missing access control', 'medium', 'access-control', 's', 'w')`,
  );
  return { pg, sql };
}

const count = async (pg: PGlite) =>
  (await pg.query<{ n: number }>("select count(*)::int as n from auditor_dispositions")).rows[0].n;

test("set → get round-trips by scan and by finding ids", async () => {
  const { pg, sql } = await database();
  try {
    const written = await setDispositionRow(sql, { findingId: "scan-1:0", disposition: "confirmed", note: "Reproduced on fork" });
    assert.equal(written.findingId, "scan-1:0");
    assert.equal(written.disposition, "confirmed");
    assert.equal(written.note, "Reproduced on fork");
    assert.ok(written.updatedAt);

    const byScan = await getDispositionRowsForScan(sql, "scan-1");
    assert.equal(byScan.length, 1);
    assert.equal(byScan[0].findingId, "scan-1:0");

    const byIds = await getDispositionRowsForFindings(sql, ["scan-1:0", "scan-1:1"]);
    assert.equal(byIds.length, 1);

    const map = dispositionsByFindingId(byScan);
    assert.equal(map["scan-1:0"].disposition, "confirmed");
    assert.equal(map["scan-1:1"], undefined);
  } finally {
    await pg.close();
  }
});

test("re-setting the same disposition + note is a true no-op (row and updated_at unmoved)", async () => {
  const { pg, sql } = await database();
  try {
    const first = await setDispositionRow(sql, { findingId: "scan-1:0", disposition: "false_positive", note: "guarded" });
    await new Promise((r) => setTimeout(r, 20));
    const again = await setDispositionRow(sql, { findingId: "scan-1:0", disposition: "false_positive", note: "guarded" });
    assert.equal(await count(pg), 1);
    assert.equal(again.updatedAt, first.updatedAt);
    assert.deepEqual(again, first);
  } finally {
    await pg.close();
  }
});

test("changing the disposition or the note updates the single row", async () => {
  const { pg, sql } = await database();
  try {
    const first = await setDispositionRow(sql, { findingId: "scan-1:0", disposition: "needs_more_info" });
    assert.equal(first.note, null);
    await new Promise((r) => setTimeout(r, 20));
    const changed = await setDispositionRow(sql, { findingId: "scan-1:0", disposition: "confirmed", note: "ran it" });
    assert.equal(await count(pg), 1);
    assert.equal(changed.disposition, "confirmed");
    assert.equal(changed.note, "ran it");
    assert.ok(changed.updatedAt >= first.updatedAt);

    // Same disposition, different note: still an update, not a no-op.
    const noted = await setDispositionRow(sql, { findingId: "scan-1:0", disposition: "confirmed", note: "ran it twice" });
    assert.equal(await count(pg), 1);
    assert.equal(noted.note, "ran it twice");
  } finally {
    await pg.close();
  }
});

test("blank notes normalize to null; an unknown disposition is refused", async () => {
  const { pg, sql } = await database();
  try {
    const written = await setDispositionRow(sql, { findingId: "scan-1:1", disposition: "needs_more_info", note: "   " });
    assert.equal(written.note, null);
    await assert.rejects(
      // @ts-expect-error deliberately invalid vocabulary value
      setDispositionRow(sql, { findingId: "scan-1:1", disposition: "bogus" }),
      /Unknown auditor disposition/,
    );
    assert.equal(await count(pg), 1);
  } finally {
    await pg.close();
  }
});

test("empty lookups stay empty, and deleting the scan cascades the disposition away", async () => {
  const { pg, sql } = await database();
  try {
    assert.deepEqual(await getDispositionRowsForScan(sql, "no-such-scan"), []);
    assert.deepEqual(await getDispositionRowsForFindings(sql, []), []);
    await setDispositionRow(sql, { findingId: "scan-1:0", disposition: "confirmed" });
    assert.equal(await count(pg), 1);
    await pg.query("delete from contract_scans where id = 'scan-1'");
    assert.equal(await count(pg), 0);
  } finally {
    await pg.close();
  }
});
