import assert from "node:assert/strict";
import test from "node:test";
import { readFile } from "node:fs/promises";
import { PGlite } from "@electric-sql/pglite";
import { createSqlClient } from "../sql-client.ts";
import { writeAuditBatch } from "./bulk-persist.server.ts";

import { record } from "../../../scripts/audit-fixture.ts";

async function database() {
  const pg = new PGlite();
  await pg.waitReady;
  for (const f of ["0002_scans.sql", "0003_comprehensive_records_and_rag.sql"]) {
    await pg.exec(await readFile(new URL(`../../../migrations/${f}`, import.meta.url), "utf8"));
  }
  let queries = 0;
  const sql = createSqlClient(
    async <T>(text: string, params: unknown[]) => { queries++; return (await pg.query<T>(text, params)).rows; },
    (work) => pg.transaction((tx) => work(async <T>(text: string, params: unknown[]) => {
      queries++; return (await tx.query<T>(text, params)).rows;
    })),
  );
  return { pg, sql, queryCount: () => queries };
}

test("bulk writes replace dossiers atomically and replay without duplicate RAG chunks", async () => {
  const { pg, sql, queryCount } = await database();
  try {
    const items = [record("one"), record("two")];
    await writeAuditBatch(sql, items);
    assert.ok(queryCount() <= 6, "one bulk statement per table, independent of row count");
    await writeAuditBatch(sql, items);
    assert.equal((await pg.query<{ n: number }>("select count(*)::int as n from contract_scans")).rows[0].n, 2);
    assert.equal((await pg.query<{ n: number }>("select count(*)::int as n from findings")).rows[0].n, 4);
    assert.equal((await pg.query<{ n: number }>("select count(*)::int as n from rag_knowledge_chunks")).rows[0].n, 6);
    items[0].report.findings = [];
    await writeAuditBatch(sql, [items[0]]);
    assert.equal((await pg.query<{ n: number }>("select count(*)::int as n from findings where scan_id='one'")).rows[0].n, 0);
    assert.equal((await pg.query<{ n: number }>("select count(*)::int as n from rag_knowledge_chunks where scan_id='one'")).rows[0].n, 1);
    items[0].indexToRag = false;
    await writeAuditBatch(sql, [items[0]]);
    assert.equal((await pg.query<{ n: number }>("select count(*)::int as n from rag_knowledge_chunks where scan_id='one'")).rows[0].n, 0);
  } finally { await pg.close(); }
});

test("a late findings error rolls back headers, payloads and all previous rows", async () => {
  const { pg, sql } = await database();
  try {
    await pg.exec("alter table findings add constraint test_reject check (title <> 'reject')");
    const bad = record("bad");
    bad.report.findings[1].title = "reject";
    await assert.rejects(writeAuditBatch(sql, [record("good"), bad]), /test_reject/);
    assert.equal((await pg.query<{ n: number }>("select count(*)::int as n from contract_scans")).rows[0].n, 0);
    assert.equal((await pg.query<{ n: number }>("select count(*)::int as n from scan_payloads")).rows[0].n, 0);
  } finally { await pg.close(); }
});
