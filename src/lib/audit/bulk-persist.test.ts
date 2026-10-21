import assert from "node:assert/strict";
import test from "node:test";
import { readFile } from "node:fs/promises";
import { PGlite } from "@electric-sql/pglite";
import { createSqlClient } from "../sql-client.ts";
import { writeAuditBatch } from "./bulk-persist.server.ts";
import { savedScanVersions, scanFreshness } from "./persist.server.ts";
import { analyzerStamp } from "./analyzer-version.ts";

import { record } from "../../../scripts/audit-fixture.ts";

async function database() {
  const pg = new PGlite();
  await pg.waitReady;
  for (const f of [
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
  ]) {
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



test("bulk saves preserve SmartPoC evidence and its run history on replay", async () => {
  const {pg,sql} = await database();
  try {
    const item = record("proof");
    Object.assign(item.report.findings[0], {pocStatus:"passed",pocOutput:"[SmartPoC | Foundry] tests=1",pocCode:"executed",pocDurationMs:3,pocRunAt:"2026-10-20T00:00:00Z"});
    await writeAuditBatch(sql,[item]);
    assert.equal((await pg.query<{poc_status:string}>("select poc_status from findings where id='proof:0'")).rows[0].poc_status,"passed");
    await pg.exec("insert into finding_poc_runs(id,finding_id,scan_id,status,source,output) values('run','proof:0','proof','passed','executed','logs')");
    delete item.report.findings[0].pocStatus;
    delete item.report.findings[0].pocOutput;
    await writeAuditBatch(sql,[item]);
    assert.equal((await pg.query<{poc_status:string}>("select poc_status from findings where id='proof:0'")).rows[0].poc_status,"passed");
    assert.equal((await pg.query<{n:number}>("select count(*)::int as n from finding_poc_runs")).rows[0].n,1);
  } finally {await pg.close();}
});

test("a PoC run is identified by (finding, source digest) — replays upsert instead of appending", async () => {
  const { pg, sql } = await database();
  try {
    await writeAuditBatch(sql, [record("idem")]); // scan 'idem' + finding 'idem:0'
    const digest = "d".repeat(64);
    await pg.exec(
      `insert into finding_poc_runs(id,finding_id,scan_id,status,source,source_digest,output) values('r1','idem:0','idem','failed','src','${digest}','first')`,
    );
    // The identity index rejects a second row for the same (finding, digest).
    await assert.rejects(
      pg.exec(
        `insert into finding_poc_runs(id,finding_id,scan_id,status,source,source_digest,output) values('r2','idem:0','idem','passed','src','${digest}','second')`,
      ),
      /duplicate key|unique/i,
    );
    // The upsert path saveFindingPocResult uses updates the existing row in place.
    await pg.exec(
      `insert into finding_poc_runs(id,finding_id,scan_id,status,source,source_digest,output) values('r1','idem:0','idem','passed','src','${digest}','updated') on conflict (id) do update set status=excluded.status, output=excluded.output`,
    );
    const row = (await pg.query<{ n: number; status: string; output: string }>(
      "select count(*)::int as n, max(status) as status, max(output) as output from finding_poc_runs",
    )).rows[0];
    assert.equal(row.n, 1, "a replay must not append a duplicate run");
    assert.equal(row.status, "passed");
    assert.equal(row.output, "updated");
  } finally { await pg.close(); }
});


test("records carry the analyzer stamp, and resume re-analyzes only the stale ones", async () => {
  const { pg, sql } = await database();
  try {
    const fresh = record("fresh");
    fresh.targetAddress = "0x00000000000000000000000000000000000000a1";
    const stale = record("stale");
    stale.targetAddress = "0x00000000000000000000000000000000000000b2";
    await writeAuditBatch(sql, [fresh, stale]);

    // Every saved row is stamped with the analyzer that produced it.
    const stamped = (await pg.query<{ id: string; v: string | null }>(
      "select id, analyzer_version as v from contract_scans order by id",
    )).rows;
    assert.deepEqual(
      stamped.map((r) => [r.id, r.v]),
      [["fresh", analyzerStamp()], ["stale", analyzerStamp()]],
    );

    // Now pretend one of them was produced by an older analyzer.
    await pg.exec(
      "update contract_scans set analyzer_version = '2020-01-01.0+0000000000000000' where id = 'stale'",
    );

    const { current, stale: staleKeys } = await savedScanVersions(
      [
        { chainId: "ethereum", address: fresh.targetAddress! },
        { chainId: "ethereum", address: stale.targetAddress! },
        { chainId: "ethereum", address: "0x00000000000000000000000000000000000000c3" },
      ],
      analyzerStamp(),
      sql,
    );
    assert.ok(current.has(`ethereum:${fresh.targetAddress}`), "a current row is skipped");
    assert.ok(!current.has(`ethereum:${stale.targetAddress}`));
    assert.ok(staleKeys.has(`ethereum:${stale.targetAddress}`), "an older row is re-analyzed");
    assert.ok(
      !staleKeys.has("ethereum:0x00000000000000000000000000000000000000c3"),
      "an address that was never saved is neither current nor stale",
    );

    // A key with ANY current row is current, whatever else the archive holds —
    // the archive can hold several scans of one address.
    const again = record("fresh2");
    again.targetAddress = fresh.targetAddress;
    await writeAuditBatch(sql, [again]);
    await pg.exec(
      "update contract_scans set analyzer_version = '2020-01-01.0+0000000000000000' where id = 'fresh'",
    );
    const mixed = await savedScanVersions(
      [{ chainId: "ethereum", address: fresh.targetAddress! }],
      analyzerStamp(),
      sql,
    );
    assert.ok(mixed.current.has(`ethereum:${fresh.targetAddress}`));
    assert.ok(!mixed.stale.has(`ethereum:${fresh.targetAddress}`), "one current row is enough");

    const counts = await scanFreshness(sql);
    assert.equal(counts.total, 3);
    assert.equal(counts.current, 2);
    assert.equal(counts.stale, 1);
  } finally { await pg.close(); }
});
