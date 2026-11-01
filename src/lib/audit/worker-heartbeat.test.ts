// src/lib/audit/worker-heartbeat.test.ts
import assert from "node:assert/strict";
import test from "node:test";
import { readFile } from "node:fs/promises";
import { PGlite } from "@electric-sql/pglite";
import { createSqlClient } from "../sql-client.ts";
import {
  judgeWorkerStaleness,
  listWorkerHeartbeats,
  recordWorkerHeartbeat,
} from "./worker-heartbeat.server.ts";
import { archiveAnalyzerCensus, newestArchiveBaseline } from "./scan-freshness.server.ts";

const MIGRATIONS = [
  "0002_scans.sql",
  "0003_comprehensive_records_and_rag.sql",
  "0004_poc_results.sql",
  "0007_unparsed.sql",
  "0011_balance.sql",
  "0012_value_at_risk.sql",
  "0014_analyzer_version.sql",
  "0020_worker_heartbeats.sql",
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
  return { pg, sql };
}

test("heartbeat upserts one row per worker and refreshes state", async () => {
  const { pg, sql } = await database();
  try {
    await recordWorkerHeartbeat(sql, { workerId: "phone", analyzerVersion: "2026-11-01.18+abc", state: "idle" });
    await recordWorkerHeartbeat(sql, { workerId: "phone", analyzerVersion: "2026-11-01.18+abc", state: "running", note: "run started" });
    await recordWorkerHeartbeat(sql, { workerId: "laptop", analyzerVersion: "2026-11-01.16+def", state: "idle" });
    const rows = await listWorkerHeartbeats(sql);
    assert.equal(rows.length, 2);
    const phone = rows.find((r) => r.workerId === "phone")!;
    assert.equal(phone.state, "running");
    assert.equal(phone.note, "run started");
    await assert.rejects(
      () => recordWorkerHeartbeat(sql, { workerId: "  ", analyzerVersion: "x", state: "idle" }),
      /worker id is required/,
    );
  } finally {
    await pg.close();
  }
});

test("staleness judges a worker's baseline against the current stamp", async () => {
  const { pg, sql } = await database();
  try {
    await recordWorkerHeartbeat(sql, { workerId: "old", analyzerVersion: "2026-10-31.16+aaa", state: "idle" });
    await recordWorkerHeartbeat(sql, { workerId: "new", analyzerVersion: "2026-11-01.18+bbb", state: "idle" });
    const judged = judgeWorkerStaleness(await listWorkerHeartbeats(sql), "2026-11-01.18+ccc");
    assert.equal(judged.find((j) => j.workerId === "old")!.stale, true);
    assert.equal(judged.find((j) => j.workerId === "old")!.baseline, "2026-10-31.16");
    assert.equal(judged.find((j) => j.workerId === "new")!.stale, false);
  } finally {
    await pg.close();
  }
});

test("the archive census reports per-baseline counts and the newest baseline", async () => {
  const { pg, sql } = await database();
  try {
    const insert = async (id: string, version: string | null) => {
      await pg.query(
        `insert into contract_scans (id, label, input_kind, contract_name, summary, inventory_json, risk_score, analyzer_version)
         values ($1, 'L', 'address', 'C', 's', '{}', 0, $2)`,
        [id, version],
      );
    };
    await insert("a", "2026-10-31.16+aaa");
    await insert("b", "2026-10-31.16+bbb");
    await insert("c", "2026-11-01.18+ccc");
    await insert("d", null);
    const census = await archiveAnalyzerCensus(sql);
    assert.deepEqual(
      census.map((c) => [c.baseline, c.scans]),
      [
        ["2026-10-31.16", 2],
        ["2026-11-01.18", 1],
      ],
    );
    assert.equal(await newestArchiveBaseline(sql), "2026-11-01.18");
  } finally {
    await pg.close();
  }
});
