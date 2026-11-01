// src/lib/audit/code-reuse.test.ts
import assert from "node:assert/strict";
import test from "node:test";
import { readFile } from "node:fs/promises";
import { PGlite } from "@electric-sql/pglite";
import { createSqlClient } from "../sql-client.ts";
import {
  codeHashOf,
  findSiblingScan,
  inheritDispositionsForScans,
} from "./code-reuse.server.ts";

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
  "0021_codehash.sql",
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

const CODE_A = "0x6080604052348015600e575f5ffd5b50606380601a5f395ff3fe60806040525f5ffd";
const CODE_B = "0x6080604052348015600e575f5ffd5b50606380601a5f395ff3fe60806040525f5ffe";

async function insertScan(
  pg: PGlite,
  opts: { id: string; address: string; body: string; codehash?: string | null; chain?: string },
) {
  await pg.query(
    `insert into contract_scans (id, label, input_kind, contract_name, target_address, chain_id, summary, inventory_json, risk_score, codehash)
     values ($1, 'L', 'address', 'C', $2, $3, 's', '{}', 0, $4)`,
    [opts.id, opts.address, opts.chain ?? "ethereum", opts.codehash ?? null],
  );
  await pg.query(`insert into scan_payloads (scan_id, body) values ($1, $2)`, [opts.id, opts.body]);
}

async function insertFinding(
  pg: PGlite,
  opts: { scanId: string; ord: number; detector: string; fn: string; disposition?: string },
) {
  const id = `${opts.scanId}:${opts.ord}`;
  await pg.query(
    `insert into findings (id, scan_id, ord, severity, title, confidence, detector, summary, walkthrough, location_fn)
     values ($1, $2, $3, 'high', 't', 'high', $4, 's', 'w', $5)`,
    [id, opts.scanId, opts.ord, opts.detector, opts.fn],
  );
  if (opts.disposition) {
    await pg.query(
      `insert into auditor_dispositions (finding_id, disposition, note) values ($1, $2, 'human verdict')`,
      [id, opts.disposition],
    );
  }
  return id;
}

test("codeHashOf is keccak256 over the raw code bytes", () => {
  // Canonical vectors: keccak256("") and keccak256(0x00).
  assert.equal(codeHashOf("0x"), null); // no code — no siblings
  assert.equal(codeHashOf(""), null);
  assert.equal(codeHashOf(null), null);
  assert.equal(codeHashOf("not hex"), null);
  assert.equal(codeHashOf("0x0"), null); // odd-length hex is not code
  assert.equal(
    codeHashOf("0x00"),
    "0xbc36789e7a1e281436464229828f817d6612f7b477d66591ff96a9e064bcc98a",
  );
  // Prefix and case do not change the hash.
  assert.equal(codeHashOf(CODE_A.slice(2)), codeHashOf(CODE_A));
  assert.equal(codeHashOf(CODE_A.toUpperCase().replace("0X", "0x")), codeHashOf(CODE_A));
  assert.notEqual(codeHashOf(CODE_A), codeHashOf(CODE_B));
});

test("findSiblingScan matches on the persisted codehash, excluding the item itself", async () => {
  const { pg, sql } = await database();
  try {
    const hash = codeHashOf(CODE_A)!;
    await insertScan(pg, { id: "sib", address: "0xAAA", body: "contract C {}", codehash: hash });
    await insertScan(pg, { id: "other", address: "0xBBB", body: "0x00", codehash: codeHashOf(CODE_B) });
    const sib = await findSiblingScan(sql, "ethereum", hash, "0xCCC");
    assert.equal(sib?.scanId, "sib");
    assert.equal(sib?.body, "contract C {}");
    // The item's own earlier scan is not its sibling.
    assert.equal(await findSiblingScan(sql, "ethereum", hash, "0xAAA"), null);
    // Another chain is another world.
    assert.equal(await findSiblingScan(sql, "bsc", hash, "0xCCC"), null);
  } finally {
    await pg.close();
  }
});

test("findSiblingScan falls back to hashing stored bytecode bodies for pre-0021 rows", async () => {
  const { pg, sql } = await database();
  try {
    await insertScan(pg, { id: "legacy", address: "0xAAA", body: CODE_A, codehash: null });
    await insertScan(pg, { id: "legacy-src", address: "0xBBB", body: "contract D {}", codehash: null });
    const sib = await findSiblingScan(sql, "ethereum", codeHashOf(CODE_A)!, "0xCCC");
    assert.equal(sib?.scanId, "legacy");
    assert.equal(await findSiblingScan(sql, "ethereum", codeHashOf(CODE_B)!, "0xCCC"), null);
  } finally {
    await pg.close();
  }
});

test("inheritDispositionsForScans copies verdicts onto matching findings of a clone", async () => {
  const { pg, sql } = await database();
  try {
    const hash = codeHashOf(CODE_A)!;
    await insertScan(pg, { id: "sib", address: "0xAAA", body: "src", codehash: hash });
    await insertFinding(pg, { scanId: "sib", ord: 0, detector: "reentrancy", fn: "withdraw", disposition: "false_positive" });
    await insertFinding(pg, { scanId: "sib", ord: 1, detector: "tx-origin", fn: "claim", disposition: "confirmed" });
    await insertFinding(pg, { scanId: "sib", ord: 2, detector: "oracle-spot", fn: "poke" }); // no verdict — nothing to inherit

    await insertScan(pg, { id: "clone", address: "0xCCC", body: "src", codehash: hash });
    const f0 = await insertFinding(pg, { scanId: "clone", ord: 0, detector: "reentrancy", fn: "withdraw" });
    const f1 = await insertFinding(pg, { scanId: "clone", ord: 1, detector: "tx-origin", fn: "claim" });
    const f2 = await insertFinding(pg, { scanId: "clone", ord: 2, detector: "oracle-spot", fn: "poke" });
    // One finding already carries the auditor's own word — never overwritten.
    const f3 = await insertFinding(pg, { scanId: "clone", ord: 3, detector: "reentrancy", fn: "withdraw", disposition: "needs_more_info" });

    const inherited = await inheritDispositionsForScans(sql, ["clone"]);
    assert.equal(inherited, 2);
    const rows = await pg.query<{ finding_id: string; disposition: string; note: string }>(
      `select finding_id, disposition, note from auditor_dispositions where finding_id = any($1) order by finding_id`,
      [[f0, f1, f2, f3]],
    );
    const byId = new Map(rows.rows.map((r) => [r.finding_id, r]));
    assert.equal(byId.get(f0)?.disposition, "false_positive");
    assert.match(byId.get(f0)?.note ?? "", /inherited from 0xAAA/);
    assert.equal(byId.get(f1)?.disposition, "confirmed");
    assert.equal(byId.has(f2), false);
    assert.equal(byId.get(f3)?.disposition, "needs_more_info");
    assert.equal(byId.get(f3)?.note, "human verdict");
    // A scan without a codehash inherits nothing.
    await insertScan(pg, { id: "nocode", address: "0xDDD", body: "src", codehash: null });
    assert.equal(await inheritDispositionsForScans(sql, ["nocode"]), 0);
    assert.equal(await inheritDispositionsForScans(sql, []), 0);
  } finally {
    await pg.close();
  }
});
