// src/lib/audit/fp-signatures.server.test.ts
import assert from "node:assert/strict";
import test from "node:test";
import { readFile } from "node:fs/promises";
import { PGlite } from "@electric-sql/pglite";
import { createSqlClient } from "../sql-client.ts";
import { setDispositionRow } from "./dispositions.server.ts";
import {
  getConfirmedFpSignatureRows,
  listFpSignatureRows,
  refreshFpSignatures,
  setFpSignatureStatus,
} from "./fp-signatures.server.ts";
import { fpMatchForFinding } from "./fp-signatures.ts";

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
  "0016_finding_corroborated.sql",
  "0017_fp_signatures.sql",
];

const SNIPPET = "function harvest() public {\n  token.transfer(owner, token.balanceOf(address(this)));\n}";

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
  for (const scanId of ["scan-1", "scan-2", "scan-3"]) {
    await pg.query(
      `insert into contract_scans (id, label, input_kind, risk_score, summary, inventory_json)
       values ($1, 'Vault', 'source', 90, 'summary', '{}')`,
      [scanId],
    );
  }
  const finding = async (
    id: string,
    scanId: string,
    ord: number,
    over: { title?: string; locationFn?: string } = {},
  ) => {
    await pg.query(
      `insert into findings (id, scan_id, ord, severity, title, confidence, detector, summary, walkthrough, location_fn, snippet)
       values ($1, $2, $3, 'high', $4, 'medium', 'access-control', 's', 'w', $5, $6)`,
      [id, scanId, ord, over.title ?? "harvest sends tokens with no access check", over.locationFn ?? "harvest", SNIPPET],
    );
  };
  // The harvest shape: FP-disposed on scan-1 (twice) and scan-2 (once).
  await finding("scan-1:3", "scan-1", 3);
  await finding("scan-1:4", "scan-1", 4);
  await finding("scan-2:1", "scan-2", 1);
  // Same shape on scan-3, disposed only later in the dismissal test.
  await finding("scan-3:0", "scan-3", 0);
  // A lone different shape (claim, one scan) — never enough evidence.
  await finding("scan-1:5", "scan-1", 5, { title: "claim sends tokens with no access check", locationFn: "claim" });
  // Same harvest shape but disposed CONFIRMED — must not count as FP evidence.
  await finding("scan-2:2", "scan-2", 2);

  await setDispositionRow(sql, { findingId: "scan-1:3", disposition: "false_positive" });
  await setDispositionRow(sql, { findingId: "scan-1:4", disposition: "false_positive" });
  await setDispositionRow(sql, { findingId: "scan-2:1", disposition: "false_positive" });
  await setDispositionRow(sql, { findingId: "scan-1:5", disposition: "false_positive" });
  await setDispositionRow(sql, { findingId: "scan-2:2", disposition: "confirmed" });
  return { pg, sql };
}

test("refresh derives one candidate from FP dispositions only, across distinct scans", async () => {
  const { pg, sql } = await database();
  try {
    const rows = await refreshFpSignatures(sql);
    assert.equal(rows.length, 1);
    const [sig] = rows;
    assert.equal(sig.status, "candidate");
    assert.equal(sig.detector, "access-control");
    assert.equal(sig.titlePattern, "* sends tokens with no access check");
    assert.equal(sig.locationFn, "harvest");
    assert.equal(sig.snippetClass, "source");
    // 3 FP rows (the confirmed-disposed twin contributes nothing),
    // spanning exactly 2 distinct scans.
    assert.equal(sig.evidenceCount, 3);
    assert.equal(sig.scanCount, 2);
    assert.equal(sig.decidedAt, null);
    assert.deepEqual(sig.sampleTitles, ["harvest sends tokens with no access check"]);

    // Refresh is idempotent: same single row, still a candidate.
    const again = await refreshFpSignatures(sql);
    assert.equal(again.length, 1);
    assert.equal(again[0].key, sig.key);
    assert.equal(again[0].createdAt, sig.createdAt);
  } finally {
    await pg.close();
  }
});

test("confirm persists, and the confirmed signature annotates a matching finding", async () => {
  const { pg, sql } = await database();
  try {
    const [candidate] = await refreshFpSignatures(sql);
    const decided = await setFpSignatureStatus(sql, { signatureKey: candidate.key, status: "confirmed" });
    assert.equal(decided.status, "confirmed");
    assert.ok(decided.decidedAt);

    const confirmed = await getConfirmedFpSignatureRows(sql);
    assert.equal(confirmed.length, 1);
    assert.equal(confirmed[0].key, candidate.key);

    const match = fpMatchForFinding(
      {
        detector: "access-control",
        title: "harvest sends tokens with no access check",
        locationFn: "harvest",
        snippet: SNIPPET,
      },
      confirmed,
    );
    assert.equal(match?.signatureKey, candidate.key);

    const listed = await listFpSignatureRows(sql);
    assert.equal(listed[0].status, "confirmed");
  } finally {
    await pg.close();
  }
});

test("a dismissed signature is never re-proposed, even as its evidence grows", async () => {
  const { pg, sql } = await database();
  try {
    const [candidate] = await refreshFpSignatures(sql);
    await setFpSignatureStatus(sql, { signatureKey: candidate.key, status: "dismissed" });

    // A third scan's FP lands — the pattern's evidence grows to 4/3.
    await setDispositionRow(sql, { findingId: "scan-3:0", disposition: "false_positive" });
    const rows = await refreshFpSignatures(sql);
    assert.equal(rows.length, 1);
    assert.equal(rows[0].status, "dismissed");
    assert.equal(rows[0].evidenceCount, 4);
    assert.equal(rows[0].scanCount, 3);
    assert.deepEqual(await getConfirmedFpSignatureRows(sql), []);
  } finally {
    await pg.close();
  }
});

test("a candidate whose evidence evaporates is removed; decisions survive a re-decide", async () => {
  const { pg, sql } = await database();
  try {
    const [candidate] = await refreshFpSignatures(sql);
    // Re-deciding is the human's prerogative: confirm, then dismiss.
    await setFpSignatureStatus(sql, { signatureKey: candidate.key, status: "confirmed" });
    const flipped = await setFpSignatureStatus(sql, { signatureKey: candidate.key, status: "dismissed" });
    assert.equal(flipped.status, "dismissed");

    // Now the evidence evaporates — but a DECIDED row is kept.
    await setDispositionRow(sql, { findingId: "scan-2:1", disposition: "confirmed" });
    const rows = await refreshFpSignatures(sql);
    assert.equal(rows.length, 1);
    assert.equal(rows[0].status, "dismissed");
  } finally {
    await pg.close();
  }
});

test("an undecided candidate is deleted when its dispositions are withdrawn", async () => {
  const { pg, sql } = await database();
  try {
    await refreshFpSignatures(sql);
    // Dropping scan-2's FP leaves the shape on one scan only.
    await setDispositionRow(sql, { findingId: "scan-2:1", disposition: "needs_more_info" });
    assert.deepEqual(await refreshFpSignatures(sql), []);
  } finally {
    await pg.close();
  }
});

test("unknown keys and non-decisions are refused", async () => {
  const { pg, sql } = await database();
  try {
    const [candidate] = await refreshFpSignatures(sql);
    await assert.rejects(
      setFpSignatureStatus(sql, { signatureKey: "no-such-key", status: "confirmed" }),
      /No FP signature exists/,
    );
    await assert.rejects(
      // @ts-expect-error deliberately invalid decision value
      setFpSignatureStatus(sql, { signatureKey: candidate.key, status: "candidate" }),
      /Unknown FP signature decision/,
    );
    // The refusals wrote nothing.
    const rows = await listFpSignatureRows(sql);
    assert.equal(rows.length, 1);
    assert.equal(rows[0].status, "candidate");
  } finally {
    await pg.close();
  }
});
