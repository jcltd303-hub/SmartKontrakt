import test from "node:test";
import assert from "node:assert/strict";
import { EMBEDDED_MIGRATIONS } from "./migrations-sql.ts";

test("embedded migrations include both archive migrations", () => {
  assert.deepEqual(Object.keys(EMBEDDED_MIGRATIONS).sort(), [
    "0002_scans.sql",
    "0003_comprehensive_records_and_rag.sql",
  ]);
});

test("embedded 0002 creates contract_scans, scan_payloads, and findings", () => {
  const sql = EMBEDDED_MIGRATIONS["0002_scans.sql"];
  assert.match(sql, /create table if not exists contract_scans/i);
  assert.match(sql, /create table if not exists scan_payloads/i);
  assert.match(sql, /create table if not exists findings/i);
});

test("embedded 0003 extends contract_scans and adds rag_knowledge_chunks", () => {
  const sql = EMBEDDED_MIGRATIONS["0003_comprehensive_records_and_rag.sql"];
  assert.match(sql, /alter table contract_scans add column if not exists/i);
  assert.match(sql, /create table if not exists rag_knowledge_chunks/i);
});
