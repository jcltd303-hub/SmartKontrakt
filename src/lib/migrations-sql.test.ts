import test from "node:test";
import assert from "node:assert/strict";
import { EMBEDDED_MIGRATIONS } from "./migrations-sql.ts";

test("embedded migrations include both archive migrations", () => {
  assert.deepEqual(Object.keys(EMBEDDED_MIGRATIONS).sort(), [
    "0002_scans.sql",
    "0003_comprehensive_records_and_rag.sql",
    "0004_poc_results.sql",
    "0005_fourbyte.sql",
    "0006_fourbyte_events.sql",
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

test("embedded 0004 adds PoC result columns to contract_scans", () => {
  const sql = EMBEDDED_MIGRATIONS["0004_poc_results.sql"];
  assert.match(sql, /alter table contract_scans add column if not exists poc_status/i);
  assert.match(sql, /alter table contract_scans add column if not exists poc_logs/i);
  assert.match(sql, /alter table contract_scans add column if not exists poc_duration_ms/i);
  assert.match(sql, /alter table contract_scans add column if not exists poc_run_at/i);
});

test("embedded 0005 creates fourbyte_signatures keyed by (selector, signature)", () => {
  const sql = EMBEDDED_MIGRATIONS["0005_fourbyte.sql"];
  assert.match(sql, /create table if not exists fourbyte_signatures/i);
  assert.match(sql, /primary key \(selector, signature\)/i);
});

test("embedded 0006 creates fourbyte_event_signatures keyed by (topic, signature)", () => {
  const sql = EMBEDDED_MIGRATIONS["0006_fourbyte_events.sql"];
  assert.match(sql, /create table if not exists fourbyte_event_signatures/i);
  assert.match(sql, /primary key \(topic, signature\)/i);
});
