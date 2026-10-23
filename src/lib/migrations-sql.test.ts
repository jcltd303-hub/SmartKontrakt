import test from "node:test";
import assert from "node:assert/strict";
import { EMBEDDED_MIGRATIONS } from "./migrations-sql.ts";

test("embedded migrations match the files shipped for deployment", async () => {
  const { readdir, readFile } = await import("node:fs/promises");
  const directory = new URL("../../migrations/", import.meta.url);
  const names = (await readdir(directory)).filter(name => /^\d+.*\.sql$/.test(name)).sort();
  assert.deepEqual(Object.keys(EMBEDDED_MIGRATIONS).sort(), names);
  for (const name of names) {
    const disk = await readFile(new URL(name, directory), "utf8");
    assert.equal(EMBEDDED_MIGRATIONS[name].trim(), disk.trim(), `${name}: embedded SQL is stale`);
  }
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

test("embedded 0007 adds unparsed to contract_scans and backfills unparsed records", () => {
  const sql = EMBEDDED_MIGRATIONS["0007_unparsed.sql"];
  assert.match(sql, /alter table contract_scans add column if not exists unparsed boolean/i);
  assert.match(sql, /detector <> 'parse'/i);
  assert.match(sql, /contractNames.*Fragment/i);
});

test("embedded 0015 creates auditor_dispositions keyed by finding with the disposition vocabulary", () => {
  const sql = EMBEDDED_MIGRATIONS["0015_auditor_dispositions.sql"];
  assert.match(sql, /create table if not exists auditor_dispositions/i);
  assert.match(sql, /finding_id text primary key references findings \(id\) on delete cascade/i);
  assert.match(sql, /'confirmed', 'false_positive', 'needs_more_info'/i);
});

test("embedded 0017 creates fp_signatures keyed by signature with the decision vocabulary", () => {
  const sql = EMBEDDED_MIGRATIONS["0017_fp_signatures.sql"];
  assert.match(sql, /create table if not exists fp_signatures/i);
  assert.match(sql, /signature_key text primary key/i);
  assert.match(sql, /'candidate', 'confirmed', 'dismissed'/i);
});
