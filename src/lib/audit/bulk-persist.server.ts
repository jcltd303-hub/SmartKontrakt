import type { Sql } from "../sql-client.ts";
import type { ComprehensiveRecordInput } from "./persist.server.ts";
import { analyzerStamp } from "./analyzer-version.ts";
import { buildReportRagChunks } from "./rag-chunks.ts";
import { serializedBytes } from "./batch-writer.ts";
import { resolveContractDisplayName } from "./simulator.ts";

export const MAX_BATCH_RECORDS = 50;
export const MAX_BATCH_BYTES = 1_500_000;

export function validateAuditBatch(records: unknown, maxBytes: number = MAX_BATCH_BYTES): ComprehensiveRecordInput[] {
  if (!Array.isArray(records) || records.length > MAX_BATCH_RECORDS) {
    throw new Error(`Batch must contain at most ${MAX_BATCH_RECORDS} audit records`);
  }
  const ids = new Set<string>();
  for (const record of records) {
    if (!record || typeof record !== "object" || typeof record.id !== "string" || !record.id.trim() ||
      typeof record.label !== "string" || typeof record.body !== "string" ||
      !record.report?.inventory || !Array.isArray(record.report.findings)) {
      throw new Error("Every batch record requires a stable id, label, body and report");
    }
    if (ids.has(record.id)) throw new Error("Duplicate audit id in batch");
    ids.add(record.id);
  }
  if (Number.isFinite(maxBytes) && serializedBytes(records) > maxBytes) {
    throw new Error("Batch exceeds the payload byte limit");
  }
  return records as ComprehensiveRecordInput[];
}

/**
 * Four bulk statements in one transaction; a retry replaces the same dossier.
 * `opts.maxBytes` overrides the batch payload cap — the single-record
 * save path passes `Infinity`, since one dossier is bounded by its own
 * construction, not by the batch limit.
 */
export async function writeAuditBatch(
  sql: Sql,
  records: ComprehensiveRecordInput[],
  opts?: { maxBytes?: number },
): Promise<{ savedCount: number; ids: string[] }> {
  validateAuditBatch(records, opts?.maxBytes);
  if (!records.length) return { savedCount: 0, ids: [] };
  const ids = records.map((r) => r.id!);
  const scans = records.map((r) => {
    const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const f of r.report.findings) counts[f.severity]++;
    return {
      id: r.id, label: r.label, input_kind: r.report.inputKind,
      // Item 1: the record name is the unified display name — on-chain
      // name() probe first, then the analyzed/main contract — NOT the
      // first contract in the file (SafeMath/Context/Strings/...).
      contract_name: resolveContractDisplayName(r.probes, r.report),
      target_address: r.targetAddress ?? null, chain_id: r.chainId ?? "ethereum",
      compiler_version: r.compilerVersion ?? r.report.inventory.compiler ?? null,
      proxy_info_json: r.proxyInfo ? JSON.stringify(r.proxyInfo) : null,
      probes_json: r.probes ? JSON.stringify(r.probes) : null,
      ai_review_json: r.aiReview ? JSON.stringify(r.aiReview) : null,
      triage_states_json: r.triageStates ? JSON.stringify(r.triageStates) : null,
      cert_hash: r.certHash ?? null, source_origin: r.sourceOrigin ?? "pipeline",
      // RAG eliminated 2026-10-21 (storage): new saves are never RAG-indexed.
      is_rag_indexed: false, risk_score: r.report.riskScore,
      critical_count: counts.critical, high_count: counts.high, medium_count: counts.medium,
      low_count: counts.low, info_count: counts.info, summary: r.report.summary,
      inventory_json: JSON.stringify(r.report.inventory),
      ai_narrative: r.report.aiNarrative ?? r.aiReview?.threatModelReport ?? null,
      ai_status: r.report.aiStatus,
      // Item 3: explicit unparsed state (migration 0007).
      unparsed: r.report.unparsed ?? false,
      // Native balance at analysis time (migration 0011); null when not read.
      balance_wei: r.report.inventory.balanceWei ?? null,
      // Value-at-risk + gathered ABI (migration 0012); null when not computed.
      value_usd: r.report.inventory.valueUsd ?? null,
      value_json: r.report.inventory.value ? JSON.stringify(r.report.inventory.value) : null,
      abi_json: r.report.inventory.abi ? JSON.stringify(r.report.inventory.abi) : null,
      abi_source: r.report.inventory.abiSource ?? null,
      // Which analyzer produced this record (migration 0014). Written on every
      // save so resume can tell a current row from a stale one.
      analyzer_version: analyzerStamp(),
      // Fork-PoC verdict on the scan row (migration 0004). Null when the
      // caller has none; the on-conflict update coalesces so a later batch
      // without a PoC never clears one already stored.
      poc_status: r.pocResult?.status ?? null,
      poc_logs: r.pocResult?.logs ?? null,
      poc_duration_ms: r.pocResult?.durationMs ?? null,
      poc_run_at: r.pocResult?.runAt ?? null,
    };
  });
  const findings = records.flatMap((r) => r.report.findings.map((f, ord) => ({
    id: `${r.id}:${ord}`, scan_id: r.id, ord, severity: f.severity, swc: f.swc,
    title: f.title, confidence: f.confidence, detector: f.detector, summary: f.summary,
    walkthrough: f.walkthrough, exploit_solidity: f.exploitSolidity,
    remediation_solidity: f.remediationSolidity, location_fn: f.locationFn,
    location_line: f.locationLine, snippet: f.snippet,
    poc_status: f.pocStatus ?? null, poc_output: f.pocOutput ?? null,
    poc_duration_ms: f.pocDurationMs ?? null, poc_run_at: f.pocRunAt ?? null, poc_code: f.pocCode ?? null,
    // Migration 0016 (G3): the corroboration marker persists as a
    // boolean — the Finding field also accepts a non-empty note
    // string, which stamps true (the note itself is not stored).
    corroborated:
      f.corroborated === true ||
      (typeof f.corroborated === "string" && f.corroborated.trim() !== "")
        ? true
        : null,
  })));
  // RAG eliminated 2026-10-21 (storage): chunks are no longer built or
  // written on save — contract_scans records are the source of truth.
  // The `indexToRag` input flag is ignored (kept for caller compatibility).

  await sql.transaction(async (tx) => {
    await tx.query(`
      insert into contract_scans (
        id, label, input_kind, contract_name, target_address, chain_id, compiler_version,
        proxy_info_json, probes_json, ai_review_json, triage_states_json, cert_hash,
        source_origin, is_rag_indexed, risk_score, critical_count, high_count, medium_count,
        low_count, info_count, summary, inventory_json, ai_narrative, ai_status, unparsed,
        balance_wei, value_usd, value_json, abi_json, abi_source, analyzer_version,
        poc_status, poc_logs, poc_duration_ms, poc_run_at
      ) select * from jsonb_to_recordset($1::jsonb) as r(
        id text, label text, input_kind text, contract_name text, target_address text,
        chain_id text, compiler_version text, proxy_info_json text, probes_json text,
        ai_review_json text, triage_states_json text, cert_hash text, source_origin text,
        is_rag_indexed boolean, risk_score integer, critical_count integer, high_count integer,
        medium_count integer, low_count integer, info_count integer, summary text,
        inventory_json text, ai_narrative text, ai_status text, unparsed boolean,
        balance_wei text, value_usd numeric, value_json text, abi_json text, abi_source text,
        analyzer_version text,
        poc_status text, poc_logs text, poc_duration_ms integer, poc_run_at timestamptz
      ) on conflict (id) do update set
        label=excluded.label, input_kind=excluded.input_kind, contract_name=excluded.contract_name,
        target_address=excluded.target_address, chain_id=excluded.chain_id,
        compiler_version=excluded.compiler_version, proxy_info_json=excluded.proxy_info_json,
        probes_json=excluded.probes_json, ai_review_json=excluded.ai_review_json,
        triage_states_json=excluded.triage_states_json, cert_hash=excluded.cert_hash,
        source_origin=excluded.source_origin, is_rag_indexed=excluded.is_rag_indexed,
        risk_score=excluded.risk_score, critical_count=excluded.critical_count,
        high_count=excluded.high_count, medium_count=excluded.medium_count,
        low_count=excluded.low_count, info_count=excluded.info_count, summary=excluded.summary,
        inventory_json=excluded.inventory_json, ai_narrative=excluded.ai_narrative,
        ai_status=excluded.ai_status, unparsed=excluded.unparsed,
        balance_wei=coalesce(excluded.balance_wei, contract_scans.balance_wei),
        value_usd=coalesce(excluded.value_usd, contract_scans.value_usd),
        value_json=coalesce(excluded.value_json, contract_scans.value_json),
        abi_json=coalesce(excluded.abi_json, contract_scans.abi_json),
        abi_source=coalesce(excluded.abi_source, contract_scans.abi_source),
        analyzer_version=excluded.analyzer_version,
        poc_status=coalesce(excluded.poc_status, contract_scans.poc_status),
        poc_logs=coalesce(excluded.poc_logs, contract_scans.poc_logs),
        poc_duration_ms=coalesce(excluded.poc_duration_ms, contract_scans.poc_duration_ms),
        poc_run_at=coalesce(excluded.poc_run_at, contract_scans.poc_run_at)`, [JSON.stringify(scans)]);
    await tx.query(`insert into scan_payloads (scan_id, body)
      select scan_id, body from jsonb_to_recordset($1::jsonb) as r(scan_id text, body text)
      on conflict (scan_id) do update set body=excluded.body`,
    [JSON.stringify(records.map((r) => ({ scan_id: r.id, body: r.body })))]);
    await tx.query("delete from findings where scan_id = any($1::text[]) and not (id = any($2::text[]))", [ids, findings.map(f => f.id)]);
    await tx.query(`insert into findings (
      id, scan_id, ord, severity, swc, title, confidence, detector, summary, walkthrough,
      exploit_solidity, remediation_solidity, location_fn, location_line, snippet,
      poc_status, poc_output, poc_duration_ms, poc_run_at, poc_code, corroborated
    ) select * from jsonb_to_recordset($1::jsonb) as r(
      id text, scan_id text, ord integer, severity text, swc text, title text, confidence text,
      detector text, summary text, walkthrough text, exploit_solidity text,
      remediation_solidity text, location_fn text, location_line integer, snippet text,
      poc_status text, poc_output text, poc_duration_ms integer, poc_run_at timestamptz, poc_code text,
      corroborated boolean
    ) on conflict (id) do update set
      ord=excluded.ord, severity=excluded.severity, swc=excluded.swc, title=excluded.title,
      confidence=excluded.confidence, detector=excluded.detector, summary=excluded.summary,
      walkthrough=excluded.walkthrough, exploit_solidity=excluded.exploit_solidity,
      remediation_solidity=excluded.remediation_solidity, location_fn=excluded.location_fn,
      location_line=excluded.location_line, snippet=excluded.snippet,
      poc_status=case when excluded.exploit_solidity = findings.exploit_solidity then coalesce(excluded.poc_status, findings.poc_status) else excluded.poc_status end, poc_output=case when excluded.exploit_solidity = findings.exploit_solidity then coalesce(excluded.poc_output, findings.poc_output) else excluded.poc_output end,
      poc_duration_ms=case when excluded.exploit_solidity = findings.exploit_solidity then coalesce(excluded.poc_duration_ms, findings.poc_duration_ms) else excluded.poc_duration_ms end, poc_run_at=case when excluded.exploit_solidity = findings.exploit_solidity then coalesce(excluded.poc_run_at, findings.poc_run_at) else excluded.poc_run_at end, poc_code=case when excluded.exploit_solidity = findings.exploit_solidity then coalesce(excluded.poc_code, findings.poc_code) else excluded.poc_code end, corroborated=coalesce(excluded.corroborated, findings.corroborated)`, [JSON.stringify(findings)]);
  });
  return { savedCount: ids.length, ids };
}

// Params are prefixed `_` because this is deliberately a no-op: they are kept
// only so the exported signature does not change for its callers.
export async function replaceRagChunks(
  _sql: Sql,
  _ids: string[],
  _chunks: ReturnType<typeof buildReportRagChunks>,
): Promise<void> {
  // RAG eliminated 2026-10-21 (storage): indexing writes are OFF. This is an
  // intentional no-op, kept exported for compatibility — no save path may
  // write rag_knowledge_chunks. Records are the source of truth.
  return;
}
