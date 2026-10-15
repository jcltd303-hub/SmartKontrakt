import type { Sql } from "../sql-client.ts";
import type { ComprehensiveRecordInput } from "./persist.server.ts";
import { buildReportRagChunks } from "./rag-chunks.ts";
import { serializedBytes } from "./batch-writer.ts";

export const MAX_BATCH_RECORDS = 50;
export const MAX_BATCH_BYTES = 1_500_000;

export function validateAuditBatch(records: unknown): ComprehensiveRecordInput[] {
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
  if (serializedBytes(records) > MAX_BATCH_BYTES) throw new Error("Batch exceeds the payload byte limit");
  return records as ComprehensiveRecordInput[];
}

/** Six bulk statements in one transaction; a retry replaces the same dossier and RAG rows. */
export async function writeAuditBatch(sql: Sql, records: ComprehensiveRecordInput[]): Promise<{ savedCount: number; ids: string[] }> {
  validateAuditBatch(records);
  if (!records.length) return { savedCount: 0, ids: [] };
  const ids = records.map((r) => r.id!);
  const scans = records.map((r) => {
    const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const f of r.report.findings) counts[f.severity]++;
    return {
      id: r.id, label: r.label, input_kind: r.report.inputKind,
      contract_name: r.report.inventory.contractNames[0] ?? null,
      target_address: r.targetAddress ?? null, chain_id: r.chainId ?? "ethereum",
      compiler_version: r.compilerVersion ?? r.report.inventory.compiler ?? null,
      proxy_info_json: r.proxyInfo ? JSON.stringify(r.proxyInfo) : null,
      probes_json: r.probes ? JSON.stringify(r.probes) : null,
      ai_review_json: r.aiReview ? JSON.stringify(r.aiReview) : null,
      triage_states_json: r.triageStates ? JSON.stringify(r.triageStates) : null,
      cert_hash: r.certHash ?? null, source_origin: r.sourceOrigin ?? "pipeline",
      is_rag_indexed: r.indexToRag !== false, risk_score: r.report.riskScore,
      critical_count: counts.critical, high_count: counts.high, medium_count: counts.medium,
      low_count: counts.low, info_count: counts.info, summary: r.report.summary,
      inventory_json: JSON.stringify(r.report.inventory),
      ai_narrative: r.report.aiNarrative ?? r.aiReview?.threatModelReport ?? null,
      ai_status: r.report.aiStatus,
    };
  });
  const findings = records.flatMap((r) => r.report.findings.map((f, ord) => ({
    id: `${r.id}:${ord}`, scan_id: r.id, ord, severity: f.severity, swc: f.swc,
    title: f.title, confidence: f.confidence, detector: f.detector, summary: f.summary,
    walkthrough: f.walkthrough, exploit_solidity: f.exploitSolidity,
    remediation_solidity: f.remediationSolidity, location_fn: f.locationFn,
    location_line: f.locationLine, snippet: f.snippet,
  })));
  const chunks = records.flatMap((r) => r.indexToRag === false ? [] : buildReportRagChunks({
    scanId: r.id!, report: r.report, targetAddress: r.targetAddress, chainId: r.chainId,
    proxyInfo: r.proxyInfo, probes: r.probes, aiReview: r.aiReview,
  }));

  await sql.transaction(async (tx) => {
    await tx.query(`
      insert into contract_scans (
        id, label, input_kind, contract_name, target_address, chain_id, compiler_version,
        proxy_info_json, probes_json, ai_review_json, triage_states_json, cert_hash,
        source_origin, is_rag_indexed, risk_score, critical_count, high_count, medium_count,
        low_count, info_count, summary, inventory_json, ai_narrative, ai_status
      ) select * from jsonb_to_recordset($1::jsonb) as r(
        id text, label text, input_kind text, contract_name text, target_address text,
        chain_id text, compiler_version text, proxy_info_json text, probes_json text,
        ai_review_json text, triage_states_json text, cert_hash text, source_origin text,
        is_rag_indexed boolean, risk_score integer, critical_count integer, high_count integer,
        medium_count integer, low_count integer, info_count integer, summary text,
        inventory_json text, ai_narrative text, ai_status text
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
        ai_status=excluded.ai_status`, [JSON.stringify(scans)]);
    await tx.query(`insert into scan_payloads (scan_id, body)
      select scan_id, body from jsonb_to_recordset($1::jsonb) as r(scan_id text, body text)
      on conflict (scan_id) do update set body=excluded.body`,
    [JSON.stringify(records.map((r) => ({ scan_id: r.id, body: r.body })))]);
    await tx.query("delete from findings where scan_id = any($1::text[])", [ids]);
    await tx.query(`insert into findings (
      id, scan_id, ord, severity, swc, title, confidence, detector, summary, walkthrough,
      exploit_solidity, remediation_solidity, location_fn, location_line, snippet
    ) select * from jsonb_to_recordset($1::jsonb) as r(
      id text, scan_id text, ord integer, severity text, swc text, title text, confidence text,
      detector text, summary text, walkthrough text, exploit_solidity text,
      remediation_solidity text, location_fn text, location_line integer, snippet text
    )`, [JSON.stringify(findings)]);
    await replaceRagChunks(tx, ids, chunks);
  });
  return { savedCount: ids.length, ids };
}

export async function replaceRagChunks(sql: Sql, ids: string[], chunks: ReturnType<typeof buildReportRagChunks>): Promise<void> {
  await sql.query("delete from rag_knowledge_chunks where scan_id = any($1::text[])", [ids]);
  await sql.query(`insert into rag_knowledge_chunks (
    id, scan_id, category, title, content, severity, swc, detector, contract_name,
    target_address, chain_id, keywords, vector_data, metadata_json
  ) select * from jsonb_to_recordset($1::jsonb) as r(
    id text, scan_id text, category text, title text, content text, severity text, swc text,
    detector text, contract_name text, target_address text, chain_id text, keywords text,
    vector_data text, metadata_json text
  )`, [JSON.stringify(chunks)]);
}
