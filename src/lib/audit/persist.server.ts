import { writeAuditBatch } from "./bulk-persist.server";
import { getSql } from "@/lib/db";
import { analyzeInput } from "./engine";
import type { Finding, Inventory, Report, Severity } from "./types";
import type { ProxyAnalysis } from "./proxy-resolver";
import type { CallProbeResult } from "./simulator";
import type { AiSecurityReview } from "./ai-review.server";
import { OPENROUTER_API_URL, resolveOpenRouterConfig } from "./ai-review.server";
import { indexReportToRag } from "./rag.server";
import { openRouterLimiter, withRetry } from "./rate-limit";

export type ScanSummary = {
  id: string;
  label: string;
  inputKind: string;
  contractName: string | null;
  targetAddress?: string | null;
  chainId?: string | null;
  riskScore: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  infoCount: number;
  certHash?: string | null;
  isRagIndexed?: boolean;
  sourceOrigin?: string;
  hasProxy?: boolean;
  probesCount?: number;
  createdAt: string;
};

export type StoredScan = ScanSummary & {
  body: string;
  report: Report;
  proxyInfo?: ProxyAnalysis | null;
  probes?: CallProbeResult[];
  aiReview?: AiSecurityReview | null;
  triageStates?: Record<string, string>;
};

type ScanRow = {
  id: string;
  label: string;
  input_kind: string;
  contract_name: string | null;
  target_address?: string | null;
  chain_id?: string | null;
  compiler_version?: string | null;
  proxy_info_json?: string | null;
  probes_json?: string | null;
  ai_review_json?: string | null;
  triage_states_json?: string | null;
  cert_hash?: string | null;
  source_origin?: string | null;
  is_rag_indexed?: boolean | null;
  risk_score: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  info_count: number;
  summary: string;
  inventory_json: string;
  ai_narrative: string | null;
  ai_status: string;
  created_at: string;
};

type FindingRow = {
  id: string;
  ord: number;
  severity: Severity;
  swc: string | null;
  title: string;
  confidence: Finding["confidence"];
  detector: string;
  summary: string;
  walkthrough: string;
  exploit_solidity: string;
  remediation_solidity: string;
  location_fn: string | null;
  location_line: number | null;
  snippet: string;
};

function summaryFrom(row: ScanRow): ScanSummary {
  let hasProxy = false;
  if (row.proxy_info_json) {
    try {
      const p = JSON.parse(row.proxy_info_json);
      hasProxy = Boolean(p?.isProxy);
    } catch {
      hasProxy = false;
    }
  }

  let probesCount = 0;
  if (row.probes_json) {
    try {
      const pr = JSON.parse(row.probes_json);
      probesCount = Array.isArray(pr) ? pr.length : 0;
    } catch {
      probesCount = 0;
    }
  }

  return {
    id: row.id,
    label: row.label,
    inputKind: row.input_kind,
    contractName: row.contract_name,
    targetAddress: row.target_address ?? null,
    chainId: row.chain_id ?? "ethereum",
    riskScore: row.risk_score,
    criticalCount: row.critical_count,
    highCount: row.high_count,
    mediumCount: row.medium_count,
    lowCount: row.low_count,
    infoCount: row.info_count,
    certHash: row.cert_hash ?? null,
    isRagIndexed: Boolean(row.is_rag_indexed),
    sourceOrigin: row.source_origin ?? "workbench",
    hasProxy,
    probesCount,
    createdAt: row.created_at,
  };
}

export async function listScanSummaries(): Promise<ScanSummary[]> {
  try {
    const sql = await getSql();
    const rows = await sql<ScanRow>`
      select id, label, input_kind, contract_name, target_address, chain_id,
             proxy_info_json, probes_json, cert_hash, source_origin, is_rag_indexed,
             risk_score, critical_count, high_count, medium_count, low_count, info_count,
             created_at::text as created_at
      from contract_scans
      order by created_at desc
      limit 60
    `;
    return rows.map(summaryFrom);
  } catch (err) {
    console.warn("[kiln] DB scans table not ready or empty:", err);
    return [];
  }
}

export async function loadScan(id: string): Promise<StoredScan | null> {
  const sql = await getSql();
  const rows = await sql<ScanRow>`
    select id, label, input_kind, contract_name, target_address, chain_id,
           compiler_version, proxy_info_json, probes_json, ai_review_json,
           triage_states_json, cert_hash, source_origin, is_rag_indexed,
           risk_score, critical_count, high_count, medium_count, low_count, info_count,
           summary, inventory_json, ai_narrative, ai_status,
           created_at::text as created_at
    from contract_scans
    where id = ${id}
  `;
  const row = rows[0];
  if (!row) return null;
  const payloads = await sql<{ body: string }>`select body from scan_payloads where scan_id = ${id}`;
  const findingRows = await sql<FindingRow>`
    select id, ord, severity, swc, title, confidence, detector, summary, walkthrough,
           exploit_solidity, remediation_solidity, location_fn, location_line, snippet
    from findings
    where scan_id = ${id}
    order by ord asc
  `;
  const inventory = JSON.parse(row.inventory_json) as Inventory;
  const findings: Finding[] = findingRows.map((f) => ({
    id: f.id,
    severity: f.severity,
    swc: f.swc,
    title: f.title,
    confidence: f.confidence,
    detector: f.detector,
    summary: f.summary,
    walkthrough: f.walkthrough,
    exploitSolidity: f.exploit_solidity,
    remediationSolidity: f.remediation_solidity,
    locationFn: f.location_fn,
    locationLine: f.location_line,
    snippet: f.snippet,
  }));
  const aiStatus = row.ai_status === "ok" || row.ai_status === "error" ? row.ai_status : "unavailable";
  const report: Report = {
    label: row.label,
    inputKind: row.input_kind === "bytecode" ? "bytecode" : "source",
    riskScore: row.risk_score,
    summary: row.summary,
    inventory,
    findings,
    aiNarrative: row.ai_narrative,
    aiStatus,
  };

  let proxyInfo: ProxyAnalysis | null = null;
  if (row.proxy_info_json) {
    try {
      proxyInfo = JSON.parse(row.proxy_info_json);
    } catch {
      // ignore
    }
  }

  let probes: CallProbeResult[] = [];
  if (row.probes_json) {
    try {
      probes = JSON.parse(row.probes_json);
    } catch {
      // ignore
    }
  }

  let aiReview: AiSecurityReview | null = null;
  if (row.ai_review_json) {
    try {
      aiReview = JSON.parse(row.ai_review_json);
    } catch {
      // ignore
    }
  }

  let triageStates: Record<string, string> = {};
  if (row.triage_states_json) {
    try {
      triageStates = JSON.parse(row.triage_states_json);
    } catch {
      // ignore
    }
  }

  return {
    ...summaryFrom(row),
    body: payloads[0]?.body ?? "",
    report,
    proxyInfo,
    probes,
    aiReview,
    triageStates,
  };
}

export async function deleteScan(id: string): Promise<void> {
  const sql = await getSql();
  await sql`delete from contract_scans where id = ${id}`;
}

function tally(findings: Finding[]) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) counts[f.severity] += 1;
  return counts;
}

/**
 * Saves a comprehensive audit report with complete dossier into local DB
 * and triggers automatic local RAG knowledgebase chunk indexing.
 */
export async function saveComprehensiveRecord(input: {
  id?: string;
  label: string;
  report: Report;
  body: string;
  targetAddress?: string | null;
  chainId?: string | null;
  compilerVersion?: string | null;
  proxyInfo?: ProxyAnalysis | null;
  probes?: CallProbeResult[] | null;
  aiReview?: AiSecurityReview | null;
  triageStates?: Record<string, string> | null;
  certHash?: string | null;
  sourceOrigin?: string;
  indexToRag?: boolean;
}): Promise<StoredScan> {
  const sql = await getSql();
  const id = input.id && input.id.trim() ? input.id : crypto.randomUUID();
  const report = input.report;
  const counts = tally(report.findings);
  const contractName = report.inventory.contractNames[0] ?? null;

  // Automatic OpenRouter second pass: every saved audit gets an AI narrative
  // unless the report already carries one (e.g. re-saving a loaded scan).
  // Best-effort — an LLM failure must never fail the save.
  if (report.aiNarrative == null) {
    const pass = await secondPass(report, input.body);
    if (pass.text) report.aiNarrative = pass.text;
    report.aiStatus = pass.status;
  }

  const proxyJson = input.proxyInfo ? JSON.stringify(input.proxyInfo) : null;
  const probesJson = input.probes ? JSON.stringify(input.probes) : null;
  const aiReviewJson = input.aiReview ? JSON.stringify(input.aiReview) : null;
  const triageJson = input.triageStates ? JSON.stringify(input.triageStates) : null;
  const sourceOrigin = input.sourceOrigin ?? "workbench";

  // Upsert main record into contract_scans
  await sql`
    insert into contract_scans (
      id, label, input_kind, contract_name, target_address, chain_id,
      compiler_version, proxy_info_json, probes_json, ai_review_json,
      triage_states_json, cert_hash, source_origin, is_rag_indexed,
      risk_score, critical_count, high_count, medium_count, low_count, info_count,
      summary, inventory_json, ai_narrative, ai_status
    ) values (
      ${id},
      ${input.label},
      ${report.inputKind},
      ${contractName},
      ${input.targetAddress ?? null},
      ${input.chainId ?? "ethereum"},
      ${input.compilerVersion ?? report.inventory.compiler ?? null},
      ${proxyJson},
      ${probesJson},
      ${aiReviewJson},
      ${triageJson},
      ${input.certHash ?? null},
      ${sourceOrigin},
      ${Boolean(input.indexToRag !== false)},
      ${report.riskScore},
      ${counts.critical},
      ${counts.high},
      ${counts.medium},
      ${counts.low},
      ${counts.info},
      ${report.summary},
      ${JSON.stringify(report.inventory)},
      ${report.aiNarrative ?? input.aiReview?.threatModelReport ?? null},
      ${report.aiStatus}
    )
    on conflict (id) do update set
      label = excluded.label,
      contract_name = excluded.contract_name,
      target_address = excluded.target_address,
      chain_id = excluded.chain_id,
      compiler_version = excluded.compiler_version,
      proxy_info_json = excluded.proxy_info_json,
      probes_json = excluded.probes_json,
      ai_review_json = excluded.ai_review_json,
      triage_states_json = excluded.triage_states_json,
      cert_hash = excluded.cert_hash,
      source_origin = excluded.source_origin,
      is_rag_indexed = excluded.is_rag_indexed,
      risk_score = excluded.risk_score,
      critical_count = excluded.critical_count,
      high_count = excluded.high_count,
      medium_count = excluded.medium_count,
      low_count = excluded.low_count,
      info_count = excluded.info_count,
      summary = excluded.summary,
      inventory_json = excluded.inventory_json,
      ai_narrative = excluded.ai_narrative,
      ai_status = excluded.ai_status
  `;

  // Payload upsert
  await sql`
    insert into scan_payloads (scan_id, body) values (${id}, ${input.body})
    on conflict (scan_id) do update set body = excluded.body
  `;

  // Clear existing findings and replace with clean ordered findings
  await sql`delete from findings where scan_id = ${id}`;
  for (let i = 0; i < report.findings.length; i += 1) {
    const f = report.findings[i];
    if (!f) continue;
    await sql`
      insert into findings (
        id, scan_id, ord, severity, swc, title, confidence, detector, summary,
        walkthrough, exploit_solidity, remediation_solidity, location_fn, location_line, snippet
      ) values (
        ${`${id}:${i}`},
        ${id},
        ${i},
        ${f.severity},
        ${f.swc},
        ${f.title},
        ${f.confidence},
        ${f.detector},
        ${f.summary},
        ${f.walkthrough},
        ${f.exploitSolidity},
        ${f.remediationSolidity},
        ${f.locationFn},
        ${f.locationLine},
        ${f.snippet}
      )
    `;
  }

  // Automatic Indexing to RAG Knowledgebase
  if (input.indexToRag !== false) {
    try {
      await indexReportToRag({
        scanId: id,
        report,
        rawBody: input.body,
        targetAddress: input.targetAddress,
        chainId: input.chainId,
        proxyInfo: input.proxyInfo,
        probes: input.probes,
        aiReview: input.aiReview,
      });
    } catch (ragErr) {
      console.warn("[kiln] RAG knowledgebase auto-index warning:", ragErr);
    }
  }

  const stored = await loadScan(id);
  if (!stored) throw new Error("The comprehensive audit record was written but could not be read back.");
  return stored;
}

export type ComprehensiveRecordInput = {
  id?: string;
  label: string;
  report: Report;
  body: string;
  targetAddress?: string | null;
  chainId?: string | null;
  compilerVersion?: string | null;
  proxyInfo?: ProxyAnalysis | null;
  probes?: CallProbeResult[] | null;
  aiReview?: AiSecurityReview | null;
  triageStates?: Record<string, string> | null;
  certHash?: string | null;
  sourceOrigin?: string;
  indexToRag?: boolean;
};

/**
 * High-performance batched writing of multiple audit dossiers into local DB
 * and bulk ingestion into the local RAG knowledgebase.
 */
export async function saveBatchComprehensiveRecords(
  records: ComprehensiveRecordInput[]
): Promise<{ savedCount: number; ids: string[] }> {
  const sql = await getSql();
  // Pure SQL bulk write — no LLM calls here. A 50-record batch with per-record
  // AI would blow past the serverless function timeout and stall the flush at
  // 0 records. The pipeline runs the AI second pass per item (client-side,
  // via runSecondPassFn) before enqueue, so the bulk save stays fast.
  return writeAuditBatch(sql, records);
}

export async function secondPass(report: Report, body: string): Promise<{ text: string | null; status: Report["aiStatus"] }> {
  // Second pass goes through OpenRouter, same as the AI review panel —
  // the old xAI/Grok path (XAI_API_KEY, api.x.ai, grok-4.5) was never
  // migrated and silently returned "unavailable" on every audit.
  const { apiKey, model } = resolveOpenRouterConfig();
  if (!apiKey) return { text: null, status: "unavailable" };
  const listed = report.findings
    .slice(0, 12)
    .map((f) => `- [${f.severity}] ${f.title} (${f.locationFn ?? "n/a"}:${f.locationLine ?? "?"}) ${f.summary}`)
    .join("\n");
  const notes = report.inventory.notes.join("\n");
  const excerpt = body.slice(0, 6000);
  try {
    const res = await withRetry(async () => {
      await openRouterLimiter.acquire();
      return fetch(OPENROUTER_API_URL, {
        method: "POST",
        signal: AbortSignal.timeout(28_000),
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${apiKey}`,
          "HTTP-Referer": process.env.APP_URL?.trim() || "https://smart-kontrakt.vercel.app",
          "X-Title": "SmartKontrakt / Kiln",
        },
        body: JSON.stringify({
          model,
          max_tokens: 700,
          temperature: 0.2,
          messages: [
            {
              role: "system",
              content:
                "You are the second pass on a smart-contract audit. The static detectors already ran. " +
                "Add only issues they missed, or one sharper exploit note if their lead finding is real but shallow. " +
                "Do not repeat their list. Under 280 words. Plain prose. " +
                "If you have nothing new, reply exactly: No additional issues beyond the static report. " +
                "Never invent a mainnet address or a line you were not shown.",
            },
            {
              role: "user",
              content: `KIND: ${report.inputKind}\nSUMMARY: ${report.summary}\nNOTES:\n${notes}\n\nSTATIC FINDINGS:\n${listed || "(none)"}\n\nINPUT:\n${excerpt}`,
            },
          ],
        }),
      });
    }, { retries: 3, baseDelayMs: 2000 });
    if (!res.ok) return { text: null, status: "error" };
    const json = (await res.json()) as { choices?: { message?: { content?: string } }[] };
    const text = json.choices?.[0]?.message?.content?.trim() ?? "";
    if (!text) return { text: null, status: "error" };
    return { text: text.slice(0, 4000), status: "ok" };
  } catch {
    return { text: null, status: "error" };
  }
}

export async function runAndStore(input: { label: string; body: string }): Promise<StoredScan> {
  const report = analyzeInput(input.body, input.label);
  // saveComprehensiveRecord runs the OpenRouter second pass.
  return saveComprehensiveRecord({
    label: input.label,
    report,
    body: input.body,
    sourceOrigin: "workbench",
    indexToRag: true,
  });
}
