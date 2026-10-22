import { writeAuditBatch } from "./bulk-persist.server";
import { getSql } from "@/lib/db";
import type { Sql } from "../sql-client.ts";
import {
  queryDatabaseSize,
  queryScanSummaries,
  queryScansStats,
  summaryFromRow,
  type DatabaseSizeResult,
  type ScanSummariesResult,
  type ScansStatsResult,
} from "./scan-archive.server";

export type {
  DatabaseSizeResult,
  DbSizeTable,
  ScanSummariesResult,
  ScansStats,
  ScansStatsResult,
} from "./scan-archive.server";
import { analyzeInput } from "./engine";
import type { Finding, Inventory, PocResult, Report, Severity } from "./types";
import type { ProxyAnalysis } from "./proxy-resolver";
import type { CallProbeResult } from "./simulator";
import type { AiSecurityReview } from "./ai-review.server";
import { postChatWithModelFallback, resolveOpenRouterConfig, stripThinkBlocks } from "./ai-review.server";
import { openRouterLimiter, withRetry } from "./rate-limit";
import { pocRunKey } from "./poc-run-key.ts";


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
  /** Native-coin balance (wei, decimal string) at analysis time. Null = not read
   *  (distinct from "0", a confirmed empty balance). */
  balanceWei?: string | null;
  /** Total USD value at analysis time (native + ERC-20). Null = not valued. */
  valueUsd?: number | null;
  certHash?: string | null;
  isRagIndexed?: boolean;
  sourceOrigin?: string;
  hasProxy?: boolean;
  probesCount?: number;
  createdAt: string;
  /** True when the input did not parse (Item 3) — the record analyzed
   * nothing and renders "Unparsed", never "Clean". Derived from the
   * findings rows (all parse-detector) so records saved before the
   * engine set report.unparsed are still labeled correctly. */
  unparsed?: boolean;
  /** Which analyzer produced this record (migration 0014). Null = written
   *  before the stamp existed, and therefore stale. */
  analyzerVersion?: string | null;
};

export type StoredScan = ScanSummary & {
  body: string;
  report: Report;
  proxyInfo?: ProxyAnalysis | null;
  probes?: CallProbeResult[];
  aiReview?: AiSecurityReview | null;
  triageStates?: Record<string, string>;
  pocResult?: PocResult | null;
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
  analyzer_version?: string | null;
  is_rag_indexed?: boolean | null;
  risk_score: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  info_count: number;
  balance_wei?: string | null;
  value_usd?: number | null;
  abi_json?: string | null;
  abi_source?: string | null;
  summary: string;
  inventory_json: string;
  ai_narrative: string | null;
  ai_status: string;
  poc_status?: string | null;
  poc_logs?: string | null;
  poc_duration_ms?: number | null;
  poc_run_at?: string | null;
  created_at: string;
  unparsed?: boolean;
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
  poc_status?: string | null;
  poc_output?: string | null;
  poc_duration_ms?: number | null;
  poc_run_at?: string | null;
  poc_code?: string | null;
};


export async function listScanSummaries(opts?: { limit?: number; offset?: number }): Promise<ScanSummariesResult> {
  // Error contract (2026-10-22, improvement #2): a failed query returns
  // { summaries: [], error } instead of the old silent [] — the Records tab
  // renders the error with the effective DB identity, so a wrong-project
  // misconfiguration can never again masquerade as an empty archive. The
  // query itself lives in scan-archive.server.ts (Sql injected, testable).
  let sql: Sql;
  try {
    sql = await getSql();
  } catch (err) {
    console.warn("[kiln] DB unavailable for scan list:", err);
    return { summaries: [], error: err instanceof Error ? err.message : String(err) };
  }
  return queryScanSummaries(sql, opts);
}

/** True totals for the stat cards (not per-page sums). Same error
 *  contract as listScanSummaries: failures surface, never silent zeros. */
export async function getScansStats(): Promise<ScansStatsResult> {
  let sql: Sql;
  try {
    sql = await getSql();
  } catch (err) {
    console.warn("[kiln] DB unavailable for scan stats:", err);
    return {
      stats: { total: 0, critical: 0, high: 0, ragIndexed: 0 },
      error: err instanceof Error ? err.message : String(err),
    };
  }
  return queryScansStats(sql);
}

/** Database size guardrail (improvement #3): fail soft — a size read
 *  failure returns totalBytes null + error and never throws. */
export async function getDatabaseSize(): Promise<DatabaseSizeResult> {
  let sql: Sql;
  try {
    sql = await getSql();
  } catch (err) {
    return { totalBytes: null, tables: [], error: err instanceof Error ? err.message : String(err) };
  }
  return queryDatabaseSize(sql);
}

export async function loadScan(id: string): Promise<StoredScan | null> {
  const sql = await getSql();
  const rows = await sql<ScanRow>`
    select id, label, input_kind, contract_name, target_address, chain_id,
           compiler_version, proxy_info_json, probes_json, ai_review_json,
           triage_states_json, cert_hash, source_origin, is_rag_indexed,
           risk_score, critical_count, high_count, medium_count, low_count, info_count,
           balance_wei, value_usd, abi_json, abi_source, analyzer_version,
           summary, inventory_json, ai_narrative, ai_status, unparsed,
           poc_status, poc_logs, poc_duration_ms, poc_run_at::text as poc_run_at,
           created_at::text as created_at
    from contract_scans
    where id = ${id}
  `;
  const row = rows[0];
  if (!row) return null;
  const payloads = await sql<{ body: string }>`select body from scan_payloads where scan_id = ${id}`;
  const findingRows = await sql<FindingRow>`
    select id, ord, severity, swc, title, confidence, detector, summary, walkthrough,
           exploit_solidity, remediation_solidity, location_fn, location_line, snippet,
           poc_status, poc_output, poc_duration_ms, poc_run_at::text as poc_run_at, poc_code
    from findings
    where scan_id = ${id}
    order by ord asc
  `;
  const inventory = JSON.parse(row.inventory_json) as Inventory;
  // Backfill from the dedicated column when the stored inventory predates it.
  if (inventory.balanceWei == null && row.balance_wei != null) inventory.balanceWei = row.balance_wei;
  if (inventory.valueUsd == null && row.value_usd != null) inventory.valueUsd = Number(row.value_usd);
  // The stored ABI is authoritative when the inventory does not carry one.
  if (inventory.abi == null && row.abi_json) {
    try { inventory.abi = JSON.parse(row.abi_json); inventory.abiSource = row.abi_source ?? null; } catch { /* ignore */ }
  }
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
    pocStatus: f.poc_status ?? null,
    pocOutput: f.poc_output ?? null,
    pocDurationMs: f.poc_duration_ms ?? null,
    pocRunAt: f.poc_run_at ?? null,
    pocCode: f.poc_code ?? null,
  }));
  const aiStatus = row.ai_status === "ok" || row.ai_status === "error" ? row.ai_status : "unavailable";
  // Item 3: the stored column is authoritative; the derivation covers rows
  // saved before migration 0007 (or by a client without the column):
  // Fragment-only inventory with no findings (bare enum paste), or
  // findings that are all the parse-failure INFO.
  const inventoryIsFragmentOnly =
    inventory.contractNames.length > 0 &&
    inventory.contractNames.every((n) => n === "Fragment") &&
    inventory.functions.length === 0;
  const unparsed =
    row.unparsed === true ||
    (inventoryIsFragmentOnly && findings.length === 0) ||
    (row.input_kind === "source" && findings.length > 0 && findings.every((f) => f.detector === "parse"));
  const report: Report = {
    label: row.label,
    inputKind: row.input_kind === "bytecode" ? "bytecode" : "source",
    riskScore: row.risk_score,
    summary: row.summary,
    inventory,
    findings,
    aiNarrative: row.ai_narrative,
    aiStatus,
    // Item 3: same derivation as the list query, from the findings rows.
    unparsed,
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

  let pocResult: PocResult | null = null;
  if (row.poc_status) {
    pocResult = {
      status: row.poc_status as PocResult["status"],
      logs: row.poc_logs ?? "",
      durationMs: row.poc_duration_ms ?? 0,
      runAt: row.poc_run_at ?? row.created_at,
    };
  }

  return {
    ...summaryFromRow(row),
    body: payloads[0]?.body ?? "",
    report,
    proxyInfo,
    probes,
    aiReview,
    triageStates,
    pocResult,
  };
}

export async function deleteScan(id: string): Promise<void> {
  const sql = await getSql();
  await sql`delete from contract_scans where id = ${id}`;
}

/**
 * Saves a comprehensive audit report with complete dossier into local DB
 * (transactionally, via the bulk writer) and indexes it into the local
 * knowledge base.
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
  pocResult?: PocResult | null;
}): Promise<StoredScan> {
  const id = input.id && input.id.trim() ? input.id : crypto.randomUUID();
  const report = input.report;

  // Automatic OpenRouter second pass: every saved audit gets an AI narrative
  // unless the report already carries one (e.g. re-saving a loaded scan).
  // Best-effort — an LLM failure must never fail the save.
  if (report.aiNarrative == null) {
    const pass = await secondPass(report, input.body);
    if (pass.text) report.aiNarrative = pass.text;
    report.aiStatus = pass.status;
  }

  // One dossier through the SAME transactional bulk writer the pipeline uses:
  // a single BEGIN/COMMIT with set-based inserts, instead of the old sequence
  // of per-statement writes and a per-finding INSERT loop. A failure rolls the
  // whole save back rather than leaving a scan row with half its findings.
  // `maxBytes: Infinity` because a single dossier is bounded by its own
  // construction, not by the 50-record / 1.5 MB batch cap.
  const record: ComprehensiveRecordInput = {
    id,
    label: input.label,
    report,
    body: input.body,
    targetAddress: input.targetAddress ?? null,
    chainId: input.chainId ?? "ethereum",
    compilerVersion: input.compilerVersion ?? report.inventory.compiler ?? null,
    proxyInfo: input.proxyInfo ?? null,
    probes: input.probes ?? null,
    aiReview: input.aiReview ?? null,
    triageStates: input.triageStates ?? null,
    certHash: input.certHash ?? null,
    sourceOrigin: input.sourceOrigin ?? "workbench",
    indexToRag: input.indexToRag !== false,
    pocResult: input.pocResult ?? null,
  };
  const sql = await getSql();
  await writeAuditBatch(sql, [record], { maxBytes: Infinity });

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
  pocResult?: PocResult | null;
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
  // Prose reasoning over findings + a source excerpt → the "review" model.
  const { apiKey } = resolveOpenRouterConfig(process.env, "review");
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
      return postChatWithModelFallback({
        purpose: "review",
        apiKey,
        timeoutMs: 28_000,
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${apiKey}`,
          "HTTP-Referer": process.env.APP_URL?.trim() || "https://smart-kontrakt.vercel.app",
          "X-Title": "SmartKontrakt / Kiln",
        },
        makeBody: (model) => ({
          model,
          max_tokens: 2000,
          temperature: 0.7,
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
    const text = stripThinkBlocks(json.choices?.[0]?.message?.content ?? "");
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

export type FindingWithScanInfo = Finding & {
  scanId: string;
  scanLabel: string;
  contractName: string | null;
  targetAddress: string | null;
  chainId: string | null;
  /** Native balance (wei) of the scan's target at analysis time. */
  balanceWei?: string | null;
  scanCreatedAt: string;
};

/**
 * Fetch all recent Critical and High severity findings from the database,
 * joined with their parent contract scan metadata (target address, label, chain).
 */
export async function getRecentHighSeverityFindings(opts?: {
  limit?: number;
  offset?: number;
  severityFilter?: "all" | "critical" | "high";
}): Promise<FindingWithScanInfo[]> {
  const limit = Math.min(Math.max(Math.floor(opts?.limit ?? 50), 1), 200);
  const offset = Math.max(Math.floor(opts?.offset ?? 0), 0);
  const filter = opts?.severityFilter ?? "all";

  try {
    const sql = await getSql();
    let rows;
    if (filter === "critical") {
      rows = await sql<FindingRow & {
        scan_id: string;
        scan_label: string;
        contract_name: string | null;
        target_address: string | null;
        chain_id: string | null;
        balance_wei: string | null;
        scan_created_at: string;
      }>`
        select f.id, f.scan_id, f.ord, f.severity, f.swc, f.title, f.confidence, f.detector,
               f.summary, f.walkthrough, f.exploit_solidity, f.remediation_solidity,
               f.location_fn, f.location_line, f.snippet,
               f.poc_status, f.poc_output, f.poc_duration_ms, f.poc_run_at::text as poc_run_at, f.poc_code,
               s.label as scan_label, s.contract_name, s.target_address, s.chain_id, s.balance_wei, s.created_at::text as scan_created_at
        from findings f
        join contract_scans s on f.scan_id = s.id
        where f.severity = 'critical'
          and length(trim(f.exploit_solidity)) > 0
        order by s.created_at desc, f.ord asc
        limit ${limit} offset ${offset}
      `;
    } else if (filter === "high") {
      rows = await sql<FindingRow & {
        scan_id: string;
        scan_label: string;
        contract_name: string | null;
        target_address: string | null;
        chain_id: string | null;
        balance_wei: string | null;
        scan_created_at: string;
      }>`
        select f.id, f.scan_id, f.ord, f.severity, f.swc, f.title, f.confidence, f.detector,
               f.summary, f.walkthrough, f.exploit_solidity, f.remediation_solidity,
               f.location_fn, f.location_line, f.snippet,
               f.poc_status, f.poc_output, f.poc_duration_ms, f.poc_run_at::text as poc_run_at, f.poc_code,
               s.label as scan_label, s.contract_name, s.target_address, s.chain_id, s.balance_wei, s.created_at::text as scan_created_at
        from findings f
        join contract_scans s on f.scan_id = s.id
        where f.severity = 'high'
          and length(trim(f.exploit_solidity)) > 0
        order by s.created_at desc, f.ord asc
        limit ${limit} offset ${offset}
      `;
    } else {
      rows = await sql<FindingRow & {
        scan_id: string;
        scan_label: string;
        contract_name: string | null;
        target_address: string | null;
        chain_id: string | null;
        balance_wei: string | null;
        scan_created_at: string;
      }>`
        select f.id, f.scan_id, f.ord, f.severity, f.swc, f.title, f.confidence, f.detector,
               f.summary, f.walkthrough, f.exploit_solidity, f.remediation_solidity,
               f.location_fn, f.location_line, f.snippet,
               f.poc_status, f.poc_output, f.poc_duration_ms, f.poc_run_at::text as poc_run_at, f.poc_code,
               s.label as scan_label, s.contract_name, s.target_address, s.chain_id, s.balance_wei, s.created_at::text as scan_created_at
        from findings f
        join contract_scans s on f.scan_id = s.id
        where f.severity in ('critical', 'high')
          and length(trim(f.exploit_solidity)) > 0
        order by s.created_at desc, f.ord asc
        limit ${limit} offset ${offset}
      `;
    }

    return rows.map((f) => ({
      id: f.id,
      scanId: f.scan_id,
      ord: f.ord,
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
      pocStatus: f.poc_status ?? null,
      pocOutput: f.poc_output ?? null,
      pocDurationMs: f.poc_duration_ms ?? null,
      pocRunAt: f.poc_run_at ?? null,
      pocCode: f.poc_code ?? null,
      scanLabel: f.scan_label,
      contractName: f.contract_name,
      targetAddress: f.target_address,
      chainId: f.chain_id,
      balanceWei: f.balance_wei ?? null,
      scanCreatedAt: f.scan_created_at,
    }));
  } catch (err) {
    console.warn("[kiln] getRecentHighSeverityFindings failed:", err);
    return [];
  }
}

/**
 * Persist an executed PoC run verdict for a specific finding to the database.
 * Updates the finding record and UPSERTS the run row keyed by
 * (finding, source digest), so repeating a run is idempotent.
 */
export async function saveFindingPocResult(data: {
  findingId: string;
  scanId: string;
  status: string;
  source: string;
  output: string;
  durationMs: number;
  chainId?: string | null;
  targetAddress?: string | null;
  exitCode?: number | null;
  truncated?: boolean;
}): Promise<void> {
  const sql = await getSql();
  const { id, digest } = pocRunKey(data.findingId, data.source);

  // 1. Update finding row with latest PoC outcome
  await sql`
    update findings
    set poc_status = ${data.status},
        poc_output = ${data.output.slice(0, 50000)},
        poc_duration_ms = ${Math.round(data.durationMs)},
        poc_run_at = now(),
        poc_code = ${data.source.slice(0, 100000)}
    where id = ${data.findingId}
  `;

  // 2. Insert into historical finding_poc_runs
  try {
    await sql`
      insert into finding_poc_runs (
        id, finding_id, scan_id, status, source, source_digest, output, duration_ms, chain_id, target_address, exit_code, truncated, created_at
      ) values (
        ${id}, ${data.findingId}, ${data.scanId}, ${data.status}, ${data.source.slice(0, 100000)}, ${digest}, ${data.output.slice(0, 50000)},
        ${Math.round(data.durationMs)}, ${data.chainId ?? null}, ${data.targetAddress ?? null}, ${data.exitCode ?? null}, ${Boolean(data.truncated)}, now()
      )
      on conflict (id) do update set
        status = excluded.status,
        output = excluded.output,
        duration_ms = excluded.duration_ms,
        chain_id = excluded.chain_id,
        target_address = excluded.target_address,
        exit_code = excluded.exit_code,
        truncated = excluded.truncated
    `;
  } catch (runErr) {
    console.warn("[kiln] finding_poc_runs insert failed (non-fatal):", runErr);
  }
}


