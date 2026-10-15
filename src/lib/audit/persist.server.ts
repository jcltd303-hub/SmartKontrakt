import { getSql } from "@/lib/db";
import { analyzeInput } from "./engine";
import type { Finding, Inventory, Report, Severity } from "./types";

export type ScanSummary = {
  id: string;
  label: string;
  inputKind: string;
  contractName: string | null;
  riskScore: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  lowCount: number;
  infoCount: number;
  createdAt: string;
};

export type StoredScan = ScanSummary & {
  body: string;
  report: Report;
};

type ScanRow = {
  id: string;
  label: string;
  input_kind: string;
  contract_name: string | null;
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
  return {
    id: row.id,
    label: row.label,
    inputKind: row.input_kind,
    contractName: row.contract_name,
    riskScore: row.risk_score,
    criticalCount: row.critical_count,
    highCount: row.high_count,
    mediumCount: row.medium_count,
    lowCount: row.low_count,
    infoCount: row.info_count,
    createdAt: row.created_at,
  };
}

export async function listScanSummaries(): Promise<ScanSummary[]> {
  try {
    const sql = await getSql();
    const rows = await sql<ScanRow>`
      select id, label, input_kind, contract_name, risk_score,
             critical_count, high_count, medium_count, low_count, info_count,
             summary, inventory_json, ai_narrative, ai_status,
             created_at::text as created_at
      from contract_scans
      order by created_at desc
      limit 40
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
    select id, label, input_kind, contract_name, risk_score,
           critical_count, high_count, medium_count, low_count, info_count,
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
  return {
    ...summaryFrom(row),
    body: payloads[0]?.body ?? "",
    report,
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

async function secondPass(report: Report, body: string): Promise<{ text: string | null; status: Report["aiStatus"] }> {
  const apiKey = process.env.XAI_API_KEY;
  if (!apiKey) return { text: null, status: "unavailable" };
  const listed = report.findings
    .slice(0, 12)
    .map((f) => `- [${f.severity}] ${f.title} (${f.locationFn ?? "n/a"}:${f.locationLine ?? "?"}) ${f.summary}`)
    .join("\n");
  const notes = report.inventory.notes.join("\n");
  const excerpt = body.slice(0, 6000);
  try {
    const res = await fetch("https://api.x.ai/v1/chat/completions", {
      method: "POST",
      signal: AbortSignal.timeout(28_000),
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${apiKey}`,
      },
      body: JSON.stringify({
        model: "grok-4.5",
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
  const pass = await secondPass(report, input.body);
  report.aiNarrative = pass.text;
  report.aiStatus = pass.status;
  const counts = tally(report.findings);
  const id = crypto.randomUUID();
  const contractName = report.inventory.contractNames[0] ?? null;
  const sql = await getSql();
  await sql`
    insert into contract_scans (
      id, label, input_kind, contract_name, risk_score,
      critical_count, high_count, medium_count, low_count, info_count,
      summary, inventory_json, ai_narrative, ai_status
    ) values (
      ${id},
      ${input.label},
      ${report.inputKind},
      ${contractName},
      ${report.riskScore},
      ${counts.critical},
      ${counts.high},
      ${counts.medium},
      ${counts.low},
      ${counts.info},
      ${report.summary},
      ${JSON.stringify(report.inventory)},
      ${pass.text},
      ${pass.status}
    )
  `;
  await sql`insert into scan_payloads (scan_id, body) values (${id}, ${input.body})`;
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
  const stored = await loadScan(id);
  if (!stored) throw new Error("The audit was written but could not be read back.");
  return stored;
}
