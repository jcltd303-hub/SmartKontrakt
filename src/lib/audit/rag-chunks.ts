import type { Finding, Report, Severity } from "./types.ts";
import type { ProxyAnalysis } from "./proxy-resolver.ts";
import type { CallProbeResult } from "./simulator.ts";
import { resolveContractDisplayName } from "./simulator.ts";
import type { AiSecurityReview } from "./ai-review.server.ts";


export interface RagDbRow {
  id: string;
  scan_id: string | null;
  category: string;
  title: string;
  content: string;
  severity: string | null;
  swc: string | null;
  detector: string | null;
  contract_name: string | null;
  target_address: string | null;
  chain_id: string | null;
  keywords: string;
  vector_data: string | null;
  metadata_json: string;
  created_at: string;
}

export type RagIndexInput = {
  scanId: string;
  report: Report;
  rawBody?: string;
  targetAddress?: string | null;
  chainId?: string | null;
  proxyInfo?: ProxyAnalysis | null;
  probes?: CallProbeResult[] | null;
  aiReview?: AiSecurityReview | null;
};

function tokenize(text: string): string[] {
  const clean = text.toLowerCase().replace(/[^a-z0-9_#$]/g, " ");
  const stopWords = new Set(["the", "and", "or", "to", "in", "a", "of", "for", "with", "on", "at", "by", "from", "is", "this", "that", "it"]);
  return clean
    .split(/\s+/)
    .filter((w) => w.length > 2 && !stopWords.has(w));
}

export function buildReportRagChunks(params: RagIndexInput): Omit<RagDbRow, "created_at">[] {
  const { scanId, report, targetAddress, chainId, proxyInfo, probes, aiReview } = params;
  // Item 1: RAG chunks carry the same unified display name as the record.
  const contractName = resolveContractDisplayName(probes, report);
  const chunksToInsert: Omit<RagDbRow, "created_at">[] = [];

  // 1. Chunks for each finding
  for (let idx = 0; idx < report.findings.length; idx++) {
    const f: Finding = report.findings[idx];
    const chunkId = `rag-${scanId}-finding-${idx}`;
    const title = `[${f.severity.toUpperCase()}] ${f.title} (${f.detector})`;
    const content = `${f.title}\nSeverity: ${f.severity.toUpperCase()} | SWC: ${f.swc ?? "N/A"} | Detector: ${f.detector}\n\nSummary:\n${f.summary}\n\nWalkthrough & Root Cause:\n${f.walkthrough}\n${f.snippet ? `\nCode Snippet:\n${f.snippet}` : ""}`;
    const keywords = [
      f.detector,
      f.swc ?? "",
      f.severity,
      contractName,
      ...tokenize(f.title),
      ...tokenize(f.summary).slice(0, 5),
    ].filter(Boolean).join(", ");

    chunksToInsert.push({
      id: chunkId,
      scan_id: scanId,
      category: "vulnerability",
      title,
      content,
      severity: f.severity,
      swc: f.swc ?? null,
      detector: f.detector,
      contract_name: contractName,
      target_address: targetAddress ?? null,
      chain_id: chainId ?? "ethereum",
      keywords,
      vector_data: null,
      metadata_json: JSON.stringify({
        locationFn: f.locationFn,
        locationLine: f.locationLine,
        snippet: f.snippet,
        exploitSolidity: f.exploitSolidity,
        remediationSolidity: f.remediationSolidity,
      }),
    });

    // If finding has specific remediation code, create a dedicated remediation chunk
    if (f.remediationSolidity && f.remediationSolidity.trim().length > 10) {
      const remId = `rag-${scanId}-rem-${idx}`;
      chunksToInsert.push({
        id: remId,
        scan_id: scanId,
        category: "remediation",
        title: `Remediation Pattern: Fix for ${f.title}`,
        content: `Remediation strategy for ${f.title} (${f.detector} / ${f.swc ?? "SWC"}):\n\nSolidity Fix Pattern:\n${f.remediationSolidity}\n\nContext:\n${f.walkthrough}`,
        severity: f.severity,
        swc: f.swc ?? null,
        detector: f.detector,
        contract_name: contractName,
        target_address: targetAddress ?? null,
        chain_id: chainId ?? "ethereum",
        keywords: ["remediation", "patch", "fix", f.detector, f.swc ?? "", contractName].filter(Boolean).join(", "),
        vector_data: null,
        metadata_json: JSON.stringify({
          remediationSolidity: f.remediationSolidity,
          locationFn: f.locationFn,
        }),
      });
    }
  }

  // 2. Threat Model & AI Narrative Chunk
  if (aiReview?.threatModelReport || report.aiNarrative) {
    const narrativeText = aiReview?.threatModelReport || report.aiNarrative || "";
    const tmId = `rag-${scanId}-threatmodel`;
    chunksToInsert.push({
      id: tmId,
      scan_id: scanId,
      category: "threat_model",
      title: `Executive Threat Model: ${contractName}`,
      content: `Threat Model Analysis for ${contractName}:\n\n${narrativeText}`,
      severity: report.riskScore > 60 ? "critical" : report.riskScore > 30 ? "high" : "medium",
      swc: null,
      detector: "ai-threat-model",
      contract_name: contractName,
      target_address: targetAddress ?? null,
      chain_id: chainId ?? "ethereum",
      keywords: ["threat model", "attack surface", "risk narrative", contractName].join(", "),
      vector_data: null,
      metadata_json: JSON.stringify({
        riskScore: report.riskScore,
        economicRiskSummary: aiReview?.economicRiskSummary ?? "",
      }),
    });
  }

  // 3. Executable Foundry Test PoC Chunk
  if (aiReview?.foundryTestCode && aiReview.foundryTestCode.trim().length > 20) {
    const pocId = `rag-${scanId}-foundry-poc`;
    chunksToInsert.push({
      id: pocId,
      scan_id: scanId,
      category: "foundry_poc",
      title: `Foundry Exploit PoC Suite: ${contractName}`,
      content: `Executable Foundry test suite (Exploit.t.sol) demonstrating vulnerability exploitation on ${contractName}:\n\n${aiReview.foundryTestCode}`,
      severity: "high",
      swc: null,
      detector: "foundry-poc",
      contract_name: contractName,
      target_address: targetAddress ?? null,
      chain_id: chainId ?? "ethereum",
      keywords: ["foundry", "exploit.t.sol", "poc", "test", contractName].join(", "),
      vector_data: null,
      metadata_json: JSON.stringify({
        foundryTestCode: aiReview.foundryTestCode,
      }),
    });
  }

  // 4. Contract Architecture & Interface Profile Chunk
  const profileId = `rag-${scanId}-profile`;
  const probeSummary = probes && probes.length > 0
    ? probes.map((p) => `${p.name} (${p.selector}): ${p.success ? (p.decodedString || p.decodedNumber || p.decodedAddress || "Returned") : "Reverted"}`).join("; ")
    : "No RPC probes recorded";
  const proxyNote = proxyInfo?.isProxy
    ? `Upgrade Pattern: ${proxyInfo.proxyType} Proxy (Impl: ${proxyInfo.implementationAddress}, Admin: ${proxyInfo.adminAddress ?? "None"})`
    : "Non-proxy direct implementation";

  chunksToInsert.push({
    id: profileId,
    scan_id: scanId,
    category: "contract_profile",
    title: `Contract Architecture & On-Chain Profile: ${contractName}`,
    content: `Architecture Dossier for ${contractName} (${targetAddress ?? "Unspecified Address"} on ${chainId ?? "ethereum"}):\n\n${proxyNote}\n\nCompiler / Pragma: ${report.inventory.compiler ?? report.inventory.pragma ?? "Unknown"}\nFunctions: ${report.inventory.functions.length} detected\nState Variables: ${report.inventory.stateVars.length} detected\nOn-Chain Probes:\n${probeSummary}\n\nInventory Notes:\n${report.inventory.notes.join("\n")}`,
    severity: "architecture",
    swc: null,
    detector: "architecture-profile",
    contract_name: contractName,
    target_address: targetAddress ?? null,
    chain_id: chainId ?? "ethereum",
    keywords: ["architecture", "profile", "probes", proxyInfo?.proxyType ?? "", contractName].filter(Boolean).join(", "),
    vector_data: null,
    metadata_json: JSON.stringify({
      proxyInfo: proxyInfo ?? null,
      probesCount: probes?.length ?? 0,
      functionsCount: report.inventory.functions.length,
    }),
  });

  return chunksToInsert;
}
