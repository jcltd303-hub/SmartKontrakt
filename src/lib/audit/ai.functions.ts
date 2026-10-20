import { createServerFn } from "@tanstack/react-start";
import type { Finding, Report } from "./types";
import type { DeepAgentPriorResult } from "./deep-agent.server";
import type { FourbyteResults } from "./fourbyte";

/**
 * Clean the optional fourbyte payload (resolved 4byte names from the
 * report). Caps keys + signatures per key so a hostile payload cannot
 * bloat the prompt. Returns undefined when nothing usable was sent.
 */
function cleanFourbyte(input: unknown): FourbyteResults | undefined {
  if (!input || typeof input !== "object") return undefined;
  const { selectors, topics } = input as {
    selectors?: unknown;
    topics?: unknown;
  };
  const cleanMap = (v: unknown, maxKeys: number): Record<string, string[]> => {
    const out: Record<string, string[]> = {};
    if (!v || typeof v !== "object") return out;
    for (const [k, sigs] of Object.entries(v as Record<string, unknown>)) {
      if (Object.keys(out).length >= maxKeys) break;
      if (typeof k !== "string" || !Array.isArray(sigs)) continue;
      const cleanSigs = sigs
        .filter((s): s is string => typeof s === "string")
        .map((s) => s.slice(0, 500))
        .slice(0, 3);
      if (cleanSigs.length > 0) out[k.slice(0, 100)] = cleanSigs;
    }
    return out;
  };
  const cleaned = {
    selectors: cleanMap(selectors, 50),
    topics: cleanMap(topics, 30),
  };
  if (Object.keys(cleaned.selectors).length === 0 && Object.keys(cleaned.topics).length === 0) {
    return undefined;
  }
  return cleaned;
}

export const requestAiReview = createServerFn({ method: "POST" })
  .validator((input: unknown) => {
    if (!input || typeof input !== "object") {
      throw new Error("Invalid request payload");
    }
    const { contractName, body, findings, fourbyte } = input as {
      contractName?: string;
      body?: string;
      findings?: Finding[];
      fourbyte?: unknown;
    };
    return {
      contractName: contractName || "TargetContract",
      body: typeof body === "string" ? body.slice(0, 30000) : "",
      findings: Array.isArray(findings) ? findings.slice(0, 20) : [],
      fourbyte: cleanFourbyte(fourbyte),
    };
  })
  .handler(async ({ data }) => {
    const { assertAdminToken } = await import("../admin-guard.server");
    assertAdminToken();
    const { generateAiSecurityReview } = await import("./ai-review.server");
    return generateAiSecurityReview(data.contractName, data.body, data.findings, data.fourbyte);
  });

/**
 * Deep Agent: ONE agentic round (LLM proposes hypotheses + PoCs). The
 * browser orchestrates rounds because PoC execution lives on the phone
 * backend, not on Vercel. See deep-agent.server.ts for the loop design.
 */
export const requestDeepAgentRound = createServerFn({ method: "POST" })
  .validator((input: unknown) => {
    if (!input || typeof input !== "object") {
      throw new Error("Invalid request payload");
    }
    const { contractName, body, findings, priorResults, round, fourbyte } = input as {
      contractName?: string;
      body?: string;
      findings?: Finding[];
      priorResults?: DeepAgentPriorResult[];
      round?: number;
      fourbyte?: unknown;
    };
    const cleanPrior: DeepAgentPriorResult[] = Array.isArray(priorResults)
      ? priorResults.slice(0, 20).map((p) => ({
          title: typeof p?.title === "string" ? p.title.slice(0, 300) : "",
          detector: typeof p?.detector === "string" ? p.detector.slice(0, 100) : "",
          outcome:
            p?.outcome === "confirmed" || p?.outcome === "refuted" || p?.outcome === "error"
              ? p.outcome
              : "error",
          pocLogs: typeof p?.pocLogs === "string" ? p.pocLogs.slice(0, 3000) : "",
        }))
      : [];
    return {
      contractName: contractName || "TargetContract",
      body: typeof body === "string" ? body.slice(0, 30000) : "",
      findings: Array.isArray(findings) ? findings.slice(0, 20) : [],
      priorResults: cleanPrior,
      round: typeof round === "number" && round > 0 ? Math.floor(round) : 1,
      fourbyte: cleanFourbyte(fourbyte),
    };
  })
  .handler(async ({ data }) => {
    const { assertAdminToken } = await import("../admin-guard.server");
    assertAdminToken();
    const { runDeepAgentRound } = await import("./deep-agent.server");
    return runDeepAgentRound(
      data.contractName,
      data.body,
      data.findings,
      data.priorResults,
      data.round,
      data.fourbyte,
    );
  });

/**
 * PoC repair: ONE LLM call that fixes a PoC which failed to compile.
 * The caller re-runs the fixed PoC once; there is no second repair
 * (a PoC that fails twice is a dead hypothesis, not a conversation).
 */
export const requestPocRepair = createServerFn({ method: "POST" })
  .validator((input: unknown) => {
    if (!input || typeof input !== "object") {
      throw new Error("Invalid request payload");
    }
    const { contractName, originalCode, errorLogs, body } = input as {
      contractName?: string;
      originalCode?: string;
      errorLogs?: string;
      body?: string;
    };
    if (typeof originalCode !== "string" || originalCode.trim().length === 0) {
      throw new Error("Repair requires the original PoC code");
    }
    return {
      contractName: contractName || "TargetContract",
      originalCode: originalCode.slice(0, 30000),
      errorLogs: typeof errorLogs === "string" ? errorLogs.slice(0, 8000) : "",
      body: typeof body === "string" ? body.slice(0, 30000) : "",
    };
  })
  .handler(async ({ data }) => {
    const { assertAdminToken } = await import("../admin-guard.server");
    assertAdminToken();
    const { repairPocCode } = await import("./deep-agent.server");
    return repairPocCode(data.contractName, data.originalCode, data.errorLogs, data.body);
  });

/**
 * Per-item OpenRouter second pass for the pipeline. Kept separate from the
 * bulk save on purpose: a bulk save with per-record LLM calls blows past the
 * serverless function timeout and stalls the flush at 0 records. The pipeline
 * calls this once per item (when the AI toggle is on), then the bulk save
 * stays pure SQL and fast. Best-effort — the caller never fails an item on it.
 */
export const runSecondPassFn = createServerFn({ method: "POST" })
  .validator((input: unknown) => {
    if (!input || typeof input !== "object") throw new Error("Invalid second-pass payload");
    const { report, body } = input as { report?: Report; body?: string };
    if (!report || typeof report !== "object" || !Array.isArray(report.findings) || !report.inventory) {
      throw new Error("Second pass requires a report with findings and inventory");
    }
    if (typeof body !== "string") throw new Error("Second pass requires the contract body");
    return { report, body };
  })
  .handler(async ({ data }) => {
    const { assertAdminToken } = await import("../admin-guard.server");
    assertAdminToken();
    const { secondPass } = await import("./persist.server");
    return secondPass(data.report, data.body);
  });
