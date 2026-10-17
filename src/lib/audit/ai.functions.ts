import { createServerFn } from "@tanstack/react-start";
import type { Finding, Report } from "./types";
import type { DeepAgentPriorResult } from "./deep-agent.server";

export const requestAiReview = createServerFn({ method: "POST" })
  .validator((input: unknown) => {
    if (!input || typeof input !== "object") {
      throw new Error("Invalid request payload");
    }
    const { contractName, body, findings } = input as {
      contractName?: string;
      body?: string;
      findings?: Finding[];
    };
    return {
      contractName: contractName || "TargetContract",
      body: typeof body === "string" ? body.slice(0, 30000) : "",
      findings: Array.isArray(findings) ? findings.slice(0, 20) : [],
    };
  })
  .handler(async ({ data }) => {
    const { generateAiSecurityReview } = await import("./ai-review.server");
    return generateAiSecurityReview(data.contractName, data.body, data.findings);
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
    const { contractName, body, findings, priorResults, round } = input as {
      contractName?: string;
      body?: string;
      findings?: Finding[];
      priorResults?: DeepAgentPriorResult[];
      round?: number;
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
    };
  })
  .handler(async ({ data }) => {
    const { runDeepAgentRound } = await import("./deep-agent.server");
    return runDeepAgentRound(
      data.contractName,
      data.body,
      data.findings,
      data.priorResults,
      data.round,
    );
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
    const { secondPass } = await import("./persist.server");
    return secondPass(data.report, data.body);
  });
