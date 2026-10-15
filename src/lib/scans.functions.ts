import { createServerFn } from "@tanstack/react-start";
import type { Report } from "./audit/types";
import type { ProxyAnalysis } from "./audit/proxy-resolver";
import type { CallProbeResult } from "./audit/simulator";
import type { AiSecurityReview } from "./audit/ai-review.server";

const MAX_CHARS = 120_000;

export const listScans = createServerFn({ method: "GET" }).handler(async () => {
  const { listScanSummaries } = await import("./audit/persist.server");
  return listScanSummaries();
});

export const getScan = createServerFn({ method: "GET" })
  .validator((input: unknown) => {
    if (!input || typeof input !== "object" || !("id" in input) || typeof input.id !== "string") {
      throw new Error("Missing audit id");
    }
    return { id: input.id };
  })
  .handler(async ({ data }) => {
    const { loadScan } = await import("./audit/persist.server");
    const scan = await loadScan(data.id);
    if (!scan) throw new Error("That audit is no longer in the archive.");
    return scan;
  });

export const analyzeContract = createServerFn({ method: "POST" })
  .validator((input: unknown) => {
    if (!input || typeof input !== "object") throw new Error("Missing contract");
    const body = "body" in input && typeof input.body === "string" ? input.body.replaceAll("\0", "") : "";
    const labelRaw = "label" in input && typeof input.label === "string" ? input.label : "";
    if (!body.trim()) throw new Error("Paste Solidity source or runtime bytecode first.");
    if (body.length > MAX_CHARS) throw new Error("Keep the paste under 120,000 characters.");
    const label = labelRaw.replace(/\s+/g, " ").trim().slice(0, 100) || "Untitled contract";
    return { body, label };
  })
  .handler(async ({ data }) => {
    const { runAndStore } = await import("./audit/persist.server");
    return runAndStore(data);
  });

export const saveComprehensiveScanFn = createServerFn({ method: "POST" })
  .validator((input: unknown) => {
    if (!input || typeof input !== "object") throw new Error("Invalid payload");
    const val = input as {
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
    if (!val.label || !val.report || typeof val.body !== "string") {
      throw new Error("Missing mandatory audit report fields");
    }
    return val;
  })
  .handler(async ({ data }) => {
    const { saveComprehensiveRecord } = await import("./audit/persist.server");
    return saveComprehensiveRecord(data);
  });

export const saveBatchComprehensiveScansFn = createServerFn({ method: "POST" })
  .validator((input: unknown) => {
    if (!input || typeof input !== "object" || !("records" in input) || !Array.isArray(input.records)) {
      throw new Error("Invalid batch payload: records array required");
    }
    return input as { records: import("./audit/persist.server").ComprehensiveRecordInput[] };
  })
  .handler(async ({ data }) => {
    const { validateAuditBatch } = await import("./audit/bulk-persist.server");
    validateAuditBatch(data.records);
    const { saveBatchComprehensiveRecords } = await import("./audit/persist.server");
    return saveBatchComprehensiveRecords(data.records);
  });

export const removeScan = createServerFn({ method: "POST" })
  .validator((input: unknown) => {
    if (!input || typeof input !== "object" || !("id" in input) || typeof input.id !== "string") {
      throw new Error("Missing audit id");
    }
    return { id: input.id };
  })
  .handler(async ({ data }) => {
    const { deleteScan } = await import("./audit/persist.server");
    await deleteScan(data.id);
    return { ok: true as const };
  });

export const queryRagKnowledgebaseFn = createServerFn({ method: "POST" })
  .validator((input: unknown) => {
    if (!input || typeof input !== "object") return { query: "" };
    const val = input as { query?: string; category?: string; minSeverity?: string; limit?: number };
    return {
      query: typeof val.query === "string" ? val.query : "",
      category: typeof val.category === "string" ? val.category : undefined,
      minSeverity: typeof val.minSeverity === "string" ? val.minSeverity : undefined,
      limit: typeof val.limit === "number" ? val.limit : 30,
    };
  })
  .handler(async ({ data }) => {
    const { queryRagKnowledgebase } = await import("./audit/rag.server");
    return queryRagKnowledgebase(data);
  });

export const listRagChunksFn = createServerFn({ method: "GET" })
  .validator((input: unknown) => {
    const limit = input && typeof input === "object" && "limit" in input && typeof input.limit === "number" ? input.limit : 80;
    return { limit };
  })
  .handler(async ({ data }) => {
    const { listRagKnowledgeChunks } = await import("./audit/rag.server");
    return listRagKnowledgeChunks(data.limit);
  });

export const deleteRagChunkFn = createServerFn({ method: "POST" })
  .validator((input: unknown) => {
    if (!input || typeof input !== "object" || !("id" in input) || typeof input.id !== "string") {
      throw new Error("Missing chunk id");
    }
    return { id: input.id };
  })
  .handler(async ({ data }) => {
    const { deleteRagChunk } = await import("./audit/rag.server");
    await deleteRagChunk(data.id);
    return { ok: true as const };
  });
