import { createServerFn } from "@tanstack/react-start";
import type { PocResult, Report } from "./audit/types";
import type { ProxyAnalysis } from "./audit/proxy-resolver";
import type { CallProbeResult } from "./audit/simulator";
import type { AiSecurityReview } from "./audit/ai-review.server";

const MAX_CHARS = 120_000;

export const listScans = createServerFn({ method: "GET" })
  .validator((input?: { limit?: number; offset?: number }) => input)
  .handler(async ({ data }) => {
    const opts = (data ?? {}) as { limit?: number; offset?: number };
    const { listScanSummaries } = await import("./audit/persist.server");
    return listScanSummaries(opts);
  });

/** True totals for the Records stat cards (not per-page sums). */
export const getScansStatsFn = createServerFn({ method: "GET" }).handler(async () => {
  const { getScansStats } = await import("./audit/persist.server");
  return getScansStats();
});

/**
 * Which database the app is actually reading (host/user/database, NEVER
 * the password). The Records tab renders this next to "Connected" so a
 * wrong-project mismatch is visible instead of showing 0 rows silently.
 * When no database is configured, returns { error } instead of throwing,
 * so the UI can show the fix instead of crashing.
 */
export const getDbInfo = createServerFn({ method: "GET" }).handler(async () => {
  try {
    const { getActiveDatabaseUrl } = await import("./db");
    const url = new URL(getActiveDatabaseUrl());
    return {
      host: url.hostname,
      port: url.port,
      user: decodeURIComponent(url.username),
      database: decodeURIComponent(url.pathname.replace(/^\//, "")),
      error: null as string | null,
    };
  } catch (err) {
    return {
      host: null as string | null,
      port: null as string | null,
      user: null as string | null,
      database: null as string | null,
      error: err instanceof Error ? err.message : String(err),
    };
  }
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
    const { assertAdminToken } = await import("./admin-guard.server");
    assertAdminToken();
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
      pocResult?: PocResult | null;
    };
    if (!val.label || !val.report || typeof val.body !== "string") {
      throw new Error("Missing mandatory audit report fields");
    }
    return val;
  })
  .handler(async ({ data }) => {
    const { assertAdminToken } = await import("./admin-guard.server");
    assertAdminToken();
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
    const { assertAdminToken } = await import("./admin-guard.server");
    assertAdminToken();
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
    const { assertAdminToken } = await import("./admin-guard.server");
    assertAdminToken();
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
    const { assertAdminToken } = await import("./admin-guard.server");
    assertAdminToken();
    const { deleteRagChunk } = await import("./audit/rag.server");
    await deleteRagChunk(data.id);
    return { ok: true as const };
  });

export const getDatabaseStatusFn = createServerFn({ method: "GET" }).handler(async () => {
  const { loadSupabaseDbConfig, buildSupabasePostgresUrl, maskPostgresUrl } = await import("./supabase-db.server");
  const { getDatabaseInfo } = await import("./db");
  const cfg = loadSupabaseDbConfig();
  const dbInfo = await getDatabaseInfo();
  const builtUrl = buildSupabasePostgresUrl(cfg);

  return {
    config: {
      projectName: cfg.projectName,
      projectRef: cfg.projectRef,
      region: cfg.region,
      host: cfg.host,
      port: cfg.port,
      database: cfg.database,
      user: cfg.user,
      mode: cfg.mode,
      customUrl: cfg.customUrl ? maskPostgresUrl(cfg.customUrl) : "",
      active: cfg.active,
      // Provide whether password is configured
      hasPassword: Boolean(cfg.password),
    },
    activeUrlMasked: builtUrl ? maskPostgresUrl(builtUrl) : (dbInfo.databaseUrlMasked || ""),
    dbInfo,
  };
});

export const testDatabaseConnectionFn = createServerFn({ method: "POST" })
  .validator((input: unknown) => {
    const val = (input && typeof input === "object" ? input : {}) as {
      url?: string;
      projectRef?: string;
      password?: string;
      host?: string;
      port?: number;
      database?: string;
      user?: string;
      mode?: "pooler" | "direct" | "custom";
      region?: string;
    };
    return val;
  })
  .handler(async ({ data }) => {
    const { assertAdminToken } = await import("./admin-guard.server");
    assertAdminToken();
    const {
      loadSupabaseDbConfig,
      buildSupabasePostgresUrl,
      testPostgresConnection,
    } = await import("./supabase-db.server");

    let targetUrl = data.url?.trim() || "";
    if (!targetUrl && (data.projectRef || data.host)) {
      const cfg = loadSupabaseDbConfig();
      targetUrl = buildSupabasePostgresUrl({
        ...cfg,
        projectRef: data.projectRef || cfg.projectRef,
        password: data.password || cfg.password,
        host: data.host || cfg.host,
        port: data.port || cfg.port,
        database: data.database || cfg.database,
        user: data.user || cfg.user,
        mode: data.mode || cfg.mode,
        region: data.region || cfg.region,
      });
    }

    if (!targetUrl) {
      return { ok: false, message: "Please specify a Supabase Project Reference ID or full connection string." };
    }

    return testPostgresConnection(targetUrl);
  });

export const saveDatabaseConfigFn = createServerFn({ method: "POST" })
  .validator((input: unknown) => {
    if (!input || typeof input !== "object") throw new Error("Invalid payload");
    const val = input as {
      projectName?: string;
      projectRef: string;
      password?: string;
      host?: string;
      port?: number;
      database?: string;
      user?: string;
      mode?: "pooler" | "direct" | "custom";
      region?: string;
      customUrl?: string;
      active: boolean;
    };
    return val;
  })
  .handler(async ({ data }) => {
    const { assertAdminToken } = await import("./admin-guard.server");
    assertAdminToken();
    const {
      saveSupabaseDbConfig,
      buildSupabasePostgresUrl,
      testPostgresConnection,
      applyMigrationsToPostgres,
    } = await import("./supabase-db.server");
    const { switchDatabase } = await import("./db");

    const saved = saveSupabaseDbConfig({
      projectName: data.projectName || "SmartKontrakt",
      projectRef: data.projectRef,
      password: data.password,
      host: data.host,
      port: data.port,
      database: data.database,
      user: data.user,
      mode: data.mode || "pooler",
      region: data.region || "us-west-2",
      customUrl: data.customUrl,
      active: data.active,
    });

    const targetUrl = buildSupabasePostgresUrl(saved);

    if (saved.active) {
      if (!targetUrl) {
        throw new Error("Cannot activate Supabase database without a Project Reference ID or Connection URL.");
      }

      // Test connection
      const testRes = await testPostgresConnection(targetUrl);
      if (!testRes.ok) {
        throw new Error(`Database connection test failed: ${testRes.message}`);
      }

      // Apply migrations
      const migRes = await applyMigrationsToPostgres(targetUrl);
      if (!migRes.ok) {
        throw new Error(`Connected, but migrations failed: ${migRes.message}`);
      }

      // Activate connection
      switchDatabase(targetUrl);

      return {
        ok: true,
        message: `Connected to Supabase project '${saved.projectName}' (${migRes.message})`,
        appliedMigrations: migRes.appliedCount,
      };
    } else {
      switchDatabase(null);
      return {
        ok: true,
        message: "Supabase connection configuration updated.",
        appliedMigrations: 0,
      };
    }
  });

export const disconnectDatabaseFn = createServerFn({ method: "POST" }).handler(async () => {
  const { assertAdminToken } = await import("./admin-guard.server");
  assertAdminToken();
  const { resetDatabasePool } = await import("./db");
  resetDatabasePool();
  return { ok: true, message: "Database connection pool refreshed." };
});

export const getRecentHighSeverityFindingsFn = createServerFn({ method: "GET" })
  .validator((input?: { limit?: number; offset?: number; severityFilter?: "all" | "critical" | "high" }) => input)
  .handler(async ({ data }) => {
    const { getRecentHighSeverityFindings } = await import("./audit/persist.server");
    return getRecentHighSeverityFindings(data);
  });

export const saveFindingPocResultFn = createServerFn({ method: "POST" })
  .validator((input: unknown) => {
    if (!input || typeof input !== "object") throw new Error("Invalid payload");
    const val = input as {
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
    };
    if (!val.findingId || !val.scanId) throw new Error("Missing findingId or scanId");
    return val;
  })
  .handler(async ({ data }) => {
    const { assertAdminToken } = await import("./admin-guard.server");
    assertAdminToken();
    const { saveFindingPocResult } = await import("./audit/persist.server");
    await saveFindingPocResult(data);
    return { ok: true };
  });

