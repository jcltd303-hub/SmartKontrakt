import { createServerFn } from "@tanstack/react-start";
import type { PocResult, Report } from "./audit/types";
import type { ProxyAnalysis } from "./audit/proxy-resolver";
import type { CallProbeResult } from "./audit/simulator";
import type { AiSecurityReview } from "./audit/ai-review.server";
import type { ScanSummary } from "./audit/persist.server";
import type { BuildInfo } from "./build-info";

const MAX_CHARS = 120_000;

/** Effective DB identity (host/user/database, NEVER the password) plus the
 *  EFFECTIVE connection state. Both come from getDbConnectionState() — the
 *  same resolution getSql() performs — so the identity the UI shows is the
 *  configured target together with whether it actually connected (the Oct
 *  2026 Records masquerade: stale password → auth failure → silent embedded
 *  substitute → healthy-looking zeros under the configured project's name).
 *  The substitute is removed: failed and unconfigured are error states,
 *  and `error` carries the classified failure / the unconfigured notice so
 *  surfaces like the workbench header can render them verbatim. */
export type DbIdentity = {
  host: string | null;
  port: string | null;
  user: string | null;
  database: string | null;
  /** remote = configured DB connected and serving; failed = DB configured
   *  but the connection failed; unconfigured = no DB configured. */
  state: "remote" | "failed" | "unconfigured";
  /** The classified connection failure when state is failed; a
   *  "no database configured" notice when unconfigured; null when remote. */
  error: string | null;
};

async function loadDbIdentity(): Promise<DbIdentity> {
  try {
    const { getDbConnectionState } = await import("./db");
    const conn = await getDbConnectionState();
    return {
      host: conn.configured?.host ?? null,
      port: conn.configured?.port ?? null,
      user: conn.configured?.user ?? null,
      database: conn.configured?.database ?? null,
      state: conn.state,
      error:
        conn.state === "failed"
          ? conn.error
          : conn.state === "unconfigured"
            ? "No database configured — set DATABASE_URL (or POSTGRES_URL via the Supabase integration) on the host."
            : null,
    };
  } catch (err) {
    return {
      host: null,
      port: null,
      user: null,
      database: null,
      state: "unconfigured",
      error: err instanceof Error ? err.message : String(err),
    };
  }
}

/**
 * Records list payload (2026-10-22, improvement #2 + no-fallback rework):
 * a failed query is surfaced as { error, db } — the Records tab renders a
 * banner with the actual message and the configured database identity —
 * instead of the old silent [] that made a wrong-project config look like
 * an empty archive. `warning` carries partial-data notices (schema drift);
 * `dbState`/`dbError` carry the effective connection state. `db` (the
 * identity object) is attached whenever there is anything to explain —
 * an error, a warning, or a non-remote state — and is null on a clean
 * remote read, including a genuinely empty archive (error null, state
 * remote: the UI renders "archive is empty", not a failure).
 */
export type ScansListPayload = {
  summaries: ScanSummary[];
  error: string | null;
  warning: string | null;
  dbState: "remote" | "failed" | "unconfigured";
  dbError: string | null;
  db: DbIdentity | null;
};

export const listScans = createServerFn({ method: "GET" })
  .validator((input?: { limit?: number; offset?: number }) => input)
  .handler(async ({ data }): Promise<ScansListPayload> => {
    const opts = (data ?? {}) as { limit?: number; offset?: number };
    const { listScanSummaries } = await import("./audit/persist.server");
    const result = await listScanSummaries(opts);
    const needsDb = Boolean(result.error || result.warning || result.dbState !== "remote");
    return {
      summaries: result.summaries,
      error: result.error,
      warning: result.warning,
      dbState: result.dbState,
      dbError: result.dbError,
      db: needsDb ? await loadDbIdentity() : null,
    };
  });

/** True totals for the Records stat cards (not per-page sums). Same
 *  surfacing contract as listScans: stats and list fail independently —
 *  one bad query never zeroes the other. */
export const getScansStatsFn = createServerFn({ method: "GET" }).handler(async () => {
  const { getScansStats } = await import("./audit/persist.server");
  const result = await getScansStats();
  const needsDb = Boolean(result.error || result.warning || result.dbState !== "remote");
  return {
    stats: result.stats,
    error: result.error,
    warning: result.warning,
    dbState: result.dbState,
    dbError: result.dbError,
    db: needsDb ? await loadDbIdentity() : null,
  };
});

/**
 * Which database the app is actually reading (host/user/database, NEVER
 * the password). The Records tab renders this next to "Connected" so a
 * wrong-project mismatch is visible instead of showing 0 rows silently.
 * When no database is configured, returns { error } instead of throwing,
 * so the UI can show the fix instead of crashing.
 */
export const getDbInfo = createServerFn({ method: "GET" }).handler(async () => loadDbIdentity());

/**
 * Database size guardrail (improvement #3): total size + largest tables.
 * Fails soft by contract — { totalBytes: null, error } on any failure —
 * so the Records tab shows "size unavailable" instead of breaking.
 */
export const getDatabaseSizeFn = createServerFn({ method: "GET" }).handler(async () => {
  const { getDatabaseSize } = await import("./audit/persist.server");
  const result = await getDatabaseSize();
  return {
    ...result,
    db: result.error || result.dbState !== "remote" ? await loadDbIdentity() : null,
  };
});

/**
 * Build stamp (improvement #6): the deployed commit (VERCEL_GIT_COMMIT_SHA,
 * "dev" when unset) + the current analyzer stamp, rendered in the header so
 * a stale bundle is visible at a glance. No user-set env vars required.
 */
export const getBuildInfoFn = createServerFn({ method: "GET" }).handler(async (): Promise<BuildInfo> => {
  const { resolveBuildInfo } = await import("./build-info");
  const { analyzerStamp } = await import("./audit/analyzer-version");
  return resolveBuildInfo(process.env, analyzerStamp());
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
  const { loadSupabaseDbConfig, buildSupabasePostgresUrl, maskPostgresUrl, configFileWritable } =
    await import("./supabase-db.server");
  const { getDatabaseInfo, resolveDatabaseUrlDetailed, databaseEnvProbes } = await import("./db");
  const cfg = loadSupabaseDbConfig();
  const dbInfo = await getDatabaseInfo();
  const builtUrl = buildSupabasePostgresUrl(cfg);
  // The environment is the source of truth on a hosted deployment: it is the
  // only channel the Supabase integration can write to, and the config file
  // cannot even be created there.
  const envSource = resolveDatabaseUrlDetailed();

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
    env: {
      configured: Boolean(envSource),
      from: envSource?.from ?? "",
      maskedUrl: envSource ? maskPostgresUrl(envSource.url) : "",
      // Names and presence only — never a value.
      vars: databaseEnvProbes(),
    },
    configFileWritable: configFileWritable(),
    activeUrlMasked: envSource
      ? maskPostgresUrl(envSource.url)
      : builtUrl
        ? maskPostgresUrl(builtUrl)
        : dbInfo.databaseUrlMasked || "",
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

    // Nothing typed: fall back to the environment, which is what the Supabase
    // integration populates. Without this, "Test connection" reported
    // "specify a project reference" on a deployment that was already wired up.
    let source = targetUrl ? "input" : "";
    if (!targetUrl) {
      const { resolveDatabaseUrlDetailed } = await import("./db");
      const envSource = resolveDatabaseUrlDetailed();
      if (envSource) {
        targetUrl = envSource.url;
        source = envSource.from;
      }
    }

    if (!targetUrl) {
      const { DATABASE_ENV_VARS } = await import("./db-env");
      return {
        ok: false,
        message:
          "No connection string to test. Enter a project reference, or set one of these environment variables on your host: " +
          DATABASE_ENV_VARS.map((v) => v.name).join(", ") +
          " (the Vercel Supabase integration sets POSTGRES_URL).",
      };
    }

    return { ...(await testPostgresConnection(targetUrl)), source };
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
      configFileWritable,
    } = await import("./supabase-db.server");
    const { switchDatabase, resolveDatabaseUrlDetailed } = await import("./db");

    if (!configFileWritable()) {
      const envSource = resolveDatabaseUrlDetailed();
      throw new Error(
        "This deployment's filesystem is read-only, so a saved Supabase configuration cannot persist here. " +
          (envSource
            ? `The database URL is already supplied by the environment (${envSource.from}) and is used automatically — nothing needs saving.`
            : "Set the Supabase integration's environment variables on your host (POSTGRES_URL, POSTGRES_PRISMA_URL or POSTGRES_URL_NON_POOLING) and redeploy."),
      );
    }

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

