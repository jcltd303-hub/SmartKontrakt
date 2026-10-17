import { pendingMigrations } from "../../scripts/migration-plan.mjs";
import { createSqlClient, type Sql } from "./sql-client";
import { EMBEDDED_MIGRATIONS } from "./migrations-sql";
import {
  loadSupabaseDbConfig,
  buildSupabasePostgresUrl,
  hasSupabaseDbConfig,
  maskPostgresUrl,
} from "./supabase-db.server";
export type { Sql } from "./sql-client";

/** Supported database backends: Supabase PostgreSQL (primary) or local embedded PGLite (fallback / offline). */
export type DbSource = "supabase" | "local";

// An empty/whitespace value (an easy misconfig in deploy UIs) must mean
// "unset" — otherwise production would silently fail.
function cleanPostgresUrl(value: string | undefined): string | undefined {
  const trimmed = value?.trim();
  if (!trimmed) return undefined;
  if (trimmed.startsWith("postgresql://") || trimmed.startsWith("postgres://")) {
    return trimmed;
  }
  return undefined;
}

/**
 * Resolve the server database URL from the environment.
 *
 * Priority:
 * 1. DATABASE_URL — explicit override.
 * 2. Vercel Supabase integration vars (in serverless-preferred order):
 *    POSTGRES_PRISMA_URL (pooler + pgbouncer), POSTGRES_URL (pooler),
 *    POSTGRES_URL_NON_POOLING (direct).
 */
export function resolveDatabaseUrlFromEnv(): string | undefined {
  if (typeof process === "undefined") return undefined;
  const env = process.env;
  return (
    cleanPostgresUrl(env.DATABASE_URL) ??
    cleanPostgresUrl(env.POSTGRES_PRISMA_URL) ??
    cleanPostgresUrl(env.POSTGRES_URL) ??
    cleanPostgresUrl(env.POSTGRES_URL_NON_POOLING)
  );
}

const databaseUrl = resolveDatabaseUrlFromEnv();

export function getActiveDatabaseUrl(): string {
  if (typeof window !== "undefined") return "";
  if (globalRef.__activeDatabaseUrl__) return globalRef.__activeDatabaseUrl__;

  // 1. Environment: DATABASE_URL override, then Vercel Supabase integration.
  if (databaseUrl) {
    return databaseUrl;
  }

  // 2. Saved config file (local dev / Supabase Config UI). Only when explicitly active.
  if (hasSupabaseDbConfig()) {
    try {
      const cfg = loadSupabaseDbConfig();
      if (cfg.active) {
        const url = buildSupabasePostgresUrl(cfg);
        if (url && (url.startsWith("postgresql://") || url.startsWith("postgres://"))) {
          return url;
        }
      }
    } catch {
      // fall through
    }
  }

  return "";
}

let activeDbSource: DbSource = "supabase";

export const dbSource: DbSource = "supabase";

export function getActiveDbSource(): DbSource {
  return activeDbSource;
}

const globalRef = globalThis as typeof globalThis & {
  __pgSqlPromise__?: Promise<Sql>;
  __pgliteSqlPromise__?: Promise<Sql>;
  __pgliteInstance__?: any;
  __activeDatabaseUrl__?: string;
};

let sqlPromise: Promise<Sql> | null = null;

const OID_INT8 = 20;
const OID_DATE = 1082;
const OID_INTERVAL = 1186;
const identity = (v: string) => v;

export function resetDatabasePool(): void {
  globalRef.__pgSqlPromise__ = undefined;
  globalRef.__pgliteSqlPromise__ = undefined;
  sqlPromise = null;
}

export function switchDatabase(url: string | null): void {
  globalRef.__activeDatabaseUrl__ = url || undefined;
  resetDatabasePool();
}

/**
 * Creates the local embedded PGLite database instance and applies all migrations.
 */
async function createPgliteSql(): Promise<Sql> {
  if (globalRef.__pgliteSqlPromise__) return globalRef.__pgliteSqlPromise__;

  globalRef.__pgliteSqlPromise__ = (async () => {
    const { PGlite } = await import("@electric-sql/pglite");
    const pg = new PGlite();
    await pg.waitReady;

    // Apply migrations to PGLite
    await pg.exec(
      "CREATE TABLE IF NOT EXISTS _migrations (name TEXT PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT now())",
    );
    const doneRows = await pg.query<{ name: string }>("SELECT name FROM _migrations");
    const done = doneRows.rows.map((r) => r.name);

    const migrationsByName: Record<string, string> = { ...EMBEDDED_MIGRATIONS };
    if (typeof import.meta.glob === "function") {
      const globbed = import.meta.glob("/migrations/*.sql", {
        query: "?raw",
        import: "default",
        eager: true,
      }) as Record<string, string>;
      for (const [key, value] of Object.entries(globbed)) {
        migrationsByName[key.split("/").pop() ?? key] = value;
      }
    }

    const pending = pendingMigrations(Object.keys(migrationsByName), done);
    for (const { name, path: mPath } of pending) {
      const sqlContent = migrationsByName[mPath];
      if (sqlContent) {
        await pg.exec(sqlContent);
        await pg.query("INSERT INTO _migrations (name) VALUES ($1)", [name]);
      }
    }

    globalRef.__pgliteInstance__ = pg;
    activeDbSource = "local";

    return createSqlClient(
      async <T>(text: string, params: unknown[]) => {
        const res = await pg.query<T>(text, params);
        return res.rows;
      },
      (work) =>
        pg.transaction((tx) =>
          work(async <T>(text: string, params: unknown[]) => {
            const res = await tx.query<T>(text, params);
            return res.rows;
          }),
        ),
    );
  })();

  return globalRef.__pgliteSqlPromise__;
}

function createSupabaseSql(customUrl?: string): Promise<Sql> {
  const rawTargetUrl = customUrl || getActiveDatabaseUrl();
  // Strip any inline sslmode parameter so node-postgres uses the explicit ssl configuration
  const targetUrl = rawTargetUrl
    ? rawTargetUrl.replace(/([?&])sslmode=[^&]*(&|$)/, "$1").replace(/[?&]$/, "")
    : rawTargetUrl;

  globalRef.__pgSqlPromise__ ??= (async () => {
    // node-postgres (`pg`) with Supabase pooler SSL configuration
    const { Pool, types } = await import("pg");
    types.setTypeParser(OID_INT8, Number);
    types.setTypeParser(OID_DATE, identity);
    types.setTypeParser(OID_INTERVAL, identity);

    const pool = new Pool({
      connectionString: targetUrl,
      ssl: { rejectUnauthorized: false },
      max: 4,
      idleTimeoutMillis: 30_000,
      connectionTimeoutMillis: 10_000,
      query_timeout: 45_000,
      allowExitOnIdle: true,
    });

    pool.on("error", (err) => {
      console.warn("[db] Supabase idle connection note:", err.message);
    });

    // Ensure migrations are auto-applied on the target Supabase PostgreSQL database
    const client = await pool.connect();
    try {
      await client.query(
        "CREATE TABLE IF NOT EXISTS _migrations (name TEXT PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT now())",
      );
      const doneRows = await client.query<{ name: string }>("SELECT name FROM _migrations");
      const done = doneRows.rows.map((r) => r.name);

      const migrationsByName: Record<string, string> = { ...EMBEDDED_MIGRATIONS };
      if (typeof import.meta.glob === "function") {
        const globbed = import.meta.glob("/migrations/*.sql", {
          query: "?raw",
          import: "default",
          eager: true,
        }) as Record<string, string>;
        for (const [key, value] of Object.entries(globbed)) {
          migrationsByName[key.split("/").pop() ?? key] = value;
        }
      }
      const pending = pendingMigrations(Object.keys(migrationsByName), done);
      for (const { name, path: mPath } of pending) {
        await client.query("BEGIN");
        try {
          await client.query(migrationsByName[mPath]);
          await client.query("INSERT INTO _migrations (name) VALUES ($1)", [name]);
          await client.query("COMMIT");
        } catch (mErr) {
          await client.query("ROLLBACK");
          throw mErr;
        }
      }
    } finally {
      client.release();
    }

    activeDbSource = "supabase";

    return createSqlClient(
      async <T>(text: string, params: unknown[]) => {
        const res = await pool.query(text, params);
        return res.rows as T[];
      },
      async (work) => {
        const client = await pool.connect();
        try {
          await client.query("BEGIN");
          const result = await work(
            async <T>(text: string, params: unknown[]) =>
              (await client.query(text, params)).rows as T[],
          );
          await client.query("COMMIT");
          return result;
        } catch (err) {
          try {
            await client.query("ROLLBACK");
          } catch {
            /* Preserve original error */
          }
          throw err;
        } finally {
          client.release();
        }
      },
    );
  })().catch((err) => {
    globalRef.__pgSqlPromise__ = undefined;
    throw err;
  });

  return globalRef.__pgSqlPromise__;
}

async function createSql(): Promise<Sql> {
  if (typeof window !== "undefined") {
    throw new Error(
      "@/lib/db is server-only — call getSql() from a createServerFn handler " +
        "or a server route loader, never from client code.",
    );
  }
  const url = getActiveDatabaseUrl();
  if (url) {
    try {
      const sql = await createSupabaseSql(url);
      // Quick verification to ensure remote host responds
      await sql`SELECT 1`;
      activeDbSource = "supabase";
      return sql;
    } catch (err) {
      console.warn(
        `[db] Supabase connection to ${maskPostgresUrl(url)} failed (${err instanceof Error ? err.message : String(err)}). Seamlessly falling back to embedded local database.`,
      );
      globalRef.__pgSqlPromise__ = undefined;
    }
  }

  // Fall back gracefully to embedded PGLite
  activeDbSource = "local";
  return createPgliteSql();
}

export async function getDatabaseInfo(): Promise<{
  source: DbSource;
  databaseUrlMasked?: string;
  connected: boolean;
  message: string;
}> {
  const activeUrl = getActiveDatabaseUrl();
  if (activeUrl && activeDbSource === "supabase") {
    return {
      source: "supabase",
      databaseUrlMasked: maskPostgresUrl(activeUrl),
      connected: true,
      message: "Connected to Supabase PostgreSQL database.",
    };
  }
  return {
    source: "local",
    connected: true,
    message: activeUrl
      ? "Embedded local database active (Supabase connection currently inactive/unreachable)."
      : "Embedded local database active. Connect your live Supabase PostgreSQL in Settings.",
  };
}

/**
 * Get the shared, **server-only** SQL client.
 * Memoized — safe to call per request.
 */
export function getSql(): Promise<Sql> {
  sqlPromise ??= createSql().catch((err) => {
    sqlPromise = null; // don't memoize failures — let the next call retry
    throw err;
  });
  return sqlPromise;
}

/**
 * Returns the underlying PGLite instance when local embedded DB is active.
 */
export async function getPglite(): Promise<any> {
  if (globalRef.__pgliteInstance__) return globalRef.__pgliteInstance__;
  await getSql();
  return globalRef.__pgliteInstance__;
}

/**
 * Finish DB bootstrap before the server handles traffic.
 */
export function ensureDbReady(): Promise<void> {
  return getSql()
    .then(() => undefined)
    .catch((err) => {
      console.warn("[db] DB bootstrap notice:", err instanceof Error ? err.message : String(err));
    });
}
