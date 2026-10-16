import { pendingMigrations } from "../../scripts/migration-plan.mjs";
import { createSqlClient, type Sql } from "./sql-client";
import { EMBEDDED_MIGRATIONS } from "./migrations-sql";
import {
  loadSupabaseDbConfig,
  buildSupabasePostgresUrl,
  DEFAULT_SUPABASE_DB_CONFIG,
} from "./supabase-db.server";
export type { Sql } from "./sql-client";

/** Dedicated Supabase PostgreSQL for Vercel production deployment. */
export type DbSource = "supabase";

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
 *
 * The Vercel Supabase integration syncs these vars for preview + production.
 * Reading them here is what actually wires a Vercel deploy to its
 * Vercel-enabled Supabase project — without them the app would fall back
 * to a bundled local config instead of the integration's database.
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

  // 2. Check Supabase saved config
  try {
    const cfg = loadSupabaseDbConfig();
    const url = buildSupabasePostgresUrl(cfg);
    if (url && (url.startsWith("postgresql://") || url.startsWith("postgres://"))) {
      return url;
    }
  } catch {
    // fallback below
  }

  // 3. Fallback to default SmartKontrakt Supabase config
  return buildSupabasePostgresUrl(DEFAULT_SUPABASE_DB_CONFIG);
}

/**
 * Active backend: Supabase PostgreSQL (only Supabase used for Vercel deployment).
 */
export const dbSource: DbSource = "supabase";

export function getActiveDbSource(): DbSource {
  return "supabase";
}

/**
 * Minimal shared SQL surface. Both the tagged-template and `.query()` forms resolve to an array of row objects:
 *
 *   const sql = await getSql();
 *   const rows = await sql`select * from contract_scans where chain = ${chain}`; // parameterized
 *   const rows2 = await sql.query("select * from contract_scans where chain = $1", [chain]);
 */

const globalRef = globalThis as typeof globalThis & {
  __pgSqlPromise__?: Promise<Sql>;
  __activeDatabaseUrl__?: string;
};

let sqlPromise: Promise<Sql> | null = null;

const OID_INT8 = 20;
const OID_DATE = 1082;
const OID_INTERVAL = 1186;
const identity = (v: string) => v;

export function resetDatabasePool(): void {
  globalRef.__pgSqlPromise__ = undefined;
  sqlPromise = null;
}

export function switchDatabase(url: string | null): void {
  globalRef.__activeDatabaseUrl__ = url || undefined;
  resetDatabasePool();
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
      connectionTimeoutMillis: 15_000,
      query_timeout: 60_000,
      allowExitOnIdle: true,
    });

    pool.on("error", (err) => {
      console.error("[db] Supabase idle connection error:", err.message);
    });

    // Ensure migrations are auto-applied on the target Supabase PostgreSQL database
    try {
      const client = await pool.connect();
      try {
        await client.query(
          "CREATE TABLE IF NOT EXISTS _migrations (name TEXT PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT now())",
        );
        const doneRows = await client.query<{ name: string }>("SELECT name FROM _migrations");
        const done = doneRows.rows.map((r) => r.name);
        // Keyed by BASENAME so the same migration from embedded + glob +
        // filesystem sources collapses to one entry — otherwise the loop
        // below would apply it twice and the second `_migrations` INSERT
        // would violate the primary key. Later sources win on disagreement.
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
        } else {
          const fs = await import("node:fs");
          const path = await import("node:path");
          const migDir = path.join(process.cwd(), "migrations");
          if (fs.existsSync(migDir)) {
            const files = fs.readdirSync(migDir).filter((f) => f.endsWith(".sql"));
            for (const file of files) {
              migrationsByName[file] = fs.readFileSync(path.join(migDir, file), "utf-8");
            }
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
    } catch (migErr) {
      console.warn("[db] Supabase auto-migration notice:", migErr instanceof Error ? migErr.message : String(migErr));
    }

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
  return createSupabaseSql(url);
}

export async function getDatabaseInfo(): Promise<{
  source: "supabase";
  databaseUrlMasked?: string;
  connected: boolean;
  message: string;
}> {
  const activeUrl = getActiveDatabaseUrl();
  if (activeUrl) {
    return {
      source: "supabase",
      databaseUrlMasked: activeUrl.replace(/:\/\/([^:]+):([^@]+)@/, "://$1:••••••@"),
      connected: true,
      message: "Connected to Supabase PostgreSQL database (SmartKontrakt).",
    };
  }
  return {
    source: "supabase",
    connected: false,
    message: "Supabase PostgreSQL configuration required.",
  };
}

/**
 * Get the shared, **server-only** SQL client connected to Supabase PostgreSQL.
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
 * Backward compatibility stub — local PGLite is completely removed for Vercel Supabase deployment.
 */
export async function getPglite(): Promise<any> {
  throw new Error("Local PGLite database has been removed. All data is persisted directly to Supabase PostgreSQL.");
}

/**
 * Finish DB bootstrap before the server handles traffic.
 */
export function ensureDbReady(): Promise<void> {
  return getSql()
    .then(() => undefined)
    .catch((err) => {
      console.warn("[db] Supabase connection notice:", err instanceof Error ? err.message : String(err));
    });
}
