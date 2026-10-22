import { pendingMigrations } from "../../scripts/migration-plan.mjs";
import { createSqlClient, type Sql } from "./sql-client";
import { EMBEDDED_MIGRATIONS } from "./migrations-sql";
import {
  DATABASE_ENV_VARS,
  databaseEnvInventory,
  resolveDatabaseUrl,
  resolveDirectDatabaseUrl,
} from "./db-env.ts";
import {
  loadSupabaseDbConfig,
  buildSupabasePostgresUrl,
  hasSupabaseDbConfig,
  maskPostgresUrl,
} from "./supabase-db.server";
export type { Sql } from "./sql-client";

/** Supported database backends: Supabase PostgreSQL (primary) or local embedded PGLite (fallback / offline). */
export type DbSource = "supabase" | "local";

// Cleaning (trim, empty/placeholder rejection, credential encoding) lives in
// db-env.ts, so the status surface, the tests and this module all apply exactly
// the same rules. An empty value in a deploy UI must mean "unset" — otherwise
// production silently falls back to an ephemeral database.

/**
 * Resolve the server database URL from the environment, with provenance.
 *
 * The Vercel Supabase integration injects POSTGRES_URL / POSTGRES_PRISMA_URL /
 * POSTGRES_URL_NON_POOLING and never DATABASE_URL, so a deployment wired up
 * through the integration read as unconfigured. The candidate list and the
 * order live in db-env.ts; this reports which name actually supplied the URL so
 * a status surface can say so instead of leaving it to guesswork.
 */
export function resolveDatabaseUrlDetailed(): { url: string; from: string } | undefined {
  if (typeof process === "undefined") return undefined;
  return resolveDatabaseUrl(process.env);
}

export function resolveDatabaseUrlFromEnv(): string | undefined {
  return resolveDatabaseUrlDetailed()?.url;
}

/**
 * Which database variables this host provides — names, roles and presence only,
 * never a value. This is what answers "I set up the integration, why is it not
 * connecting?".
 */
export function databaseEnvProbes(): { name: string; role: string; present: boolean }[] {
  if (typeof process === "undefined") return [];
  return databaseEnvInventory(process.env);
}

export { DATABASE_ENV_VARS };

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
  /**
   * Why the last Supabase attempt failed, if it did. The fallback to embedded
   * PGLite is silent by design (the app keeps working), but on a serverless
   * host PGLite is ephemeral — so an unreported fallback looks exactly like
   * working connectivity while writing every row into the void.
   */
  __lastDbError__?: { message: string; urlMasked: string; at: string };
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

/** node-postgres takes `ssl` explicitly, so drop any inline sslmode. */
function stripSslmode(url: string): string {
  return url.replace(/([?&])sslmode=[^&]*(&|$)/, "$1").replace(/[?&]$/, "");
}

type QueryRunner = { query: (text: string, params?: unknown[]) => Promise<{ rows: Record<string, unknown>[] }> };

/** Every pending migration, recorded in _migrations as it lands. */
async function applyMigrationsOver(client: QueryRunner): Promise<number> {
  await client.query(
    "CREATE TABLE IF NOT EXISTS _migrations (name TEXT PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT now())",
  );
  const doneRows = await client.query("SELECT name FROM _migrations");
  const done = doneRows.rows.map((r) => String(r.name));

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
  return pending.length;
}

function createSupabaseSql(customUrl?: string): Promise<Sql> {
  const rawTargetUrl = customUrl || getActiveDatabaseUrl();
  const targetUrl = rawTargetUrl ? stripSslmode(rawTargetUrl) : rawTargetUrl;

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

    // Migrations run over a DIRECT connection when the host publishes one. A
    // transaction-mode pooler (pgbouncer, port 6543) can reject or mis-scope
    // multi-statement DDL, and a migration failure here takes the whole
    // connection down with it — the app then fell back to ephemeral local
    // storage and reported it as "Supabase unreachable".
    const direct = typeof process === "undefined" ? undefined : resolveDirectDatabaseUrl(process.env);
    if (direct && direct.url !== targetUrl) {
      const migrationPool = new Pool({
        connectionString: stripSslmode(direct.url),
        ssl: { rejectUnauthorized: false },
        max: 1,
        connectionTimeoutMillis: 15_000,
      });
      try {
        const migClient = await migrationPool.connect();
        try {
          const applied = await applyMigrationsOver(migClient);
          if (applied > 0) console.log(`[db] applied ${applied} migration(s) over ${direct.from} (direct)`);
        } finally {
          migClient.release();
        }
      } finally {
        await migrationPool.end().catch(() => undefined);
      }
    } else {
      const client = await pool.connect();
      try {
        const applied = await applyMigrationsOver(client);
        if (applied > 0) console.log(`[db] applied ${applied} migration(s)`);
      } finally {
        client.release();
      }
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
      globalRef.__lastDbError__ = undefined;
      return sql;
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      // Recorded, not just logged: on a serverless host the PGLite fallback is
      // ephemeral, so a silent fallback writes every row into the void while
      // looking like working connectivity.
      globalRef.__lastDbError__ = { message, urlMasked: maskPostgresUrl(url), at: new Date().toISOString() };
      console.warn(
        `[db] Supabase connection to ${maskPostgresUrl(url)} failed (${message}). Falling back to embedded local database, which does NOT persist on a serverless host.`,
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
  /** Which environment variable supplied the URL, when one did. */
  envFrom?: string;
  connected: boolean;
  /** Set when a Supabase connection was attempted and failed. */
  lastError?: { message: string; urlMasked: string; at: string };
  /** True when the fallback is ephemeral, so nothing written here survives. */
  ephemeralFallback: boolean;
  message: string;
}> {
  const activeUrl = getActiveDatabaseUrl();
  const envFrom = resolveDatabaseUrlDetailed()?.from;
  if (activeUrl && activeDbSource === "supabase") {
    return {
      source: "supabase",
      databaseUrlMasked: maskPostgresUrl(activeUrl),
      envFrom,
      connected: true,
      ephemeralFallback: false,
      message: envFrom
        ? `Connected to Supabase PostgreSQL database (URL from ${envFrom}).`
        : "Connected to Supabase PostgreSQL database.",
    };
  }
  const lastError = globalRef.__lastDbError__;
  const isServerless = Boolean(
    typeof process !== "undefined" && (process.env.VERCEL || process.env.AWS_LAMBDA_FUNCTION_NAME),
  );
  return {
    source: "local",
    envFrom,
    lastError,
    connected: true,
    // On a serverless host the embedded database lives in the instance and is
    // gone on the next request.
    ephemeralFallback: isServerless,
    message: activeUrl
      ? `Embedded local database active — the Supabase connection to ${maskPostgresUrl(activeUrl)} failed${lastError ? `: ${lastError.message}` : ""}.`
      : envFrom
        ? `Embedded local database active. ${envFrom} is set but did not yield a usable URL.`
        : "Embedded local database active. No database URL found in the environment — checked " +
          DATABASE_ENV_VARS.map((v) => v.name).join(", ") +
          ".",
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
