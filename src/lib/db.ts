import { pendingMigrations } from "../../scripts/migration-plan.mjs";
import { createSqlClient, type Sql } from "./sql-client";
import { EMBEDDED_MIGRATIONS } from "./migrations-sql";
import { describeDbError } from "./db-error.ts";
import {
  DATABASE_ENV_VARS,
  classifyDbState,
  databaseEnvInventory,
  resolveDatabaseUrl,
  resolveDirectDatabaseUrl,
  type DbConnectionState,
  type DbStateKind,
} from "./db-env.ts";
import {
  loadSupabaseDbConfig,
  buildSupabasePostgresUrl,
  hasSupabaseDbConfig,
  maskPostgresUrl,
} from "./supabase-db.server";
export type { Sql } from "./sql-client";

/**
 * Which store is serving — there is exactly ONE store now: the configured
 * Supabase PostgreSQL database. The embedded PGlite substitute was REMOVED
 * (Jer, 2026-10-22: "No fallback duh"): it made a failed configured
 * connection (stale password) look like a healthy, empty archive, because
 * queries against the substitute succeeded and returned zeros. A
 * configured-but-unreachable database is "failed" and an absent
 * configuration is "unconfigured" — both are explicit errors everywhere,
 * never a silent switch to another store.
 */
export type DbSource = "supabase" | "failed" | "unconfigured";

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

let activeDbSource: DbSource = "unconfigured";

export function getActiveDbSource(): DbSource {
  return activeDbSource;
}

/**
 * Why the last Supabase connection attempt failed (classified, password-free),
 * or undefined when the last attempt succeeded / none was made. Archive reads
 * surface this as the error instead of presenting fabricated zeros.
 */
export function getLastDbError(): { message: string; urlMasked: string; at: string } | undefined {
  return globalRef.__lastDbError__;
}

export type { DbConnectionState } from "./db-env.ts";

const globalRef = globalThis as typeof globalThis & {
  __pgSqlPromise__?: Promise<Sql>;
  __activeDatabaseUrl__?: string;
  /**
   * Why the last Supabase attempt failed, if it did. There is NO fallback
   * anymore: this error is what getSql() throws and what every surface
   * reports, instead of a substitute store silently absorbing reads and
   * writes and returning zeros.
   */
  __lastDbError__?: { message: string; urlMasked: string; at: string };
  /** Set when migrations could not be applied, without the connection failing. */
  __migrationError__?: { message: string; at: string };
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
  globalRef.__lastDbError__ = undefined;
  resetDatabasePool();
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

    // MIGRATIONS ARE BEST-EFFORT AND MUST NEVER COST THE CONNECTION.
    //
    // Two things go wrong here in practice, and neither means the database is
    // unusable: Supabase's direct host is IPv6-only unless the IPv4 add-on is
    // bought, and a serverless function cannot reach IPv6 at all; and a
    // transaction-mode pooler can reject multi-statement DDL.
    //
    // So: try the direct connection briefly, retry migrations on the pooled
    // one, and if both fail, record it and keep the connection. If the
    // database itself is unreachable (bad credentials, dead host), the
    // caller's verification query fails and getSql() throws — there is no
    // substitute store to downgrade to.
    const failMsg = (e: unknown) => (e instanceof Error ? e.message : String(e));
    let applied = 0;
    try {
      const direct = typeof process === "undefined" ? undefined : resolveDirectDatabaseUrl(process.env);
      if (direct && direct.url !== targetUrl) {
        const migrationPool = new Pool({
          connectionString: stripSslmode(direct.url),
          ssl: { rejectUnauthorized: false },
          max: 1,
          // Short: this is an optimisation, not a prerequisite.
          connectionTimeoutMillis: 5_000,
        });
        try {
          const migClient = await migrationPool.connect();
          try {
            applied = await applyMigrationsOver(migClient);
          } finally {
            migClient.release();
          }
        } catch (directErr) {
          console.warn(
            `[db] migrations over ${direct.from} (direct) failed: ${failMsg(directErr)} — retrying on the pooled connection.`,
          );
          const client = await pool.connect();
          try {
            applied = await applyMigrationsOver(client);
          } finally {
            client.release();
          }
        } finally {
          await migrationPool.end().catch(() => undefined);
        }
      } else {
        const client = await pool.connect();
        try {
          applied = await applyMigrationsOver(client);
        } finally {
          client.release();
        }
      }
      globalRef.__migrationError__ = undefined;
      if (applied > 0) console.log(`[db] applied ${applied} migration(s)`);
    } catch (mErr) {
      globalRef.__migrationError__ = {
        message: describeDbError(mErr, { from: resolveDirectDatabaseUrl(process.env)?.from }),
        at: new Date().toISOString(),
      };
      console.warn(
        `[db] could not apply migrations (${failMsg(mErr)}). Keeping the Supabase connection on the existing schema.`,
      );
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
  if (!url) {
    // Unconfigured is an explicit state, NOT a license to invent a local
    // archive: throwing here is what keeps "no database configured" from
    // ever rendering as an empty Records tab.
    activeDbSource = "unconfigured";
    throw new Error(
      "No database configured: no usable URL from " +
        DATABASE_ENV_VARS.map((v) => v.name).join(", ") +
        " and no active saved Supabase configuration. Set the database URL " +
        "(the Vercel Supabase integration injects POSTGRES_URL) or activate " +
        "one in Supabase Config. There is no local fallback database.",
    );
  }
  try {
    const sql = await createSupabaseSql(url);
    // Quick verification to ensure remote host responds
    await sql`SELECT 1`;
    activeDbSource = "supabase";
    globalRef.__lastDbError__ = undefined;
    return sql;
  } catch (err) {
    // Classified, not echoed: "password authentication failed" reads like a
    // connectivity problem and is not one, and that misreading is expensive.
    const message = describeDbError(err, { from: resolveDatabaseUrlDetailed()?.from });
    globalRef.__lastDbError__ = { message, urlMasked: maskPostgresUrl(url), at: new Date().toISOString() };
    activeDbSource = "failed";
    globalRef.__pgSqlPromise__ = undefined;
    // NO FALLBACK. The configured database failed; the outcome is this
    // error. Substituting an embedded store here is what made Records
    // render TOTAL AUDITS 0 over an archive of 8,931 scans (Oct 2026):
    // every query "succeeded" against the substitute and the UI showed
    // the configured project's name over the substitute's empty tables.
    throw new Error(
      `Database connection failed for ${maskPostgresUrl(url)}: ${message} ` +
        `No fallback database is in use — reads and writes fail until the configured database is reachable.`,
    );
  }
}

/**
 * The EFFECTIVE database state, from the same resolution getSql() performs:
 * forces the (memoized) connection attempt, then classifies the outcome —
 * the configured remote connected, the configured remote FAILED (error
 * carries the classified failure), or nothing is configured at all.
 * Identity surfaces and archive reads share this so the app can never
 * again display the configured project's name over fabricated zeros.
 */
export async function getDbConnectionState(): Promise<DbConnectionState> {
  const url = getActiveDatabaseUrl();
  if (!url) return classifyDbState("", false, undefined);
  try {
    await getSql();
    return classifyDbState(url, true, undefined);
  } catch {
    return classifyDbState(url, false, globalRef.__lastDbError__);
  }
}

export async function getDatabaseInfo(): Promise<{
  source: DbSource;
  /** The effective state — the field surfaces should key on. */
  state: DbStateKind;
  databaseUrlMasked?: string;
  /** Which environment variable supplied the URL, when one did. */
  envFrom?: string;
  /** True ONLY when the configured remote actually connected. */
  connected: boolean;
  /** Set when a Supabase connection was attempted and failed. */
  lastError?: { message: string; urlMasked: string; at: string };
  /** Set when the connection succeeded but migrations could not be applied. */
  migrationError?: { message: string; at: string };
  /** Always false — the embedded fallback is removed, nothing is ephemeral. */
  ephemeralFallback: boolean;
  message: string;
}> {
  const activeUrl = getActiveDatabaseUrl();
  const envFrom = resolveDatabaseUrlDetailed()?.from;
  const conn = await getDbConnectionState();
  if (conn.state === "remote") {
    return {
      source: "supabase",
      state: "remote",
      databaseUrlMasked: maskPostgresUrl(activeUrl),
      envFrom,
      connected: true,
      ephemeralFallback: false,
      migrationError: globalRef.__migrationError__,
      message: `Connected to Supabase PostgreSQL database${envFrom ? ` (URL from ${envFrom})` : ""}.${
        globalRef.__migrationError__ ? ` Migrations could not be applied: ${globalRef.__migrationError__.message}` : ""
      }`,
    };
  }
  if (conn.state === "failed") {
    const lastError = globalRef.__lastDbError__;
    return {
      source: "failed",
      state: "failed",
      databaseUrlMasked: maskPostgresUrl(activeUrl),
      envFrom,
      lastError,
      connected: false,
      ephemeralFallback: false,
      message:
        `Supabase connection FAILED for ${maskPostgresUrl(activeUrl)}: ${conn.error ?? "connection failed"}. ` +
        `No fallback database is in use — the archive is unreachable until this is fixed.`,
    };
  }
  return {
    source: "unconfigured",
    state: "unconfigured",
    envFrom,
    connected: false,
    ephemeralFallback: false,
    message: envFrom
      ? `No database configured. ${envFrom} is set but did not yield a usable URL.`
      : "No database configured. No database URL found in the environment — checked " +
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
 * Finish DB bootstrap before the server handles traffic. A bootstrap
 * failure is logged, not hidden — and it no longer matters that this
 * swallows the throw: every actual read/write calls getSql() itself and
 * surfaces the same error at the call site.
 */
export function ensureDbReady(): Promise<void> {
  return getSql()
    .then(() => undefined)
    .catch((err) => {
      console.warn("[db] DB bootstrap notice:", err instanceof Error ? err.message : String(err));
    });
}
