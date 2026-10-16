import { pendingMigrations } from "../../scripts/migration-plan.mjs";
import { createSqlClient, type Sql } from "./sql-client";
import { loadSupabaseDbConfig, buildSupabasePostgresUrl } from "./supabase-db.server";
export type { Sql } from "./sql-client";

/** Which database backend is active. */
export type DbSource = "neon" | "pglite";

// An empty/whitespace DATABASE_URL (an easy misconfig in deploy UIs) must mean
// "unset" — otherwise production would silently run on the PGLite fallback.
const rawDatabaseUrl =
  typeof process !== "undefined" ? process.env.DATABASE_URL : undefined;
const databaseUrl =
  rawDatabaseUrl && rawDatabaseUrl.trim() ? rawDatabaseUrl : undefined;

export function getActiveDatabaseUrl(): string | undefined {
  if (typeof window !== "undefined") return undefined;
  if (globalRef.__activeDatabaseUrl__) return globalRef.__activeDatabaseUrl__;

  // 1. Check Supabase saved config if active
  try {
    const cfg = loadSupabaseDbConfig();
    if (cfg?.active) {
      const url = buildSupabasePostgresUrl(cfg);
      if (url && (url.startsWith("postgresql://") || url.startsWith("postgres://"))) {
        return url;
      }
    }
  } catch {
    // ignore
  }

  // 2. Check process.env.DATABASE_URL
  const rawEnv = process.env.DATABASE_URL?.trim();
  if (rawEnv) {
    if (rawEnv.startsWith("postgresql://") || rawEnv.startsWith("postgres://")) {
      return rawEnv;
    }
    // If someone passed a Supabase HTTPS URL (e.g. https://<ref>.supabase.co):
    try {
      const cfg = loadSupabaseDbConfig();
      const extractedRef = rawEnv.replace(/^https?:\/\//i, "").replace(/\.supabase\.co.*$/i, "").replace(/\/.*$/, "");
      if (extractedRef) {
        const url = buildSupabasePostgresUrl({
          ...cfg,
          projectRef: extractedRef,
          user: cfg.user || `postgres.${extractedRef}`,
        });
        if (url && (url.startsWith("postgresql://") || url.startsWith("postgres://"))) {
          return url;
        }
      }
    } catch {
      // ignore
    }
  }

  return undefined;
}

/**
 * Active backend: real **Neon/Supabase** when active database URL is set,
 * otherwise a local embedded **PGLite** (Postgres compiled to WASM).
 */
export const dbSource: DbSource = databaseUrl ? "neon" : "pglite";

export function getActiveDbSource(): DbSource {
  return getActiveDatabaseUrl() ? "neon" : "pglite";
}

/**
 * Minimal shared SQL surface, satisfied by both Neon/Supabase and PGLite. Both the
 * tagged-template and `.query()` forms resolve to an array of row objects:
 *
 *   const sql = await getSql();
 *   const rows = await sql`select * from todos where id = ${id}`; // parameterized
 *   const rows2 = await sql.query("select * from todos where id = $1", [id]);
 */

/**
 * Init state lives on globalThis as promises: dev HMR creates new instances of
 * this module, and two instances racing module-level state would open a second
 * pool or run two concurrent PGLite migration passes.
 */
const globalRef = globalThis as typeof globalThis & {
  __pgSqlPromise__?: Promise<Sql>;
  __pgliteInstance__?: Promise<import("@electric-sql/pglite").PGlite>;
  __pgliteMigrateChain__?: Promise<void>;
  __activeDatabaseUrl__?: string;
};

/**
 * Result-type parity: Postgres sends every value as text plus a type OID — the
 * JS value is the DRIVER's parsing choice, and pg and PGLite disagree.
 */
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

function createNeonSql(customUrl?: string): Promise<Sql> {
  const targetUrl = customUrl || getActiveDatabaseUrl() || databaseUrl;
  globalRef.__pgSqlPromise__ ??= (async () => {
    // Regular Postgres driver: node-postgres (`pg`) — works directly with Neon / Supabase.
    const { Pool, types } = await import("pg");
    types.setTypeParser(OID_INT8, Number);
    types.setTypeParser(OID_DATE, identity);
    types.setTypeParser(OID_INTERVAL, identity);
    const pool = new Pool({
      connectionString: targetUrl,
      max: 2,
      idleTimeoutMillis: 10_000,
      connectionTimeoutMillis: 12_000,
      query_timeout: 60_000,
      allowExitOnIdle: true,
    });
    pool.on("error", (err) => console.error("[db] Idle connection error:", err.message));

    // Ensure migrations are auto-applied on the target PostgreSQL database
    try {
      const client = await pool.connect();
      try {
        await client.query(
          "CREATE TABLE IF NOT EXISTS _migrations (name TEXT PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT now())",
        );
        const doneRows = await client.query<{ name: string }>("SELECT name FROM _migrations");
        const done = doneRows.rows.map((r) => r.name);
        let migrations: Record<string, string> = {};
        if (typeof import.meta.glob === "function") {
          migrations = import.meta.glob("/migrations/*.sql", {
            query: "?raw",
            import: "default",
            eager: true,
          }) as Record<string, string>;
        } else {
          const fs = await import("node:fs");
          const path = await import("node:path");
          const migDir = path.join(process.cwd(), "migrations");
          if (fs.existsSync(migDir)) {
            const files = fs.readdirSync(migDir).filter((f) => f.endsWith(".sql"));
            for (const file of files) {
              migrations[`/migrations/${file}`] = fs.readFileSync(path.join(migDir, file), "utf-8");
            }
          }
        }
        const pending = pendingMigrations(Object.keys(migrations), done);
        for (const { name, path: mPath } of pending) {
          await client.query("BEGIN");
          try {
            await client.query(migrations[mPath]);
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
      console.warn("[db] Postgres auto-migration notice:", migErr instanceof Error ? migErr.message : String(migErr));
    }

    return createSqlClient(async <T>(text: string, params: unknown[]) => {
      const res = await pool.query(text, params);
      return res.rows as T[];
    }, async (work) => {
      const client = await pool.connect();
      try {
        await client.query("BEGIN");
        const result = await work(async <T>(text: string, params: unknown[]) =>
          (await client.query(text, params)).rows as T[]);
        await client.query("COMMIT");
        return result;
      } catch (err) {
        try { await client.query("ROLLBACK"); } catch { /* Preserve the original failure. */ }
        throw err;
      } finally { client.release(); }
    });
  })().catch((err) => {
    globalRef.__pgSqlPromise__ = undefined;
    throw err;
  });
  return globalRef.__pgSqlPromise__;
}

async function createPgliteSql(): Promise<Sql> {
  // Embedded Postgres, imported on demand so it never loads on the Neon path.
  // One in-memory instance per process, shared across HMR module instances, so
  // data survives source edits (it resets on dev-server restart).
  globalRef.__pgliteInstance__ ??= (async () => {
    const { PGlite } = await import("@electric-sql/pglite");
    const pg = new PGlite({
      parsers: {
        [OID_INT8]: Number,
        [OID_DATE]: identity,
        [OID_INTERVAL]: identity,
      },
    });
    await pg.waitReady;
    await pg.exec(
      "create table if not exists _migrations (name text primary key, applied_at timestamptz not null default now())",
    );
    return pg;
  })().catch((err) => {
    globalRef.__pgliteInstance__ = undefined;
    throw err;
  });
  const pg = await globalRef.__pgliteInstance__;

  // Apply migrations/ (the single schema source) so preview matches production.
  // SQL is inlined by the bundler via import.meta.glob (no runtime fs); applied
  // files are tracked in _migrations. The glob does not descend, so the opt-in
  // auth schema under migrations/auth/ stays out. Runs once per module instance
  // — so an HMR reload after adding a migration file applies it live — with
  // passes serialized on a global chain so concurrent callers never
  // double-apply.
  const migrate = async (): Promise<void> => {
    const migrations = import.meta.glob("/migrations/*.sql", {
      query: "?raw",
      import: "default",
      eager: true,
    }) as Record<string, string>;
    const doneRows = await pg.query<{ name: string }>(
      "select name from _migrations",
    );
    const done = doneRows.rows.map((r) => r.name);
    for (const { name, path } of pendingMigrations(Object.keys(migrations), done)) {
      // Apply + record atomically (parity with scripts/migrate.mjs) so a failed
      // statement can't leave a file half-applied but untracked.
      await pg.transaction(async (tx) => {
        await tx.exec(migrations[path]);
        await tx.query("insert into _migrations (name) values ($1)", [name]);
      });
    }
  };
  const pass = (globalRef.__pgliteMigrateChain__ ?? Promise.resolve())
    .catch(() => undefined) // an earlier failed pass must not wedge the chain
    .then(migrate);
  globalRef.__pgliteMigrateChain__ = pass;
  await pass;

  return createSqlClient(async <T>(text: string, params: unknown[]) => {
    const result = await pg.query<T>(text, params);
    return result.rows;
  }, (work) => pg.transaction((tx) => work(async <T>(text: string, params: unknown[]) =>
    (await tx.query<T>(text, params)).rows)));
}

let sqlPromise: Promise<Sql> | null = null;

async function createSql(): Promise<Sql> {
  if (typeof process !== "undefined" && process.env.VERCEL && !databaseUrl) {
    throw new Error("Configure DATABASE_URL for a durable Postgres database before saving audits on Vercel.");
  }
  if (typeof window !== "undefined") {
    throw new Error(
      "@/lib/db is server-only — call getSql() from a createServerFn handler " +
        "or a server route loader, never from client code.",
    );
  }
  return getActiveDatabaseUrl() ? createNeonSql() : createPgliteSql();
}

export async function getDatabaseInfo(): Promise<{
  source: "supabase" | "postgres" | "pglite";
  databaseUrlMasked?: string;
  connected: boolean;
  message: string;
}> {
  const activeUrl = getActiveDatabaseUrl();
  if (activeUrl) {
    const isSupabase = activeUrl.includes("supabase.co") || activeUrl.includes("supabase.com");
    return {
      source: isSupabase ? "supabase" : "postgres",
      databaseUrlMasked: activeUrl.replace(/:\/\/([^:]+):([^@]+)@/, "://$1:••••••@"),
      connected: true,
      message: isSupabase ? "Connected to Supabase PostgreSQL database." : "Connected to remote PostgreSQL database.",
    };
  }
  return {
    source: "pglite",
    connected: true,
    message: "Using embedded PGLite (in-memory WASM Postgres).",
  };
}

/**
 * Get the shared, **server-only** SQL client. Neon when `DATABASE_URL` is set,
 * otherwise the local PGLite fallback. Memoized — safe to call per request.
 *
 * Schema comes from `migrations/*.sql`, auto-applied before the first query on
 * both backends — define tables there, never inline in server functions.
 */
export function getSql(): Promise<Sql> {
  sqlPromise ??= createSql().catch((err) => {
    sqlPromise = null; // don't memoize failures — let the next call retry
    throw err;
  });
  return sqlPromise;
}

/**
 * The shared PGLite instance (preview only), with `migrations/*.sql` applied.
 * Lets Better Auth persist to the SAME embedded DB as app data in preview (via a
 * Kysely dialect). Throws when `DATABASE_URL` is set (that path uses Neon).
 */
export async function getPglite(): Promise<import("@electric-sql/pglite").PGlite> {
  if (dbSource !== "pglite") {
    throw new Error("getPglite() is only available on the PGLite fallback (no DATABASE_URL)");
  }
  await getSql();
  const pg = await globalRef.__pgliteInstance__;
  if (!pg) throw new Error("PGLite instance failed to initialize");
  return pg;
}

/**
 * Finish DB bootstrap before the server handles traffic.
 *
 * - **PGLite** (preview / no `DATABASE_URL`): open the in-memory DB and apply
 *   `migrations/*.sql`. Idempotent — concurrent callers share one promise.
 * - **Neon**: no-op (pool is created lazily on first query).
 *
 * Vite `configureServer` awaits this at dev startup; production imports of this
 * module kick it off immediately (see bottom of file).
 */
export function ensureDbReady(): Promise<void> {
  if (dbSource !== "pglite") return Promise.resolve();
  return getSql().then(() => undefined);
}

// Server-only eager start: kick PGLite bootstrap as soon as this module loads in
// Node. Client bundles never hit this path (`getSql` throws in the browser).
const globalBoot = globalThis as typeof globalThis & {
  __pgBootstrapPromise__?: Promise<void>;
};
if (typeof window === "undefined" && dbSource === "pglite" && !process.env.VERCEL) {
  globalBoot.__pgBootstrapPromise__ ??= ensureDbReady().catch((err) => {
    globalBoot.__pgBootstrapPromise__ = undefined;
    console.error("[db] PGLite bootstrap failed:", err);
    throw err;
  });
}
