import { readFileSync, writeFileSync, existsSync, rmSync } from "node:fs";
import { join } from "node:path";
import pg from "pg";
import { pendingMigrations } from "../../scripts/migration-plan.mjs";
import { encodePostgresCredentials, extractSupabaseProjectRef, poolerHostRegion } from "./pg-url.ts";

export { extractSupabaseProjectRef } from "./pg-url.ts";

export type SupabaseDbConfig = {
  projectName: string;
  projectRef: string;
  password: string;
  region: string;
  mode: "pooler" | "direct" | "custom";
  host?: string;
  port?: number;
  database?: string;
  user?: string;
  customUrl?: string;
  active: boolean;
};

const CONFIG_FILE = ".supabase-db-config.json";

/**
 * Fallbacks for a config file that is missing fields — deliberately NOT a real
 * project. These used to name one (`projectRef`/`host`/`user` baked with a
 * specific reference), which meant a config that did not carry its own values
 * silently pointed at that project, and a stale copy of those values could
 * override a project reference the user had just changed. With no project
 * reference there is no connection URL, which is the honest state for a fresh
 * install.
 */
export const DEFAULT_SUPABASE_DB_CONFIG: SupabaseDbConfig = {
  projectName: "SmartKontrakt",
  projectRef: "",
  password: "",
  region: "us-east-1",
  host: "",
  port: 6543,
  database: "postgres",
  user: "",
  mode: "pooler",
  active: false,
};

function getConfigFilePath(): string {
  return join(process.cwd(), CONFIG_FILE);
}

/**
 * True only when a saved config file exists. loadSupabaseDbConfig() below
 * falls back to a hardcoded default project when the file is missing, so
 * callers that must not silently use that default (db.ts) gate on this.
 */
export function hasSupabaseDbConfig(): boolean {
  try {
    return existsSync(getConfigFilePath());
  } catch {
    return false;
  }
}

/**
 * Whether a saved config can actually persist on this host.
 *
 * A serverless deployment's working directory is read-only, so the save path
 * below reported success while writing nothing: the UI said "connected", and
 * every later request still found no config and quietly served from the
 * ephemeral embedded database. Probing the write is the only honest answer.
 */
export function configFileWritable(): boolean {
  try {
    const probe = `${getConfigFilePath()}.probe`;
    writeFileSync(probe, "probe", "utf-8");
    rmSync(probe, { force: true });
    return true;
  } catch {
    return false;
  }
}

export function loadSupabaseDbConfig(): SupabaseDbConfig {
  try {
    const path = getConfigFilePath();
    if (existsSync(path)) {
      const raw = readFileSync(path, "utf-8");
      const parsed = JSON.parse(raw);
      const cfg: SupabaseDbConfig = {
        ...DEFAULT_SUPABASE_DB_CONFIG,
        ...parsed,
      };
      // Canonicalise the reference on load: a config saved while the field
      // held a pasted URL (or written by another tool) carries that whole
      // string, and every consumer would re-derive a different "reference"
      // from it. When a valid reference is extractable, the bare reference
      // is the config's reference. When none is, the value is left as-is so
      // the modal can show it and flag it as invalid.
      const ref = extractSupabaseProjectRef(cfg.projectRef);
      if (ref) cfg.projectRef = ref;
      return cfg;
    }
  } catch (err) {
    console.warn("[supabase-db] Error reading config file:", err);
  }
  return { ...DEFAULT_SUPABASE_DB_CONFIG };
}

export function saveSupabaseDbConfig(cfg: Partial<SupabaseDbConfig>): SupabaseDbConfig {
  const current = loadSupabaseDbConfig();
  const updated: SupabaseDbConfig = {
    ...current,
    ...cfg,
    password: cfg.password ?? current.password,
  };
  try {
    writeFileSync(getConfigFilePath(), JSON.stringify(updated, null, 2), "utf-8");
  } catch (err) {
    console.error("[supabase-db] Error writing config file:", err);
  }
  return updated;
}

/**
 * Builds standard Supabase PostgreSQL connection string with properly URL-encoded password.
 */
export function buildSupabasePostgresUrl(cfg: SupabaseDbConfig): string {
  if (cfg.mode === "custom" && cfg.customUrl?.trim()) {
    // A pasted URL may carry a raw password; encode it before use.
    return encodePostgresCredentials(cfg.customUrl);
  }

  // Credentials must be supplied explicitly, never recovered from source defaults.
  if (!cfg.password) return "";
  const encPw = encodeURIComponent(cfg.password);

  // The reference is EXTRACTED and validated by the shared helper, never
  // string-trimmed into shape. The cleanup chain this replaces reduced a
  // pasted `postgresql://…` connection string to its scheme word and this
  // builder then composed the pooler user `postgres.postgresql` — a tenant
  // that cannot exist. Extraction finds the real 20-character reference in
  // a bare ref, a project/dashboard URL, or a full connection string, and
  // yields nothing otherwise, in which case no ref-based URL is built.
  const cleanRef = extractSupabaseProjectRef(cfg.projectRef || "") ?? "";

  // THE PROJECT REFERENCE WINS over a stored host/user.
  //
  // A saved config keeps the host and user from whenever it was first written,
  // and the pooler user is `postgres.<ref>` — so checking host/user first meant
  // that changing the project reference did NOTHING: the URL was rebuilt from
  // the stale pair and the app kept talking to the previous project. The user is
  // therefore always derived from the reference.
  if (cleanRef) {
    const region = (cfg.region || "us-east-1").trim();

    if (cfg.mode === "direct") {
      return `postgresql://postgres:${encPw}@db.${cleanRef}.supabase.co:5432/postgres`;
    }

    // Supabase Connection Pooler (Transaction Mode, port 6543). The pooler host
    // embeds the region AND a provider index (`aws-0-` / `aws-1-`) that the
    // reference does not encode, so a stored host is worth keeping — but only
    // when it names the region we are actually connecting to. Otherwise the
    // stored host belongs to a different project's region and must not be used.
    const savedHost = cfg.host?.trim() ?? "";
    const host =
      poolerHostRegion(savedHost) === region ? savedHost : `aws-0-${region}.pooler.supabase.com`;
    return `postgresql://postgres.${cleanRef}:${encPw}@${host}:${cfg.port || 6543}/${cfg.database || "postgres"}`;
  }

  // No reference given: a fully explicit host/user is the only way left. This is
  // the programmatic path (a config written with host/user and no reference).
  if (cfg.host?.trim() && cfg.user?.trim()) {
    const port = cfg.port || 6543;
    const db = cfg.database || "postgres";
    // Encode the user as well as the password: the username sits in the same
    // userinfo section and is subject to the same rules.
    return `postgresql://${encodeURIComponent(cfg.user.trim())}:${encPw}@${cfg.host.trim()}:${port}/${db}`;
  }

  return "";
}

/**
 * Mask sensitive credentials for safe client UI inspection
 */
export function maskPostgresUrl(url: string): string {
  if (!url) return "";
  return url.replace(/:\/\/([^:]+):([^@]+)@/, (match, user, pass) => {
    const maskedPass = pass.length > 4 ? `${pass.slice(0, 2)}••••••${pass.slice(-2)}` : "••••••";
    return `://${user}:${maskedPass}@`;
  });
}

/**
 * Tests PostgreSQL connectivity with detailed ping and server version metadata
 */
export async function testPostgresConnection(connectionString: string): Promise<{
  ok: boolean;
  message: string;
  version?: string;
  database?: string;
  latencyMs?: number;
}> {
  if (!connectionString?.trim()) {
    return { ok: false, message: "No database connection string provided." };
  }

  const start = Date.now();
  const cleanUrl = encodePostgresCredentials(connectionString).replace(/([?&])sslmode=[^&]*(&|$)/, "$1").replace(/[?&]$/, "");
  const pool = new pg.Pool({
    connectionString: cleanUrl,
    ssl: { rejectUnauthorized: false },
    connectionTimeoutMillis: 15_000,
    max: 1,
  });

  try {
    const client = await pool.connect();
    try {
      const res = await client.query("SELECT version() as ver, current_database() as db, current_user as usr, now() as ts");
      const latencyMs = Date.now() - start;
      const row = res.rows[0];
      return {
        ok: true,
        message: `Successfully connected to database '${row.db}' as '${row.usr}'.`,
        version: row.ver,
        database: row.db,
        latencyMs,
      };
    } finally {
      client.release();
    }
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    if (msg.includes("ENOTFOUND")) {
      return {
        ok: false,
        message: `Host not found: ${msg}. If using Supabase, ensure your 20-character Project Reference ID from your dashboard is correct.`,
      };
    }
    if (msg.includes("password authentication failed")) {
      return {
        ok: false,
        message: `Authentication failed: ${msg}. Check your database password.`,
      };
    }
    return { ok: false, message: `Connection error: ${msg}` };
  } finally {
    try {
      await pool.end();
    } catch {
      // ignore close errors
    }
  }
}

/**
 * Executes database migrations (0002_scans.sql, 0003_comprehensive_records_and_rag.sql)
 * on the provided PostgreSQL database connection.
 */
export async function applyMigrationsToPostgres(connectionString: string): Promise<{
  ok: boolean;
  appliedCount: number;
  message: string;
}> {
  const cleanUrl = encodePostgresCredentials(connectionString).replace(/([?&])sslmode=[^&]*(&|$)/, "$1").replace(/[?&]$/, "");
  const pool = new pg.Pool({
    connectionString: cleanUrl,
    ssl: { rejectUnauthorized: false },
    connectionTimeoutMillis: 15_000,
    max: 1,
  });

  try {
    const client = await pool.connect();
    try {
      await client.query(
        "CREATE TABLE IF NOT EXISTS _migrations (name TEXT PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT now())",
      );

      const doneRows = await client.query<{ name: string }>("SELECT name FROM _migrations");
      const applied = doneRows.rows.map((r) => r.name);

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

      const pending = pendingMigrations(Object.keys(migrations), applied);
      let count = 0;

      for (const { name, path: mPath } of pending) {
        await client.query("BEGIN");
        try {
          await client.query(migrations[mPath]);
          await client.query("INSERT INTO _migrations (name) VALUES ($1)", [name]);
          await client.query("COMMIT");
          count++;
        } catch (mErr) {
          await client.query("ROLLBACK");
          throw mErr;
        }
      }

      return {
        ok: true,
        appliedCount: count,
        message: count > 0 ? `Successfully applied ${count} migration(s) to Supabase database.` : "Database schema is up to date.",
      };
    } finally {
      client.release();
    }
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    return { ok: false, appliedCount: 0, message: `Migration error: ${msg}` };
  } finally {
    try {
      await pool.end();
    } catch {
      // ignore
    }
  }
}
