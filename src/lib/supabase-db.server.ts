import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import pg from "pg";
import { pendingMigrations } from "../../scripts/migration-plan.mjs";

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

export const DEFAULT_SUPABASE_DB_CONFIG: SupabaseDbConfig = {
  projectName: "SmartKontrakt",
  projectRef: "aadhpvhpjzkkeydzxxhk",
  password: "hX*+JxfrR4Q&3BB",
  region: "us-west-2",
  host: "aws-1-us-west-2.pooler.supabase.com",
  port: 6543,
  database: "postgres",
  user: "postgres.aadhpvhpjzkkeydzxxhk",
  mode: "pooler",
  active: true,
};

function getConfigFilePath(): string {
  return join(process.cwd(), CONFIG_FILE);
}

export function loadSupabaseDbConfig(): SupabaseDbConfig {
  try {
    const path = getConfigFilePath();
    if (existsSync(path)) {
      const raw = readFileSync(path, "utf-8");
      const parsed = JSON.parse(raw);
      return {
        ...DEFAULT_SUPABASE_DB_CONFIG,
        ...parsed,
        // Always ensure password is preserved if empty in saved file
        password: parsed.password || DEFAULT_SUPABASE_DB_CONFIG.password,
      };
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
    return cfg.customUrl.trim();
  }

  // Note: Password 'hX*+JxfrR4Q&3BB' contains characters + and & which must be percent-encoded for URI safety
  const encPw = encodeURIComponent(cfg.password || DEFAULT_SUPABASE_DB_CONFIG.password);

  // If explicit host and user are provided (e.g. Supabase pooler host)
  if (cfg.host?.trim() && cfg.user?.trim()) {
    const port = cfg.port || 6543;
    const db = cfg.database || "postgres";
    return `postgresql://${cfg.user.trim()}:${encPw}@${cfg.host.trim()}:${port}/${db}`;
  }

  const cleanRef = (cfg.projectRef || "")
    .trim()
    .replace(/^https?:\/\//i, "")
    .replace(/\.supabase\.co.*$/i, "")
    .replace(/\/.*$/, "");

  if (!cleanRef) return "";

  const region = (cfg.region || "us-east-1").trim();

  if (cfg.mode === "direct") {
    return `postgresql://postgres:${encPw}@db.${cleanRef}.supabase.co:5432/postgres`;
  }

  // Supabase Connection Pooler (Transaction Mode, port 6543) - ideal for serverless / edge workloads
  return `postgresql://postgres.${cleanRef}:${encPw}@aws-0-${region}.pooler.supabase.com:6543/postgres`;
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
  const pool = new pg.Pool({
    connectionString: connectionString.trim(),
    connectionTimeoutMillis: 12_000,
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
  const pool = new pg.Pool({
    connectionString: connectionString.trim(),
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
