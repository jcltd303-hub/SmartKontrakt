/**
 * Which environment variable supplies the database, and why.
 *
 * The app used to look at `DATABASE_URL` alone. The Vercel Supabase
 * integration does not set that name — it injects `POSTGRES_URL`,
 * `POSTGRES_PRISMA_URL` and `POSTGRES_URL_NON_POOLING` — so a deployment wired
 * up through the integration looked unconfigured, and the UI (which reads a
 * config FILE, not the environment) said so outright.
 *
 * This module is the single, dependency-free place that answers "is there a
 * database URL in the environment, which variable carried it, and which
 * variables are present at all". It takes the environment as an argument so it
 * can be tested without mutating `process.env`.
 */
import { DATABASE_ENV_VARS, DIRECT_ENV_VARS, cleanEnvUrl, sanitizeForNodePostgres } from "./config.ts";

// The env-var priority tables and the URL cleaner live in the central
// config module (src/lib/config.mjs) so bare-node consumers (the deploy
// migrator) share the same definitions; re-exported here so existing
// importers of db-env.ts are unchanged.
export { DATABASE_ENV_VARS, DIRECT_ENV_VARS, cleanEnvUrl, sanitizeForNodePostgres };

export type EnvVarProbe = {
  name: string;
  role: string;
  /** Present AND usable (non-empty, not a placeholder). */
  present: boolean;
};

export type ResolvedDbUrl = { url: string; from: string };

/** The first usable URL in priority order, with the variable it came from. */
export function resolveDatabaseUrl(env: Record<string, string | undefined>): ResolvedDbUrl | undefined {
  for (const { name } of DATABASE_ENV_VARS) {
    const url = cleanEnvUrl(env[name]);
    if (url) return { url, from: name };
  }
  return undefined;
}

/** The URL migrations should run over — direct when one exists. */
export function resolveDirectDatabaseUrl(env: Record<string, string | undefined>): ResolvedDbUrl | undefined {
  for (const name of DIRECT_ENV_VARS) {
    const url = cleanEnvUrl(env[name]);
    if (url) return { url, from: name };
  }
  return undefined;
}

/**
 * Names and roles of every candidate variable, with presence only — never a
 * value. This is what lets a deployment say *why* it is unconfigured instead of
 * leaving someone to guess which name their host injects.
 */
export function databaseEnvInventory(env: Record<string, string | undefined>): EnvVarProbe[] {
  return DATABASE_ENV_VARS.map(({ name, role }) => ({
    name,
    role,
    present: Boolean(cleanEnvUrl(env[name])),
  }));
}

/**
 * The effective database state — the distinction whose absence produced the
 * Records masquerade (Oct 2026): a CONFIGURED database whose connection
 * failed (classically a stale password: the pooler answers and refuses the
 * credentials) made db.ts silently substitute an embedded local database.
 * Queries against the substitute SUCCEEDED and returned empty results, so
 * every layer above saw a healthy, empty archive — while the identity
 * surfaces kept naming the configured project.
 *
 * The substitute is REMOVED (Jer, 2026-10-22: "No fallback duh"). There is
 * no embedded store anymore: a configured database that cannot be reached
 * is an ERROR, and no configuration at all is an explicit unconfigured
 * state — neither produces data. "remote" is the only state in which
 * numbers describe the configured database:
 *
 *   remote       — the configured URL connected and is serving queries
 *   failed       — a URL is configured but the connection failed (error
 *                  carries the classified failure); reads/writes throw
 *   unconfigured — no URL at all; reads/writes throw "no database
 *                  configured" instead of inventing a local archive
 *
 * Pure (URL + observed outcome in, state out) so it is testable without a
 * database; db.ts supplies the runtime values. The configured identity is
 * parsed from the URL — host/port/user/database only, NEVER the password.
 */
export type DbStateKind = "remote" | "failed" | "unconfigured";

export type DbConnectionState = {
  state: DbStateKind;
  /** Classified connection failure (password-free) when state is failed. */
  error: string | null;
  /** The configured database's identity, when a URL is configured. */
  configured: { host: string | null; port: string | null; user: string | null; database: string | null } | null;
};

export function classifyDbState(
  activeUrl: string,
  connected: boolean,
  lastError?: { message: string } | null,
): DbConnectionState {
  if (!activeUrl) return { state: "unconfigured", error: null, configured: null };
  let configured: DbConnectionState["configured"] = null;
  try {
    const url = new URL(activeUrl);
    configured = {
      host: url.hostname || null,
      port: url.port || null,
      user: url.username ? decodeURIComponent(url.username) : null,
      database: url.pathname ? decodeURIComponent(url.pathname.replace(/^\//, "")) || null : null,
    };
  } catch {
    configured = null;
  }
  if (connected) return { state: "remote", error: null, configured };
  return {
    state: "failed",
    error: lastError?.message ?? "The configured database connection failed.",
    configured,
  };
}
