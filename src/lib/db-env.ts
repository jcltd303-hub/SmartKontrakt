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
import { encodePostgresCredentials, looksLikePlaceholder } from "./pg-url.ts";

export type EnvVarProbe = {
  name: string;
  role: string;
  /** Present AND usable (non-empty, not a placeholder). */
  present: boolean;
};

/**
 * Ordered: the first entry that yields a usable URL wins.
 *
 * Pooled URLs come before the direct one because serverless functions exhaust a
 * direct connection pool; migrations go the other way (see DIRECT_ENV_VARS).
 */
export const DATABASE_ENV_VARS: readonly { name: string; role: string }[] = [
  { name: "DATABASE_URL", role: "explicit override" },
  { name: "POSTGRES_PRISMA_URL", role: "Vercel Supabase integration — pooled (pgbouncer)" },
  { name: "POSTGRES_URL", role: "Vercel Supabase integration — pooled" },
  { name: "POSTGRES_URL_NON_POOLING", role: "Vercel Supabase integration — direct" },
  { name: "SUPABASE_DB_URL", role: "Supabase CLI / manual" },
  { name: "SUPABASE_POOLER_URL", role: "Supabase pooler" },
];

/**
 * Variables that carry a DIRECT (non-pooled) connection.
 *
 * DDL is run over one of these when available: a transaction-mode pooler
 * (pgbouncer) can reject or mis-scope `CREATE TABLE` / multi-statement
 * migrations, and a migration failure takes the whole connection down with it —
 * which the app then reported as "Supabase unreachable" while quietly serving
 * from ephemeral local storage.
 *
 * `DATABASE_URL` is included as a last resort even though it *may* be pooled:
 * it is usually a hand-pasted direct string, and a wrong guess here is no worse
 * than the previous behaviour of using the pooled URL for everything.
 */
export const DIRECT_ENV_VARS: readonly string[] = [
  "POSTGRES_URL_NON_POOLING",
  "DATABASE_URL",
  "SUPABASE_DB_URL",
];

export type ResolvedDbUrl = { url: string; from: string };

/** Trim, reject empties/placeholders, and normalise credentials. */
export function cleanEnvUrl(value: string | undefined | null): string | undefined {
  const trimmed = typeof value === "string" ? value.trim() : "";
  if (!trimmed) return undefined;
  // An unreplaced deploy template, or a placeholder someone pasted.
  if (trimmed.includes("<") || trimmed.includes(">") || looksLikePlaceholder(trimmed)) return undefined;
  if (trimmed.startsWith("postgresql://") || trimmed.startsWith("postgres://")) {
    // Hand-written URLs often carry a raw password; encoding here means a
    // password containing `@ # / :` connects instead of silently mis-parsing.
    // Idempotent, so an already-encoded URL is untouched.
    return sanitizeForNodePostgres(encodePostgresCredentials(trimmed));
  }
  return undefined;
}

/**
 * Parameters that belong to a different client, not to node-postgres.
 *
 * `POSTGRES_PRISMA_URL` is the Vercel Supabase integration's Prisma-flavoured
 * URL — the same pooler, plus `?pgbouncer=true`, which Prisma needs and `pg`
 * must never see. Forwarding a client's private parameter to the server is a
 * way for a connection string that looks perfectly correct to fail at startup.
 */
const FOREIGN_URL_PARAMS = ["pgbouncer", "connection_limit", "pool_timeout", "schema"];

/**
 * Drop other clients' parameters from a connection string.
 *
 * Operates on the query string only — never through `new URL()`, which would
 * re-encode (and so corrupt) a raw password in the authority.
 */
export function sanitizeForNodePostgres(url: string): string {
  const q = url.indexOf("?");
  if (q === -1) return url;
  const base = url.slice(0, q);
  const kept = url
    .slice(q + 1)
    .split("&")
    .filter(Boolean)
    .filter((pair) => !FOREIGN_URL_PARAMS.includes(pair.split("=")[0].toLowerCase()));
  return kept.length > 0 ? `${base}?${kept.join("&")}` : base;
}

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
