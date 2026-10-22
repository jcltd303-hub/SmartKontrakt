/**
 * Turn a database driver error into the thing to do about it.
 *
 * The failure that costs the most time is `password authentication failed`: it
 * reads like a connectivity problem, and it is not. The URL resolved, the
 * server answered, and the server refused the credentials — which means the
 * connection string is fine and the secret in it is stale. Naming that, and
 * naming the variable to fix, is the difference between a five-minute fix and
 * an afternoon of checking hostnames.
 *
 * Dependency-free so the test runner can load it directly.
 */

export type DbErrorContext = {
  /** Which environment variable supplied the URL, when one did. */
  from?: string;
  /** The URL, for host-level hints only. Never echoed back with a password. */
  host?: string;
};

/** Postgres SQLSTATE and Node network codes worth translating. */
export function describeDbError(err: unknown, context: DbErrorContext = {}): string {
  const raw = err instanceof Error ? err.message : String(err);
  const code = typeof err === "object" && err !== null ? String((err as { code?: unknown }).code ?? "") : "";
  const where = context.from ? `the URL from ${context.from}` : "the connection URL";

  if (code === "28P01" || /password authentication failed/i.test(raw)) {
    return (
      `The database rejected the password in ${where}. This is not a connectivity problem — the server ` +
      `answered and refused the credentials, so the secret is stale: it is not this database's current ` +
      `password. Reset it in Supabase (Project Settings → Database) and update that variable, or ` +
      `re-connect the Supabase integration so it re-injects the current values. If the password was ever ` +
      `committed to this repository, rotating it is required regardless. [${raw}]`
    );
  }

  if (code === "3D000" || /database .* does not exist/i.test(raw)) {
    return `The database named in ${where} does not exist. Check the database name in the URL. [${raw}]`;
  }

  if (code === "ENOTFOUND" || code === "EAI_AGAIN" || /getaddrinfo|ENOTFOUND/i.test(raw)) {
    return `The host in ${where} could not be resolved. Check the project reference — a typo there produces exactly this. [${raw}]`;
  }

  if (code === "ECONNREFUSED" || code === "ETIMEDOUT" || /timeout|timed out|ECONNREFUSED/i.test(raw)) {
    return (
      `The host in ${where} refused the connection or timed out. On Supabase the direct host ` +
      `(db.<ref>.supabase.co) is IPv6-only unless the IPv4 add-on is bought, and a serverless function ` +
      `cannot reach IPv6 — prefer the pooled host (…pooler.supabase.com, port 6543). [${raw}]`
    );
  }

  return raw;
}
