/**
 * Postgres connection URLs must carry percent-encoded credentials.
 *
 * A password with `@ # / : ? %` or a space in it breaks a connection string the
 * moment it is put in the userinfo section: `postgresql://u:p@ss#word@host/db`
 * does not fail loudly, it silently becomes host `ss` with a fragment — so the
 * connection either fails with a confusing auth error or, worse, succeeds
 * against the wrong parse. Supabase passwords routinely contain such characters.
 *
 * We therefore build URLs with `encodeURIComponent` and normalise every URL that
 * arrives from outside (a pasted "Connection string → URI", a `DATABASE_URL` in
 * the environment, a saved config) before it is used.
 *
 * The hard part is IDEMPOTENCE. A Supabase URI copied from the dashboard is
 * already encoded; encoding it again turns `%40` into `%2540` and breaks a
 * working password. `isPercentEncoded` detects the already-encoded case, so
 * normalising a URL that is already correct is a no-op.
 *
 * Plain JavaScript (not TypeScript) on purpose: the deploy-time migrator
 * `scripts/migrate-vercel.mjs` runs under bare `node` during `npm run build`,
 * where a `.ts` import would need `--experimental-strip-types` and so would put
 * a Node-version dependency in the production deploy path. One implementation,
 * imported by the browser, the server, the worker and the migrator alike.
 *
 * @typedef {(value: string) => boolean} UrlPredicate
 */

const SCHEMES = ["postgresql://", "postgres://"];

/**
 * True when a credential is already percent-encoded, so encoding it again would
 * double-encode. `decodeURIComponent` throws on a lone `%` (a literal percent
 * that still needs encoding), and a round-trip that reproduces the input exactly
 * means there is nothing left to escape.
 *
 * @param {string} value
 * @returns {boolean}
 */
export function isPercentEncoded(value) {
  if (!value.includes("%")) return false;
  try {
    return encodeURIComponent(decodeURIComponent(value)) === value;
  } catch {
    return false;
  }
}

/**
 * @param {string} value
 * @returns {string}
 */
function encodeCredential(value) {
  if (value === "") return value;
  return isPercentEncoded(value) ? value : encodeURIComponent(value);
}

/**
 * Where does the credential section end? The `@` separating credentials from
 * the host is the first one whose remainder (up to the next `/`) is a bare host
 * — no `@`, `#` or `?` in it. That single rule resolves the two cases a naive
 * heuristic gets wrong:
 *
 *   - a RAW password containing `@` or `#` (`postgres:p@ss#word@db.x`), where the
 *     delimiter is the LAST `@`; and
 *   - an `@` inside the query string (`/db?x=a@b`), where it is the FIRST.
 *
 * @param {string} rest
 * @returns {number} index of the delimiter, or -1
 */
function credentialDelimiter(rest) {
  const host = /^[A-Za-z0-9][A-Za-z0-9.-]*(:\d{1,5})?$/;
  let at = rest.indexOf("@");
  while (at !== -1) {
    const slash = rest.indexOf("/", at);
    const remainder = rest.slice(at + 1, slash === -1 ? rest.length : slash);
    if (host.test(remainder)) return at;
    at = rest.indexOf("@", at + 1);
  }
  return -1;
}

/**
 * Return `url` with its username and password percent-encoded. Idempotent: a URL
 * that is already correct is returned unchanged (modulo trimming), and anything
 * that is not a postgres URL is passed through untouched.
 *
 * @param {string} url
 * @returns {string}
 */
export function encodePostgresCredentials(url) {
  const trimmed = url.trim();
  const scheme = SCHEMES.find((s) => trimmed.toLowerCase().startsWith(s));
  if (!scheme) return trimmed;

  const rest = trimmed.slice(scheme.length);
  const at = credentialDelimiter(rest);
  if (at === -1) return trimmed; // no credentials to encode

  const creds = rest.slice(0, at);
  const tail = rest.slice(at); // includes the '@'
  const colon = creds.indexOf(":");
  const user = colon === -1 ? creds : creds.slice(0, colon);
  const pass = colon === -1 ? "" : creds.slice(colon + 1);

  const encUser = encodeCredential(user);
  const rebuilt = colon === -1 ? encUser : `${encUser}:${encodeCredential(pass)}`;
  return scheme + rebuilt + tail;
}

/**
 * Unreplaced template placeholders, which are never a usable URL.
 *
 * @param {string} url
 * @returns {boolean}
 */
export function looksLikePlaceholder(url) {
  return /<[^>]*>/.test(url) || /\[your[-_ ]?password\]/i.test(url);
}

/**
 * A Supabase project reference is exactly 20 lowercase alphanumerics. It is
 * the tenant key of every pooler connection: the pooler username IS
 * `postgres.<ref>`, so a wrong token does not degrade the connection, it
 * points it at a tenant that does not exist.
 */
const PROJECT_REF_PATTERN = /^[a-z0-9]{20}$/;

/**
 * @param {unknown} value
 * @returns {boolean} true when `value` is a plausible project reference.
 */
export function isSupabaseProjectRef(value) {
  return typeof value === "string" && PROJECT_REF_PATTERN.test(value);
}

/**
 * Extract a validated project reference from whatever was pasted: the bare
 * reference, a `postgres.<ref>` pooler username, a project URL
 * (`https://<ref>.supabase.co`), a dashboard URL
 * (`https://supabase.com/dashboard/project/<ref>`), or a full connection
 * string (the reference then lives in the username, or in a `db.<ref>` direct
 * host — a pooler host encodes only the region, so a bare `postgres` user
 * with a pooler host yields NOTHING).
 *
 * Returns null when no plausible reference is present. Never returns a
 * fragment of the input's syntax: the string-cleanup chain this replaces
 * (strip `https://`, strip `.supabase.co…`, strip `/…`) reduced a pasted
 * `postgresql://…` URL to the scheme word, and the builders composed the
 * pooler user `postgres.postgresql` from it — a tenant that cannot exist,
 * presented as a generated connection string.
 *
 * @param {unknown} input
 * @returns {string | null}
 */
export function extractSupabaseProjectRef(input) {
  if (typeof input !== "string") return null;
  const text = input.trim().toLowerCase();
  if (!text) return null;
  if (PROJECT_REF_PATTERN.test(text)) return text;

  // Dashboard URL: .../project/<ref>
  const fromPath = /\/project\/([a-z0-9]{20})(?=$|[^a-z0-9])/.exec(text);
  if (fromPath) return fromPath[1];

  // Pooler/direct username: postgres.<ref>
  const fromUser = /(?:^|[^a-z0-9])postgres\.([a-z0-9]{20})(?=$|[^a-z0-9])/.exec(text);
  if (fromUser) return fromUser[1];

  // Project host: <ref>.supabase.co or db.<ref>.supabase.co
  const fromHost = /(?:^|[^a-z0-9])([a-z0-9]{20})\.supabase\.co(?=$|[^a-z0-9])/.exec(text);
  if (fromHost) return fromHost[1];

  return null;
}

/**
 * The pooler username for a reference — `postgres.<ref>` — or null when the
 * reference is not valid. Builders must use the validated value (or refuse
 * to build), never interpolate an unvalidated token.
 *
 * @param {unknown} ref
 * @returns {string | null}
 */
export function supabasePoolerUser(ref) {
  return isSupabaseProjectRef(ref) ? `postgres.${ref}` : null;
}

/**
 * The region a Supabase pooler hostname encodes
 * (`aws-1-us-west-2.pooler.supabase.com` -> `us-west-2`), or null when the
 * host is not a pooler host.
 *
 * @param {unknown} host
 * @returns {string | null}
 */
export function poolerHostRegion(host) {
  if (typeof host !== "string") return null;
  const match = /^aws-\d+-([a-z0-9-]+)\.pooler\.supabase\.com$/i.exec(host.trim());
  return match ? match[1] : null;
}
