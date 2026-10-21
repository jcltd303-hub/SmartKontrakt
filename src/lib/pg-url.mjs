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
  const host = /^[A-Za-z0-9][A-Za-z0-9.\-]*(:\d{1,5})?$/;
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
