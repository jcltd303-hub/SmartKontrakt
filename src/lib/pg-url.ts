/**
 * Typed facade over `pg-url.mjs`.
 *
 * The implementation is plain JavaScript so the deploy-time migrator
 * (`scripts/migrate-vercel.mjs`, run under bare `node` during `npm run build`)
 * can share the very same normaliser — importing a `.ts` file there would need
 * `--experimental-strip-types` and so would put a Node-version dependency in the
 * production deploy path. App code imports this module for the same functions
 * with types; `allowJs` lets TypeScript read the JSDoc annotations in the `.mjs`.
 *
 * One implementation, used by the browser, the server, the worker and the
 * migrator. See the `.mjs` for why credentials must be encoded and why the
 * normaliser has to be idempotent.
 */
export {
  encodePostgresCredentials,
  extractSupabaseProjectRef,
  isPercentEncoded,
  isSupabaseProjectRef,
  looksLikePlaceholder,
  poolerHostRegion,
  supabasePoolerUser,
} from "./pg-url.mjs";
