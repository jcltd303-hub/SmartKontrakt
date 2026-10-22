/**
 * Build stamp for the app header (improvement #6, 2026-10-22): which build
 * is actually deployed. Repeatedly, a "missing" feature turned out to be a
 * stale cached bundle and there was no way to tell from the UI which build
 * was on screen — this makes it a glance instead of a guessing game.
 *
 * Pure + dependency-free so it is unit-testable and safe to import from the
 * server-fn module. The SHA comes from VERCEL_GIT_COMMIT_SHA, which Vercel
 * sets at build time; anywhere else (local dev, Termux) it is unset and the
 * stamp honestly reads "dev".
 */
export type BuildInfo = {
  /** Full commit SHA, or "dev" when Vercel did not provide one. */
  sha: string;
  /** First 7 chars of the SHA ("dev" when unset) — the header rendering. */
  shortSha: string;
  /**
   * When this server bundle was loaded. On serverless the module is
   * evaluated once per cold start, so this is the deploy time for any
   * practical purpose (a long-lived instance reports its boot, which is
   * still the build that is serving).
   */
  builtAt: string;
  /** analyzerStamp() from audit/analyzer-version, or null when not wired. */
  analyzerVersion: string | null;
};

const MODULE_LOADED_AT = new Date().toISOString();

export function resolveBuildInfo(
  env: Record<string, string | undefined>,
  analyzerVersion?: string | null,
): BuildInfo {
  const sha = (env.VERCEL_GIT_COMMIT_SHA ?? "").trim();
  return {
    sha: sha || "dev",
    shortSha: sha ? sha.slice(0, 7) : "dev",
    builtAt: MODULE_LOADED_AT,
    analyzerVersion: analyzerVersion ?? null,
  };
}
