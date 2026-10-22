/**
 * Database-size guardrail presentation helpers (improvement #3,
 * 2026-10-22): pure formatting + thresholds for the size readout in the
 * Records tab. Kept dependency-free and out of any .server module so the
 * browser can import them and tests can pin the threshold boundaries.
 *
 * The cap is Supabase's free-tier database limit — the archive reached
 * 580 MB against it in Oct 2026 and writes started failing before anyone
 * knew why. Amber above 400 MB, red above 475 MB.
 */
export const DB_FREE_TIER_CAP_BYTES = 500 * 1024 * 1024;
export const DB_SIZE_WARN_BYTES = 400 * 1024 * 1024;
export const DB_SIZE_CRITICAL_BYTES = 475 * 1024 * 1024;

export type DbSizeLevel = "ok" | "warn" | "critical";

export function dbSizeLevel(totalBytes: number): DbSizeLevel {
  if (totalBytes > DB_SIZE_CRITICAL_BYTES) return "critical";
  if (totalBytes > DB_SIZE_WARN_BYTES) return "warn";
  return "ok";
}

export function dbSizePercentOfCap(totalBytes: number): number {
  return Math.round((totalBytes / DB_FREE_TIER_CAP_BYTES) * 100);
}

/** 843 → "843 B", 1536 → "1.5 KB", 440401920 → "420 MB", 1610612736 → "1.5 GB". */
export function formatDbBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes < 0) return "—";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let value = bytes;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit++;
  }
  const rendered = value >= 100 || unit === 0 ? String(Math.round(value)) : value.toFixed(1);
  return `${rendered} ${units[unit]}`;
}
