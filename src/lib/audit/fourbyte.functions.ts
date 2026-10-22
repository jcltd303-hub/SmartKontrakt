import { createServerFn } from "@tanstack/react-start";
import type { FourbyteResults } from "./fourbyte";

/**
 * Resolve 4byte selectors + event topics server-side, ON DEMAND
 * (2026-10-22): the fourbyte_signatures / fourbyte_event_signatures
 * tables are a cache of previously pulled rows; misses are fetched
 * live from the 4byte.directory API and cached (createOnDemandFourbyteLookup).
 * The browser workbench cannot query Supabase or the API directly, so
 * it calls this after analyzeAddress and merges the result with
 * applyFourbyteResults. The worker uses the same on-demand lookup
 * directly inside analyzeAddress instead.
 */
export const resolveFourbyte = createServerFn({ method: "POST" })
  .validator((input: unknown) => {
    if (!input || typeof input !== "object") {
      throw new Error("Invalid request payload");
    }
    const { selectors, topics } = input as {
      selectors?: unknown;
      topics?: unknown;
    };
    const clean = (v: unknown, len: number): string[] => {
      if (!Array.isArray(v)) return [];
      const out: string[] = [];
      for (const item of v) {
        if (typeof item !== "string") continue;
        const s = item.toLowerCase();
        if (s.startsWith("0x") && /^[0-9a-f]+$/.test(s.slice(2)) && s.length - 2 === len) {
          if (!out.includes(s)) out.push(s);
        }
        if (out.length >= 500) break;
      }
      return out;
    };
    return {
      selectors: clean(selectors, 8),
      topics: clean(topics, 64),
    };
  })
  .handler(async ({ data }): Promise<FourbyteResults> => {
    const { getSql } = await import("../db");
    const { createOnDemandFourbyteLookup } = await import("./fourbyte");
    // The tables are a cache, not a prerequisite: if the DB is
    // unreachable (or the cache tables were dropped), resolve live
    // from the 4byte directory API without caching.
    let sql: Awaited<ReturnType<typeof getSql>> | null = null;
    try {
      sql = await getSql();
    } catch {
      sql = null;
    }
    const lookup = createOnDemandFourbyteLookup(sql);
    const [sel, top] = await Promise.all([
      lookup.selectors(data.selectors),
      lookup.topics(data.topics),
    ]);
    return {
      selectors: Object.fromEntries(sel),
      topics: Object.fromEntries(top),
    };
  });
