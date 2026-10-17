import { createServerFn } from "@tanstack/react-start";
import type { FourbyteResults } from "./fourbyte";

/**
 * Resolve 4byte selectors + event topics server-side (DB tables from
 * migrations 0005 + 0006). The browser workbench cannot query Supabase
 * directly, so it calls this after analyzeAddress and merges the result
 * with applyFourbyteResults. The worker uses createDbFourbyteLookup
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
    const { createDbFourbyteLookup } = await import("./fourbyte");
    const sql = await getSql();
    const lookup = createDbFourbyteLookup(sql);
    const [sel, top] = await Promise.all([
      lookup.selectors(data.selectors),
      lookup.topics(data.topics),
    ]);
    return {
      selectors: Object.fromEntries(sel),
      topics: Object.fromEntries(top),
    };
  });
