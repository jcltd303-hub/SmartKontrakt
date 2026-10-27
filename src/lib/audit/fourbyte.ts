/**
 * 4byte.directory resolution: function selectors (4-byte) and event
 * topics (32-byte), resolved ON DEMAND (2026-10-22).
 *
 * The bulk-import model is retired: the full dataset (~1.18M function
 * + ~278k event signatures) cost 130 MB of Supabase storage for a
 * lookup any single audit only touches a few dozen keys of. Now,
 * when bytecode analysis encounters a selector/topic it doesn't know,
 * just that signature is pulled from the 4byte.directory API at that
 * moment (createOnDemandFourbyteLookup), and the two tables
 * (migrations 0005 + 0006, schema unchanged) serve as a CACHE of what
 * was actually pulled. A missing cache table or a dead upstream
 * degrades to "unknown", never to a failed audit.
 *
 * The sync bundled list in ./selectors.ts stays the fast path for the
 * ~100 common signatures — analyzeBytecode fills those inline. This
 * module resolves everything else.
 *
 * Callers with no DB (the browser workbench) do NOT call this module —
 * they use the resolveFourbyte server fn (fourbyte.functions.ts),
 * which runs the on-demand lookup server-side and returns plain maps.
 */
import type { Report } from "./types";
import type { Sql } from "../sql-client";

/** One batched DB lookup for selectors and topics. Keys are '0x'-prefixed hex. */
export type FourbyteLookup = {
  selectors(selectors: string[]): Promise<Map<string, string[]>>;
  topics(topics: string[]): Promise<Map<string, string[]>>;
};

export type FourbyteKind = "signatures" | "event-signatures";

/**
 * The DB-backed lookup, which also remembers misses. Kept separate from
 * FourbyteLookup so every existing fake (tests, cache-less callers) still
 * satisfies the small contract.
 */
export type FourbyteCache = FourbyteLookup & {
  recentMisses(kind: FourbyteKind, keys: string[]): Promise<Set<string>>;
  recordMisses(kind: FourbyteKind, keys: string[]): Promise<void>;
};

/** Plain-map form of a lookup result — what the resolveFourbyte server fn returns. */
export type FourbyteResults = {
  selectors: Record<string, string[]>;
  topics: Record<string, string[]>;
};

/** Cap per lookup: a contract's dispatcher + PUSH32s stay well under this. */
const MAX_KEYS = 500;

export function createDbFourbyteLookup(sql: Sql): FourbyteCache {
  return {
    selectors: async (keys) => {
      const out = new Map<string, string[]>();
      const uniq = [...new Set(keys.map((k) => k.toLowerCase()))].slice(0, MAX_KEYS);
      if (uniq.length === 0) return out;
      const rows = await sql<{ selector: string; signature: string }>`
        select selector, signature from fourbyte_signatures where selector = any(${uniq})`;
      for (const r of rows) {
        const arr = out.get(r.selector) ?? [];
        arr.push(r.signature);
        out.set(r.selector, arr);
      }
      return out;
    },
    topics: async (keys) => {
      const out = new Map<string, string[]>();
      const uniq = [...new Set(keys.map((k) => k.toLowerCase()))].slice(0, MAX_KEYS);
      if (uniq.length === 0) return out;
      const rows = await sql<{ topic: string; signature: string }>`
        select topic, signature from fourbyte_event_signatures where topic = any(${uniq})`;
      for (const r of rows) {
        const arr = out.get(r.topic) ?? [];
        arr.push(r.signature);
        out.set(r.topic, arr);
      }
      return out;
    },
    /** Keys recently checked and NOT found upstream — skip the network for these. */
    recentMisses: async (kind, keys) => {
      const out = new Set<string>();
      const uniq = [...new Set(keys.map((k) => k.toLowerCase()))].slice(0, MAX_KEYS);
      if (uniq.length === 0) return out;
      const rows = await sql<{ key: string }>`
        select key from fourbyte_misses
        where kind = ${kind}
          and key = any(${uniq})
          and checked_at > now() - make_interval(days => ${MISS_TTL_DAYS})`;
      for (const r of rows) out.add(r.key);
      return out;
    },
    recordMisses: async (kind, keys) => {
      const uniq = [...new Set(keys.map((k) => k.toLowerCase()))].slice(0, MAX_KEYS);
      if (uniq.length === 0) return;
      await sql`
        insert into fourbyte_misses (kind, key, checked_at)
        select ${kind}, k, now() from unnest(${uniq}::text[]) as k
        on conflict (kind, key) do update set checked_at = now()`;
    },
  };
}

/** Upstream 4byte.directory API base (verified live 2026-10-22). */
const FOURBYTE_API_BASE = "https://www.4byte.directory/api/v1";
/**
 * Per-request upstream timeout — enrichment must never stall an audit.
 *
 * 5s was too generous: on a bytecode-only contract every selector is a miss, so
 * the timeout is multiplied by N/8 lanes and became the whole audit's cost
 * (measured: 20 s per address, 23 days for 100k). A reply that takes more than
 * two seconds is not worth waiting for, and with negative caching the cost is
 * paid once per selector rather than once per contract.
 */
const UPSTREAM_TIMEOUT_MS = 2_000;

/** How long a miss is trusted before 4byte.directory is asked again. */
const MISS_TTL_DAYS = 7;
/** Bounded parallelism for batch upstream pulls. */
const UPSTREAM_CONCURRENCY = 8;
/** How long a negative upstream result stays memoized (ms). Successes
 * are memoized for the life of the process; negatives expire so a
 * transient outage cannot poison a long-lived worker. */
const NEGATIVE_MEMO_MS = 60_000;

/** Minimal fetch shape — injectable for tests. */
export type FourbyteFetchLike = (
  url: string,
  init?: { signal?: AbortSignal },
) => Promise<{ ok: boolean; status: number; json(): Promise<unknown> }>;

/** Per-process memo of upstream pulls: `s:<hex>` / `e:<hex>` -> promise. */
const upstreamMemo = new Map<string, Promise<string[] | null>>();

/** Test/ops helper: drop every memoized upstream pull. */
export function clearFourbyteUpstreamMemo(): void {
  upstreamMemo.clear();
}

/**
 * One upstream pull. The API returns `{ count, results: [{ id,
 * text_signature, hex_signature, ... }] }` NEWEST first — the
 * canonical registration for a selector is the LOWEST id (e.g.
 * transfer(address,uint256) is id 145 among six 0xa9059cbb rows), so
 * results are re-sorted ascending before use. Returns null on ANY
 * failure (HTTP error, timeout, bad JSON, no registrations).
 */
async function pullFromUpstream(
  kind: "signatures" | "event-signatures",
  hex: string,
  fetchImpl: FourbyteFetchLike,
): Promise<string[] | null> {
  const memoKey = `${kind === "signatures" ? "s" : "e"}:${hex}`;
  const hit = upstreamMemo.get(memoKey);
  if (hit) return hit;
  const p = (async (): Promise<string[] | null> => {
    try {
      const ctl = new AbortController();
      const timer = setTimeout(() => ctl.abort(), UPSTREAM_TIMEOUT_MS);
      try {
        const res = await fetchImpl(`${FOURBYTE_API_BASE}/${kind}/?hex_signature=${hex}`, {
          signal: ctl.signal,
        });
        if (!res.ok) return null;
        const body = (await res.json()) as { results?: unknown };
        const rows = Array.isArray(body?.results) ? body.results : [];
        const parsed: { id: number; sig: string }[] = [];
        for (const r of rows) {
          const row = r as { id?: unknown; text_signature?: unknown };
          if (typeof row?.id === "number" && typeof row?.text_signature === "string") {
            parsed.push({ id: row.id, sig: row.text_signature });
          }
        }
        if (parsed.length === 0) return null;
        parsed.sort((a, b) => a.id - b.id);
        return [...new Set(parsed.map((x) => x.sig))];
      } finally {
        clearTimeout(timer);
      }
    } catch {
      return null;
    }
  })();
  upstreamMemo.set(memoKey, p);
  if ((await p) === null) {
    const t = setTimeout(() => upstreamMemo.delete(memoKey), NEGATIVE_MEMO_MS);
    (t as unknown as { unref?: () => void }).unref?.();
  }
  return p;
}

/** Best-effort cache write of pulled signatures — never throws. */
async function cachePulled(
  sql: Sql,
  kind: "signatures" | "event-signatures",
  hex: string,
  sigs: string[],
): Promise<void> {
  try {
    for (const sig of sigs) {
      if (kind === "signatures") {
        await sql`insert into fourbyte_signatures (selector, signature) values (${hex}, ${sig}) on conflict do nothing`;
      } else {
        await sql`insert into fourbyte_event_signatures (topic, signature) values (${hex}, ${sig}) on conflict do nothing`;
      }
    }
  } catch {
    // Cache is an optimization: a failed write (incl. a dropped
    // table) never fails the lookup that already has the answer.
  }
}

/**
 * On-demand lookup — the resolution path since 2026-10-22.
 *
 * Same FourbyteLookup interface as createDbFourbyteLookup, so every
 * caller keeps working:
 *   1. Cache check in fourbyte_signatures / fourbyte_event_signatures
 *      (the tables are a cache of previously pulled rows now, not a
 *      preloaded dataset). A cache hit never touches the network, and
 *      a missing/broken cache is treated as an empty one.
 *   2. Cache misses pull just those keys from the 4byte.directory
 *      API (per-process memoized, concurrency-bounded, 5s timeout,
 *      canonical = lowest registration id) and best-effort insert
 *      what came back into the cache.
 *   3. Any upstream failure resolves as "unknown" (key absent) —
 *      never a throw.
 *
 * `sql` may be null: then every lookup is cache-less (live pull,
 * no caching) — used when the DB itself is unreachable.
 */
export function createOnDemandFourbyteLookup(
  sql?: Sql | null,
  opts?: { fetchImpl?: FourbyteFetchLike },
): FourbyteLookup {
  const fetchImpl: FourbyteFetchLike =
    opts?.fetchImpl ?? ((url, init) => fetch(url, init));
  const cache = sql ? createDbFourbyteLookup(sql) : null;

  const resolveBatch = async (
    kind: "signatures" | "event-signatures",
    keys: string[],
  ): Promise<Map<string, string[]>> => {
    const out = new Map<string, string[]>();
    const uniq = [...new Set(keys.map((k) => k.toLowerCase()))].slice(0, MAX_KEYS);
    if (uniq.length === 0) return out;
    if (cache) {
      try {
        const cached =
          kind === "signatures" ? await cache.selectors(uniq) : await cache.topics(uniq);
        for (const [k, v] of cached) if (v.length > 0) out.set(k, v);
      } catch {
        // Missing table / DB down: cache-less for this batch.
      }
    }
    // A key 4byte did not know within the TTL is not asked again: this is the
    // difference between 20 s per contract and a fraction of a second, because
    // on a bytecode-only report EVERY selector is a miss.
    let recent = new Set<string>();
    if (cache) {
      try {
        recent = await cache.recentMisses(kind, uniq);
      } catch {
        // Missing table / DB down: behave as before, cache-less.
      }
    }
    const misses = uniq.filter((k) => !out.has(k) && !recent.has(k));
    let idx = 0;
    const unanswered: string[] = [];
    const lanes = Array.from(
      { length: Math.min(UPSTREAM_CONCURRENCY, misses.length) },
      async () => {
        while (idx < misses.length) {
          const hex = misses[idx++]!;
          const sigs = await pullFromUpstream(kind, hex, fetchImpl);
          if (sigs && sigs.length > 0) {
            out.set(hex, sigs);
            if (sql) await cachePulled(sql, kind, hex, sigs);
          } else {
            // "I do not know this" is worth remembering too: the next contract
            // with this selector would otherwise pay the same timeout again.
            unanswered.push(hex);
          }
        }
      },
    );
    await Promise.all(lanes);
    if (cache && unanswered.length > 0) {
      try {
        await cache.recordMisses(kind, unanswered);
      } catch {
        // A failed miss write costs a repeat lookup later, never correctness.
      }
    }
    return out;
  };

  return {
    selectors: (keys) => resolveBatch("signatures", keys),
    topics: (keys) => resolveBatch("event-signatures", keys),
  };
}

/**
 * Merge lookup results into a report: fill unknown selector signatures
 * (first signature wins for display; `signatures` keeps all collisions)
 * and fill unresolved event topics. Pure + synchronous, so the browser
 * can apply server-fn results with it.
 */
export function applyFourbyteResults(report: Report, results: FourbyteResults): { resolvedSelectors: number; resolvedTopics: number } {
  let resolvedSelectors = 0;
  let resolvedTopics = 0;
  const inv = report.inventory;
  for (const s of inv.selectors) {
    if (s.signature) continue;
    const sigs = results.selectors[s.selector.toLowerCase()];
    if (sigs && sigs.length > 0) {
      s.signature = sigs[0]!;
      s.signatures = sigs;
      resolvedSelectors++;
    }
  }
  for (const t of inv.topics ?? []) {
    if (t.signature) continue;
    const sigs = results.topics[t.topic.toLowerCase()];
    if (sigs && sigs.length > 0) {
      t.signature = sigs[0]!;
      resolvedTopics++;
    }
  }
  return { resolvedSelectors, resolvedTopics };
}

/**
 * Full enrichment: look up unknown selectors + topic candidates and
 * merge. Never throws — enrichment failure leaves the report as-is,
 * because the audit stands without it.
 */
export async function enrichReportFourbyte(
  report: Report,
  lookup: FourbyteLookup,
): Promise<{ resolvedSelectors: number; resolvedTopics: number }> {
  try {
    const inv = report.inventory;
    const unknown = inv.selectors.filter((s) => !s.signature).map((s) => s.selector);
    const unresolvedTopics = (inv.topics ?? []).filter((t) => !t.signature).map((t) => t.topic);
    const [sel, top] = await Promise.all([lookup.selectors(unknown), lookup.topics(unresolvedTopics)]);
    return applyFourbyteResults(report, {
      selectors: Object.fromEntries(sel),
      topics: Object.fromEntries(top),
    });
  } catch {
    return { resolvedSelectors: 0, resolvedTopics: 0 };
  }
}

/** Build the server-fn payload shape from a report's resolved names. */
export function fourbyteResultsFromReport(report: Report): FourbyteResults {
  const selectors: Record<string, string[]> = {};
  for (const s of report.inventory.selectors) {
    // Keep ALL collision signatures, not just the first — the prompt
    // (#5) shows every known overload so the model picks the right one.
    if (s.signatures && s.signatures.length > 0) selectors[s.selector.toLowerCase()] = s.signatures;
    else if (s.signature) selectors[s.selector.toLowerCase()] = [s.signature];
  }
  const topics: Record<string, string[]> = {};
  for (const t of report.inventory.topics ?? []) {
    if (t.signature) topics[t.topic.toLowerCase()] = [t.signature];
  }
  return { selectors, topics };
}

/** Prompt-sized rendering of resolved names, for AI + Deep Agent. */
export function formatFourbyteResultsForPrompt(results: FourbyteResults, maxSelectors = 40, maxTopics = 20): string {
  const selEntries = Object.entries(results.selectors).slice(0, maxSelectors);
  const topEntries = Object.entries(results.topics).slice(0, maxTopics);
  if (selEntries.length === 0 && topEntries.length === 0) return "";
  const lines = ["\nKNOWN FUNCTIONS + EVENTS (4byte.directory — resolved from the target's bytecode; these exist on the target, prefer them over invented interfaces):"];
  // A selector can collide (several signatures share 4 bytes). The model
  // sees every known overload, not just the first — picking the wrong
  // overload is a classic fabricated-interface failure.
  const showSigs = (sigs: string[]) => {
    const shown = sigs.slice(0, 3).join(" | ");
    return sigs.length > 3 ? `${shown} (+${sigs.length - 3} more)` : shown;
  };
  if (selEntries.length > 0) {
    lines.push("Functions:");
    for (const [sel, sigs] of selEntries) lines.push(`- ${showSigs(sigs)} — ${sel}`);
  }
  if (topEntries.length > 0) {
    lines.push("Events:");
    for (const [topic, sigs] of topEntries) lines.push(`- ${showSigs(sigs)} — ${topic}`);
  }
  return lines.join("\n");
}

/** Prompt-sized rendering of a report's resolved names, for AI + Deep Agent. */
export function formatFourbyteForPrompt(report: Report, maxSelectors = 40, maxTopics = 20): string {
  return formatFourbyteResultsForPrompt(fourbyteResultsFromReport(report), maxSelectors, maxTopics);
}
