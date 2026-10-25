// src/lib/audit/poc-audit-llm.ts
//
// LLM-input parity for the PoC Audits page.
//
// The prompt BUILDERS are shared across surfaces — buildAiReviewPrompt
// for reviews, repairPocCode (behind requestPocRepair) for PoC
// repair/generation, one adjudicate-chain module driving both the
// workbench and this page. What drifted was the INPUTS each surface
// fed those builders:
//
//  1. The workbench sends resolved fourbyte context with every review
//     request (fourbyteResultsFromReport over the live report); the
//     PoC page's adjudication-chain dep sent none, so the model got a
//     thinner brief for the same scan. pocAuditReviewPayload rebuilds
//     the payload with the same helper over the stored scan's report.
//  2. The workbench repairs PoCs against the full contract source;
//     this page's direct Run PoC / AUDIT ALL path repaired against
//     `finding.snippet || finding.exploitSolidity` — a few lines
//     around the finding. createRepairBodyResolver loads the parent
//     scan's full stored body (cached per scanId, so AUDIT ALL loads
//     a scan once however many findings it carries) and falls back
//     to the snippet ONLY when the stored body cannot be loaded —
//     with the reason attached, so the caller can put the downgrade
//     on the run record instead of letting it pass silently.

import { fourbyteResultsFromReport, type FourbyteResults } from "./fourbyte.ts";
import type { ResnetResult } from "./resnet-result.ts";
import type { Finding, Inventory, Report } from "./types.ts";

/** The requestAiReview payload the PoC Audits page sends — the same
 *  fields, from the same sources, as the workbench's review calls. */
export type PocAuditReviewPayload = {
  contractName: string;
  body: string;
  findings: Finding[];
  fourbyte: FourbyteResults | undefined;
  inventory: Partial<Inventory> | undefined;
  resnet: ResnetResult | null | undefined;
};

export function pocAuditReviewPayload(input: {
  contractName: string;
  body: string;
  findings: Finding[];
  storedReport: Report | null | undefined;
}): PocAuditReviewPayload {
  return {
    contractName: input.contractName,
    body: input.body,
    findings: input.findings,
    fourbyte: fourbyteForStoredReport(input.storedReport),
    inventory: input.storedReport?.inventory,
    resnet: input.storedReport?.resnet,
  };
}

/**
 * The fourbyte payload for a stored report — the same helper the
 * workbench runs over its live report. Returns undefined when the
 * stored record cannot yield results (no report, or an inventory
 * without a selectors array — records predating the current Report
 * shape): parity means sending what the scan actually carries, never
 * fabricating context. A well-formed report with nothing resolved
 * yields the helper's empty-maps object, exactly what the workbench
 * sends for the same state (the server fn normalizes empty maps to
 * absent before the prompt is built).
 */
export function fourbyteForStoredReport(
  report: Report | null | undefined,
): FourbyteResults | undefined {
  if (!report?.inventory || !Array.isArray(report.inventory.selectors)) return undefined;
  return fourbyteResultsFromReport(report);
}

/** What an LLM repair/generation call in the direct run path sees. */
export type RepairBodyResolution = {
  /** The body to hand requestPocRepair / the generation gate. */
  body: string;
  /** "stored": the parent scan's full stored body (workbench parity).
   *  "snippet": the finding-snippet fallback — engaged only when the
   *  stored body could not be loaded. */
  source: "stored" | "snippet";
  /** Why the snippet fallback engaged; present iff source is
   *  "snippet". Callers surface it in the run output. */
  note?: string;
};

/** Loads a scan's stored body by id; null when there is none. */
export type StoredBodyLoader = (scanId: string) => Promise<string | null>;

/**
 * Per-scanId caching resolver for the direct path's repair body.
 * The load for a scan runs at most once per resolver instance —
 * successes AND failures are cached, so a batch run over many
 * findings of one scan fetches its body exactly once.
 */
export function createRepairBodyResolver(loadStoredBody: StoredBodyLoader): {
  resolve: (scanId: string, fallbackBody: string) => Promise<RepairBodyResolution>;
  cachedScanCount: () => number;
} {
  const loads = new Map<string, Promise<{ body: string | null; loadError?: string }>>();
  const loadOnce = (scanId: string): Promise<{ body: string | null; loadError?: string }> => {
    let pending = loads.get(scanId);
    if (!pending) {
      pending = (async () => {
        try {
          const body = await loadStoredBody(scanId);
          return { body: typeof body === "string" && body.trim() ? body : null };
        } catch (err) {
          return { body: null, loadError: err instanceof Error ? err.message : String(err) };
        }
      })();
      loads.set(scanId, pending);
    }
    return pending;
  };
  return {
    cachedScanCount: () => loads.size,
    async resolve(scanId, fallbackBody) {
      const { body, loadError } = await loadOnce(scanId);
      if (body) return { body, source: "stored" };
      return {
        body: fallbackBody,
        source: "snippet",
        note: loadError
          ? `Stored contract body could not be loaded (${loadError}) — the LLM repair/generation saw only the finding snippet.`
          : "No stored contract body for this scan (payload missing or empty) — the LLM repair/generation saw only the finding snippet.",
      };
    },
  };
}

/**
 * The external token a token-rescue run (template 46) should judge for
 * this target, from the stored scan's valuation (report.inventory
 * .value.holdings — the analyzer's persisted holdings inventory).
 *
 * Template 46 reads POC_TOKEN: when set, it judges the target's
 * balance of THAT token; unset, it can only test the target-as-its-
 * own-token case. The candidate is the target's most valuable EXTERNAL
 * ERC-20 holding: kind "erc20", a real address, not the target itself,
 * and a non-zero raw balance. Greatest valueUsd wins; holdings without
 * a USD value rank last (a known balance with no price still beats no
 * candidate at all). Returns null when the stored report carries no
 * valuation or no qualifying holding — the run then keeps the
 * own-token default, unchanged.
 */
export function externalTokenCandidate(
  report: Pick<Report, "inventory"> | null | undefined,
  targetAddress: string | null | undefined,
): string | null {
  const holdings = report?.inventory?.value?.holdings;
  if (!holdings || holdings.length === 0) return null;
  const target = (targetAddress ?? "").toLowerCase();
  let best: string | null = null;
  let bestValue = Number.NEGATIVE_INFINITY;
  for (const h of holdings) {
    if (h.kind !== "erc20" || !h.address) continue;
    if (target && h.address.toLowerCase() === target) continue;
    if (!h.raw || h.raw === "0") continue;
    // Unpriced holdings rank below every priced one (even $0) but
    // still count when nothing priced exists.
    const value = h.valueUsd ?? -1;
    if (value > bestValue) {
      bestValue = value;
      best = h.address;
    }
  }
  return best;
}
