import { keccak256 } from "js-sha3";
import { executeEthCall, fetchLatestBlockNumber } from "./simulator.ts";
import type { AbiItem } from "./types.ts";

/**
 * Live-state verification for high/critical findings (2026-10-22).
 *
 * Several detector closures are argued from SOURCE alone — a fee that
 * starts at 0 in the constructor, a trading flag initialized false, an
 * owner that "will" renounce. Live mutable state can differ from every
 * one of those deployment-time values, so a source-only closure is
 * provisional. This module is the live counterpart: when a verified-
 * source analysis produces a high or critical finding, the contract's
 * decisive no-arg getters are probed over public RPC and the LIVE
 * values are attached to the record as adjudication evidence.
 *
 * Findings are NOT re-scored — the report is evidence a human (or a
 * later adjudication pass) checks a closure against: "source says
 * taxFee initializes to 0" vs "live taxFee() returns 2500".
 *
 * The candidate getters mirror what the detector actually reasons
 * about (detect.ts):
 *  - `paused` — pause/unpause are admin functions there, and closures
 *    argue from Pausable state; COMMON_PROBES already probes it.
 *  - `owner` / `getOwner` — the access-control cap and the
 *    centralization / unprotected-admin rules turn on who holds
 *    ownership; the zero-address rule spells out that owner ==
 *    address(0) makes onlyOwner permanently false, so the live value
 *    separates "renounced" from "held by an EOA".
 *  - trading / swap toggles (`tradingEnabled`, `tradingOpen`, ...) and
 *    `limitsInEffect` — launch + anti-whale flags whose INITIAL value
 *    is routinely argued from the constructor while the live value is
 *    what decides whether transfers actually execute.
 *  - fee / tax getters (`buyFee`, `sellFee`, `taxFee`, ...) — the
 *    fee-on-transfer detector and the handleTax-style swap reasoning;
 *    a setFee-set live fee is a different contract than the deployed
 *    default.
 *  - limit getters (`maxTxAmount`, `maxWalletAmount`,
 *    `swapTokensAtAmount`) — anti-whale caps and the auto-swap
 *    threshold that arms the tax-swap machinery.
 *
 * Probing reuses the existing probes mechanism in simulator.ts
 * (executeEthCall: SUPPORTED_CHAINS rotation + rpcLimiter + withRetry)
 * rather than a parallel RPC stack. Everything here NEVER throws: RPC
 * failure lands in `failures`, partial results are kept, and the whole
 * probe is deadline-bounded so it cannot stall an audit.
 */

export type LiveStateKind = "bool" | "address" | "uint";

export type DecisiveGetter = {
  /** Getter name as declared, e.g. "paused" or "_maxTxAmount". */
  name: string;
  kind: LiveStateKind;
  /** Full signature, e.g. "paused()". */
  signature: string;
  /** 0x-prefixed 4-byte selector (the eth_call calldata). */
  selector: string;
};

export type LiveStateRead = {
  name: string;
  kind: LiveStateKind;
  /** Decoded value: "true"/"false", 0x-address, or a decimal string. */
  value: string;
  /** Raw eth_call result hex, exactly as returned. */
  raw: string;
};

export type LiveStateFailure = {
  name: string;
  error: string;
};

export type LiveStateReport = {
  address: string;
  chainId: string;
  /** Chain height the reads were taken at; null when no RPC gave one. */
  blockNumber: number | null;
  reads: LiveStateRead[];
  failures: LiveStateFailure[];
  /**
   * keccak256 of the runtime code the reads describe, when the caller could supply it.
   *
   * Without this the reads are unbound: they say what `paused()` returned at some block,
   * on some contract, with nothing tying them to the code that was audited. Ported from
   * the Perplexity incident harness, which refuses any probe result whose runtimeSha256
   * does not match the one it recorded.
   */
  codeHash?: string | null;
};

/**
 * Candidate decisive getters, in probe-priority order. Kind is the
 * EXPECTED return family: discovery only accepts a candidate when the
 * declared return type matches (a `paused()` returning a string is not
 * the Pausable getter and is ignored).
 */
const DECISIVE_GETTERS: { name: string; kind: LiveStateKind }[] = [
  { name: "paused", kind: "bool" },
  { name: "owner", kind: "address" },
  { name: "getOwner", kind: "address" },
  { name: "tradingEnabled", kind: "bool" },
  { name: "tradingOpen", kind: "bool" },
  { name: "tradingActive", kind: "bool" },
  { name: "isTradingEnabled", kind: "bool" },
  { name: "tradeEnabled", kind: "bool" },
  { name: "swapEnabled", kind: "bool" },
  { name: "limitsInEffect", kind: "bool" },
  { name: "buyFee", kind: "uint" },
  { name: "sellFee", kind: "uint" },
  { name: "buyTax", kind: "uint" },
  { name: "sellTax", kind: "uint" },
  { name: "taxFee", kind: "uint" },
  { name: "_taxFee", kind: "uint" },
  { name: "transferFee", kind: "uint" },
  { name: "liquidityFee", kind: "uint" },
  { name: "_liquidityFee", kind: "uint" },
  { name: "marketingFee", kind: "uint" },
  { name: "totalFees", kind: "uint" },
  { name: "maxTxAmount", kind: "uint" },
  { name: "_maxTxAmount", kind: "uint" },
  { name: "maxWalletAmount", kind: "uint" },
  { name: "_maxWalletAmount", kind: "uint" },
  { name: "maxWallet", kind: "uint" },
  { name: "_maxWallet", kind: "uint" },
  { name: "swapTokensAtAmount", kind: "uint" },
];

const CANDIDATE_KIND = new Map(DECISIVE_GETTERS.map((g) => [g.name, g.kind]));

/** Hard cap on probed getters — bounds RPC load and report size. */
export const MAX_LIVE_GETTERS = 16;

/** Overall probe deadline; unfinished getters land in `failures`. */
export const LIVE_STATE_DEADLINE_MS = 10_000;

function kindOfType(typeName: string): LiveStateKind | null {
  const t = typeName.trim().toLowerCase().replace(/\s+/g, " ");
  if (t === "bool") return "bool";
  if (t === "address" || t === "address payable") return "address";
  if (/^u?int\d*$/.test(t)) return "uint";
  return null;
}

function toGetter(name: string, kind: LiveStateKind): DecisiveGetter {
  const signature = `${name}()`;
  return { name, kind, signature, selector: "0x" + keccak256(signature).slice(0, 8) };
}

const escapeRe = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

/**
 * Discover which candidate decisive getters a contract actually
 * exposes, from its verified source and/or its gathered ABI. Only
 * no-arg view/pure functions and public state variables (which ARE
 * no-arg view getters) count, and the declared return type must match
 * the candidate's kind. Setters, parameterized functions, and
 * non-view functions are ignored. Result is in candidate-priority
 * order, deduped by name, capped at MAX_LIVE_GETTERS.
 */
export function discoverDecisiveGetters(input: {
  source?: string | null;
  abi?: AbiItem[] | null;
}): DecisiveGetter[] {
  const found = new Map<string, LiveStateKind>();

  // From the ABI: exact ground truth when one was gathered.
  for (const item of input.abi ?? []) {
    if (!item || item.type !== "function" || !item.name) continue;
    const expected = CANDIDATE_KIND.get(item.name);
    if (!expected || found.has(item.name)) continue;
    if ((item.inputs?.length ?? 0) !== 0) continue;
    if (item.stateMutability !== "view" && item.stateMutability !== "pure") continue;
    const outputs = item.outputs ?? [];
    if (outputs.length !== 1) continue;
    const kind = kindOfType(outputs[0]!.type ?? "");
    if (kind === expected) found.set(item.name, kind);
  }

  // From source: no-arg view/pure function declarations and public
  // state variables whose names are candidates.
  const source = input.source ?? "";
  if (source) {
    for (const { name, kind: expected } of DECISIVE_GETTERS) {
      if (found.has(name)) continue;
      const n = escapeRe(name);
      // function NAME() ... view|pure ... returns (TYPE ...)
      const fnRe = new RegExp(
        `function\\s+${n}\\s*\\(\\s*\\)([^;{]*)`,
        "g",
      );
      let isGetter = false;
      for (const m of source.matchAll(fnRe)) {
        const segment = m[1] ?? "";
        if (!/\b(view|pure)\b/.test(segment)) continue;
        const ret = segment.match(/returns\s*\(\s*(bool|address(?:\s+payable)?|u?int\d*)\b/);
        if (ret && kindOfType(ret[1]!) === expected) {
          isGetter = true;
          break;
        }
      }
      if (!isGetter) {
        // TYPE public NAME — a public state variable generates the getter.
        const varRe = new RegExp(
          `\\b(bool|address(?:\\s+payable)?|u?int\\d*)\\s+(?:public\\s+)(?:constant\\s+|immutable\\s+)?${n}\\b`,
        );
        const vm = source.match(varRe);
        if (vm && kindOfType(vm[1]!) === expected) isGetter = true;
      }
      if (isGetter) found.set(name, expected);
    }
  }

  return DECISIVE_GETTERS.filter((g) => found.has(g.name))
    .slice(0, MAX_LIVE_GETTERS)
    .map((g) => toGetter(g.name, found.get(g.name)!));
}

/** Decode one 32-byte ABI word. Returns null on an undecodable word. */
function decodeWord(raw: string, kind: LiveStateKind): string | null {
  const clean = raw.replace(/^0x/, "");
  if (!/^[0-9a-fA-F]+$/.test(clean)) return null;
  const word = clean.slice(0, 64).padStart(64, "0");
  try {
    if (kind === "bool") return BigInt("0x" + word) !== 0n ? "true" : "false";
    if (kind === "address") return "0x" + word.slice(24).toLowerCase();
    return BigInt("0x" + word).toString();
  } catch {
    return null;
  }
}

export type EthCallFn = (
  address: string,
  calldata: string,
  chainId: string,
) => Promise<{ success: boolean; result?: string; error?: string }>;

export type LiveStateProbeOpts = {
  /** Injectable eth_call (tests); defaults to simulator's executeEthCall. */
  callFn?: EthCallFn;
  /** Injectable block-number fetch (tests); defaults to simulator's. */
  blockNumberFn?: (chainId: string) => Promise<number | null>;
  /** Overall deadline; defaults to LIVE_STATE_DEADLINE_MS. */
  deadlineMs?: number;
  /** keccak256 of the runtime code being probed, recorded on the report. */
  codeHash?: string | null;
};

/**
 * Probe the given getters at `address` in parallel and build the
 * report. NEVER throws — every failure (RPC down, revert, empty
 * result, deadline) is recorded per-getter and partial results kept.
 * An empty getter list short-circuits to an empty report with no RPC
 * traffic at all.
 */
export async function probeLiveState(
  address: string,
  chainId: string,
  getters: DecisiveGetter[],
  opts?: LiveStateProbeOpts,
): Promise<LiveStateReport> {
  const report: LiveStateReport = {
    address,
    chainId,
    blockNumber: null,
    reads: [],
    failures: [],
    codeHash: opts?.codeHash ?? null,
  };
  const capped = getters.slice(0, MAX_LIVE_GETTERS);
  if (capped.length === 0) return report;

  const callFn = opts?.callFn ?? executeEthCall;
  const blockNumberFn = opts?.blockNumberFn ?? fetchLatestBlockNumber;
  const deadlineMs = opts?.deadlineMs ?? LIVE_STATE_DEADLINE_MS;
  const done = new Set<string>();

  const work = (async () => {
    const blockPromise = Promise.resolve()
      .then(() => blockNumberFn(chainId))
      .catch(() => null);
    const probes = capped.map(async (g) => {
      try {
        const call = await callFn(address, g.selector, chainId);
        if (call.success && call.result && call.result !== "0x") {
          const value = decodeWord(call.result, g.kind);
          if (value !== null) {
            report.reads.push({ name: g.name, kind: g.kind, value, raw: call.result });
          } else {
            report.failures.push({ name: g.name, error: "undecodable result" });
          }
        } else {
          report.failures.push({
            name: g.name,
            error: call.error || "empty result (getter missing or reverted)",
          });
        }
      } catch (err) {
        report.failures.push({
          name: g.name,
          error: err instanceof Error ? err.message : "eth_call threw",
        });
      } finally {
        done.add(g.name);
      }
    });
    const [block] = await Promise.all([blockPromise, ...probes]);
    if (typeof block === "number" && Number.isFinite(block)) {
      report.blockNumber = block;
    }
  })();

  let timer: ReturnType<typeof setTimeout> | undefined;
  const deadline = new Promise<void>((resolve) => {
    timer = setTimeout(resolve, deadlineMs);
  });
  try {
    await Promise.race([work, deadline]);
  } catch {
    // work is built to never reject; the race is belt-and-braces.
  } finally {
    if (timer) clearTimeout(timer);
  }

  for (const g of capped) {
    if (!done.has(g.name)) {
      report.failures.push({ name: g.name, error: `probe deadline (${deadlineMs}ms) exceeded` });
    }
  }
  // Deterministic candidate order regardless of completion order.
  const order = new Map(capped.map((g, i) => [g.name, i]));
  report.reads.sort((a, b) => (order.get(a.name) ?? 0) - (order.get(b.name) ?? 0));
  report.failures.sort((a, b) => (order.get(a.name) ?? 0) - (order.get(b.name) ?? 0));
  return report;
}

/**
 * Discover + probe in one call. Returns null when the contract exposes
 * no decisive getters — the caller then attaches nothing and the audit
 * pays no latency. Never throws.
 */
export async function gatherLiveState(
  address: string,
  chainId: string,
  input: { source?: string | null; abi?: AbiItem[] | null },
  opts?: LiveStateProbeOpts,
): Promise<LiveStateReport | null> {
  const getters = discoverDecisiveGetters(input);
  if (getters.length === 0) return null;
  return probeLiveState(address, chainId, getters, opts);
}
