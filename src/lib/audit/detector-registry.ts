// src/lib/audit/detector-registry.ts
//
// One declaration per detector: which FAMILY of mechanism it belongs to.
//
// Two problems this fixes, both measured rather than imagined:
//
//  1. Sixty-plus detectors describe far fewer mechanisms. `oracle-spot`,
//     `balance-as-price` and `oracle-staleness` are one story about price
//     plumbing; `hook-callback-auth`, `self-attested-auth` and
//     `ecrecover-zero` are one story about caller identity. Reporting them as
//     separate findings is how a report becomes a count of rules instead of a
//     count of problems, so findings carry a `family` and the UI can group.
//
//  2. A rule that exists only in `detect.ts` drifts, and a detector that
//     exists only in the docs drifts worse. This registry is total over what
//     the engine actually emits, and the tests assert that — which is how
//     HARNESS_ONLY_DETECTORS below was found: three "detectors" had a PoC
//     template and a SmartBugs category but no rule behind them.
//
// The SmartBugs category stays in smartbugs.ts (it is the dataset's taxonomy,
// not ours) and the harness stays in foundry/poc-fallbacks/index.json (it is a
// file). This module adds the axis neither of them owns.

export type DetectorFamily =
  | "caller-identity"
  | "price-plumbing"
  | "reentrancy"
  | "arithmetic"
  | "randomness"
  | "value-and-settlement"
  | "ordering"
  | "token-accounting"
  | "evm-and-bytecode"
  | "hygiene"
  | "analyzer-meta";

export type DetectorFamilyMeta = {
  id: DetectorFamily;
  label: string;
  /** What the family is, in one line a reviewer can act on. */
  question: string;
};

export const DETECTOR_FAMILIES: DetectorFamilyMeta[] = [
  {
    id: "caller-identity",
    label: "Who can reach this",
    question: "Does the entry point establish who may call it — and does that check survive delegation, forwarding and callbacks?",
  },
  {
    id: "price-plumbing",
    label: "What price does it trust",
    question: "Is the number the protocol prices with something an attacker can move, or something nobody checked the freshness of?",
  },
  { id: "reentrancy", label: "Re-entry", question: "Can the callee re-enter before the state it depends on is settled?" },
  { id: "arithmetic", label: "Arithmetic and rounding", question: "Does the math wrap, truncate, or round in the caller's favour?" },
  { id: "randomness", label: "Entropy and clocks", question: "Is the draw or the gate derived from something the block producer controls or predicts?" },
  { id: "value-and-settlement", label: "Value flow and settlement", question: "Who ends up with the value, and can the caller choose whether to settle?" },
  { id: "ordering", label: "Ordering and MEV", question: "Can someone who sees the transaction first profit from being first?" },
  { id: "token-accounting", label: "Token and signature accounting", question: "Do the token's real semantics and the signature's real coverage match what the code assumes?" },
  { id: "evm-and-bytecode", label: "EVM and bytecode", question: "What does the deployed code do that the source does not say?" },
  { id: "hygiene", label: "Hygiene", question: "Nothing exploitable alone — metadata, compiler pinning, event completeness." },
  { id: "analyzer-meta", label: "Analyzer meta", question: "Not a property of the target: the input could not be parsed, or the report was capped." },
];

/**
 * Detectors that have a PoC template and a SmartBugs category but NO rule in
 * the analyzer. Found by making this registry total: `front-running`,
 * `short-address` and `external-contract-referencing` were declared in
 * smartbugs.ts and shipped a harness each, yet nothing in detect.ts ever emits
 * them, so no scan has ever produced one. They are listed here rather than
 * given a family, because giving them a family would claim coverage that does
 * not exist. Either a rule is written for them or the template is retired.
 */
export const HARNESS_ONLY_DETECTORS = [
  "external-contract-referencing",
  "front-running",
  "short-address",
] as const;

/** Detector -> family. Total over every id the engine can emit. */
export const DETECTOR_FAMILY: Record<string, DetectorFamily> = {
  // caller-identity
  "arbitrary-dispatch-call": "caller-identity",
  "assembly-param-sstore": "caller-identity",
  "assembly-sstore": "caller-identity",
  "bridge-message-auth": "caller-identity",
  "bytecode-callcode": "caller-identity",
  "bytecode-delegatecall": "caller-identity",
  "bytecode-origin": "caller-identity",
  "calldata-offset-auth": "caller-identity",
  "centralization": "caller-identity",
  "default-visibility": "caller-identity",
  "delegatecall": "caller-identity",
  "ecrecover-zero": "caller-identity",
  "eoa-only-guard": "caller-identity",
  "extcodesize": "caller-identity",
  "governance-live-voting-power": "caller-identity",
  "hook-callback-auth": "caller-identity",
  "public-key-account-trust": "caller-identity",
  "self-attested-auth": "caller-identity",
  "shadowing": "caller-identity",
  "token-drain": "caller-identity",
  "tx-origin": "caller-identity",
  "unauthenticated-batch-call": "caller-identity",
  "unprotected-admin": "caller-identity",
  "unprotected-ether": "caller-identity",
  "unprotected-initializer": "caller-identity",
  // price-plumbing
  "balance-as-price": "price-plumbing",
  "oracle-spot": "price-plumbing",
  "oracle-staleness": "price-plumbing",
  // reentrancy
  "bytecode-reentrancy-shape": "reentrancy",
  "read-only-reentrancy": "reentrancy",
  "reentrancy": "reentrancy",
  // arithmetic
  "div-before-mul": "arithmetic",
  "unchecked-block": "arithmetic",
  // randomness
  "bytecode-timestamp": "randomness",
  "timestamp": "randomness",
  "weak-randomness": "randomness",
  // value-and-settlement
  "eth-gas-stipend": "value-and-settlement",
  "gas-estimator-dos": "value-and-settlement",
  "hardcoded-gas": "value-and-settlement",
  "locked-ether": "value-and-settlement",
  "msg-value-loop": "value-and-settlement",
  "registry-dispatched-logic": "value-and-settlement",
  "settlement-optionality": "value-and-settlement",
  "strict-balance": "value-and-settlement",
  "zero-address": "value-and-settlement",
  // ordering
  "slippage": "ordering",
  "zero-slippage-swap": "ordering",
  // token-accounting
  "encode-packed": "token-accounting",
  "fee-on-transfer": "token-accounting",
  "private-secret": "token-accounting",
  "signature-malleability": "token-accounting",
  "signature-replay": "token-accounting",
  "storage-gap": "token-accounting",
  // evm-and-bytecode
  "bytecode-create2": "evm-and-bytecode",
  "bytecode-metadata": "evm-and-bytecode",
  "bytecode-proxy": "evm-and-bytecode",
  "bytecode-selfdestruct": "evm-and-bytecode",
  "bytecode-unchecked-call": "evm-and-bytecode",
  "erc20-unchecked": "evm-and-bytecode",
  "selfdestruct": "evm-and-bytecode",
  "unchecked-call": "evm-and-bytecode",
  // hygiene
  "floating-pragma": "hygiene",
  "missing-event": "hygiene",
  "old-compiler": "hygiene",
  "rtl-override": "hygiene",
  // analyzer-meta
  "parse": "analyzer-meta",
  "report-cap": "analyzer-meta",
};

/** Family for a detector; `analyzer-meta` for an id nothing declares. */
export function familyForDetector(detector: string): DetectorFamily {
  return DETECTOR_FAMILY[detector] ?? "analyzer-meta";
}

/** Every detector in a family, sorted. */
export function detectorsInFamily(family: DetectorFamily): string[] {
  return Object.keys(DETECTOR_FAMILY)
    .filter((d) => DETECTOR_FAMILY[d] === family)
    .sort();
}

/** A finding shape minimal enough to group without importing the engine. */
export type GroupableFinding = {
  detector: string;
  family?: DetectorFamily | null;
  severity: string;
  title: string;
  reachability?: string | null;
};

export type FamilyGroup<T extends GroupableFinding> = {
  family: DetectorFamily;
  label: string;
  question: string;
  findings: T[];
  /** Detectors represented in this group, de-duplicated and sorted. */
  detectors: string[];
  /** True when every finding in the group is REACHABLE. */
  allReachable: boolean;
};

/**
 * Collapse a finding list into mechanism groups, ordered so groups containing a
 * REACHABLE finding come first, then the largest. This is the "stop reporting
 * counts as findings" transformation: one contract with six price-plumbing
 * findings becomes one group with six sub-points, not six lines in a list.
 */
export function groupFindingsByFamily<T extends GroupableFinding>(findings: T[]): FamilyGroup<T>[] {
  const byFamily = new Map<DetectorFamily, T[]>();
  for (const f of findings) {
    const fam = (f.family ?? familyForDetector(f.detector)) as DetectorFamily;
    const list = byFamily.get(fam) ?? [];
    list.push(f);
    byFamily.set(fam, list);
  }
  const groups: FamilyGroup<T>[] = [];
  for (const [family, list] of byFamily) {
    const meta = DETECTOR_FAMILIES.find((m) => m.id === family);
    groups.push({
      family,
      label: meta?.label ?? family,
      question: meta?.question ?? "",
      findings: list,
      detectors: [...new Set(list.map((f) => f.detector))].sort(),
      allReachable: list.every((f) => f.reachability === "REACHABLE"),
    });
  }
  groups.sort((a, b) => {
    const all = Number(b.allReachable) - Number(a.allReachable);
    if (all !== 0) return all;
    const any =
      Number(b.findings.some((f) => f.reachability === "REACHABLE")) -
      Number(a.findings.some((f) => f.reachability === "REACHABLE"));
    if (any !== 0) return any;
    return b.findings.length - a.findings.length;
  });
  return groups;
}
