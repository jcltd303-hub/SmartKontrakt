/**
 * SmartBugs Curated taxonomy.
 *
 * The fallback PoC library is organised by the same DASP categories as
 * **SmartBugs Curated** (https://github.com/smartbugs/smartbugs-curated), the
 * reference dataset of annotated vulnerable Solidity contracts, so a finding's
 * detector maps to a dataset category and to a working Foundry template.
 *
 * This module is the taxonomy + the detector -> category mapping. The
 * file -> category mapping lives in `foundry/poc-fallbacks/index.json` and is
 * emitted as `POC_FALLBACK_BY_SMARTBUGS` by `scripts/generate-poc-fallbacks-ts.mjs`.
 */

export type SmartBugsCategory =
  | "reentrancy"
  | "access_control"
  | "arithmetic"
  | "unchecked_low_level_calls"
  | "denial_of_service"
  | "bad_randomness"
  | "front_running"
  | "time_manipulation"
  | "short_addresses"
  | "other";

export const SMARTBUGS_SOURCE_URL = "https://github.com/smartbugs/smartbugs-curated";

export type SmartBugsCategoryMeta = {
  id: SmartBugsCategory;
  /** Human label, matching the SmartBugs Curated README. */
  label: string;
  /** "Solidity" | "Blockchain" | "EVM" — the level at which the class manifests. */
  level: string;
  description: string;
};

/** The ten categories of the dataset (nine DASP classes + "other"). */
export const SMARTBUGS_CATEGORIES: SmartBugsCategoryMeta[] = [
  {
    id: "reentrancy",
    label: "Reentrancy",
    level: "Solidity",
    description: "Reentrant function calls make a contract behave in an unexpected way.",
  },
  {
    id: "access_control",
    label: "Access Control",
    level: "Solidity",
    description: "Failure to use function modifiers, or use of tx.origin.",
  },
  {
    id: "arithmetic",
    label: "Arithmetic",
    level: "Solidity",
    description: "Integer over/underflows.",
  },
  {
    id: "unchecked_low_level_calls",
    label: "Unchecked Low Level Calls",
    level: "Solidity",
    description: "call(), callcode(), delegatecall() or send() fails and it is not checked.",
  },
  {
    id: "denial_of_service",
    label: "Denial Of Service",
    level: "Solidity",
    description: "The contract is overwhelmed with time-consuming computations.",
  },
  {
    id: "bad_randomness",
    label: "Bad Randomness",
    level: "Blockchain",
    description: "A malicious miner biases the outcome.",
  },
  {
    id: "front_running",
    label: "Front Running",
    level: "Blockchain",
    description: "Two dependent transactions that invoke the same contract are included in one block.",
  },
  {
    id: "time_manipulation",
    label: "Time Manipulation",
    level: "Blockchain",
    description: "The timestamp of the block is manipulated by the miner.",
  },
  {
    id: "short_addresses",
    label: "Short Addresses",
    level: "EVM",
    description: "The EVM itself accepts incorrectly padded arguments.",
  },
  {
    id: "other",
    label: "Other",
    level: "Solidity",
    description: "Vulnerable patterns outside the nine DASP classes (signatures, oracles, encoding, …).",
  },
];

/**
 * Detector id -> SmartBugs Curated (DASP) category. Total over every detector
 * the engine emits (`detect.ts` + `bytecode.ts`); `assertSmartbugsTotal()` (in
 * the fallback test) checks this against the template index.
 */
export const SMARTBUGS_BY_DETECTOR: Record<string, SmartBugsCategory> = {
  // reentrancy
  reentrancy: "reentrancy",
  "read-only-reentrancy": "reentrancy",
  "bytecode-reentrancy-shape": "reentrancy",
  // access_control
  "tx-origin": "access_control",
  "bytecode-origin": "access_control",
  "unprotected-admin": "access_control",
  "unprotected-ether": "access_control",
  "unprotected-initializer": "access_control",
  "default-visibility": "access_control",
  delegatecall: "access_control",
  "bytecode-delegatecall": "access_control",
  "bytecode-callcode": "access_control",
  "bytecode-proxy": "access_control",
  "assembly-sstore": "access_control",
  "assembly-param-sstore": "access_control",
  extcodesize: "access_control",
  centralization: "access_control",
  // SWC-105: a token-moving function with no access check (remediation is
  // onlyOwner; template 46's header is "has no access check"). No low-level
  // call is involved — transfer/safeTransfer are high-level ERC-20 calls —
  // so this is access_control, not unchecked_low_level_calls.
  "token-drain": "access_control",
  "rtl-override": "access_control",
  // arithmetic
  "unchecked-block": "arithmetic",
  "div-before-mul": "arithmetic",
  // unchecked_low_level_calls
  "unchecked-call": "unchecked_low_level_calls",
  "bytecode-unchecked-call": "unchecked_low_level_calls",
  "erc20-unchecked": "unchecked_low_level_calls",
  selfdestruct: "unchecked_low_level_calls",
  "bytecode-selfdestruct": "unchecked_low_level_calls",
  // denial_of_service
  "strict-balance": "denial_of_service",
  // 2026-10-27: the benchmark measured these two as presence findings with no
  // signal — eth-gas-stipend fired on 146 of 143 contracts (0.06), locked-ether
  // on 41 (0.00). Neither is a denial of service: nothing is overwhelmed, and
  // the 2300-gas stipend is a constraint on the CALLEE. They stay findings (both
  // are real observations) but they no longer vote for denial_of_service in the
  // dataset scoring, which is what made that column meaningless (precision 0.029).
  "eth-gas-stipend": "other",
  "hardcoded-gas": "denial_of_service",
  "gas-estimator-dos": "denial_of_service",
  "locked-ether": "other",
  "zero-address": "denial_of_service",
  // bad_randomness
  "weak-randomness": "bad_randomness",
  // time_manipulation
  timestamp: "time_manipulation",
  "bytecode-timestamp": "time_manipulation",
  // front_running
  slippage: "front_running",
  "zero-slippage-swap": "front_running",
  "front-running": "front_running",
  // short_addresses
  "short-address": "short_addresses",
  // other
  "balance-as-price": "other",
  "oracle-spot": "other",
  "encode-packed": "other",
  "signature-replay": "other",
  "signature-malleability": "other",
  "private-secret": "other",
  "fee-on-transfer": "other",
  "storage-gap": "other",
  "external-contract-referencing": "other",
  // A name-resolution bug (the write lands in the shadow variable), not a
  // modifier/tx.origin failure — template 33's own index label is "other".
  shadowing: "other",
  // The same msg.value credited per loop iteration (value extraction),
  // not computation exhaustion — template 22's own index label is "other".
  "msg-value-loop": "other",
  // Analyzer meta-findings (engine.ts `parse`, detect.ts `report-cap`):
  // not vulnerabilities at all; "other" keeps the map total over every
  // emitted detector instead of silently defaulting in prompts.
  parse: "other",
  "report-cap": "other",
  // 2026 incident classes (2026-10-27). All five caller-identity rules are
  // access-control failures in the SmartBugs sense ("failure to use function
  // modifiers"): the entry point exists, it just never checks who is calling.
  // The batch executor is the one whose mechanism is a low-level call, so it
  // joins unchecked_low_level_calls alongside unchecked-call.
  "hook-callback-auth": "access_control",
  "calldata-offset-auth": "access_control",
  "eoa-only-guard": "access_control",
  "public-key-account-trust": "access_control",
  "self-attested-auth": "access_control",
  "unauthenticated-batch-call": "unchecked_low_level_calls",
  // Deferred classes, implemented 2026-10-27. The first and last are
  // accounting/authorisation defects (access_control in the DASP sense: the
  // contract fails to enforce who may do what to whose funds); the middle two
  // are value-flow and arithmetic-in-time.
  "share-accounting-double-debit": "access_control",
  "shared-unlock-delta-netting": "unchecked_low_level_calls",
  "idle-gap-interest-accrual": "arithmetic",
  "signature-field-omission": "access_control",
  // D2 / D3 (2026-10-27, the games work). Neither is an access-control or
  // arithmetic failure: settlement optionality is an economic logic flaw
  // (the loss is free), and registry-dispatched logic is an analysis
  // requirement (the win rule lives in a sub-contract). SmartBugs Curated has
  // no category for either, so both join "other" — same treatment as
  // msg-value-loop and shadowing, whose own index labels also say "other".
  "settlement-optionality": "other",
  "registry-dispatched-logic": "other",
  // 2021-2025 incident classes (2026-10-27, the six-year sweep). The four
  // caller-identity mechanisms are access-control failures in the SmartBugs
  // sense (the entry point exists and never establishes who may use it);
  // oracle staleness is price plumbing, which the dataset has no category
  // for, so it joins "other".
  "arbitrary-dispatch-call": "access_control",
  "bridge-message-auth": "access_control",
  "governance-live-voting-power": "access_control",
  "ecrecover-zero": "access_control",
  "oracle-staleness": "other",
  "bytecode-create2": "other",
  "bytecode-metadata": "other",
  "missing-event": "other",
  "floating-pragma": "other",
  "old-compiler": "other",
};

/** Category for a detector; "other" when the detector is unknown. */
export function smartbugsCategoryForDetector(detector: string): SmartBugsCategory {
  return SMARTBUGS_BY_DETECTOR[detector] ?? "other";
}

/** Every detector mapped to a category. */
export function detectorsForSmartbugsCategory(category: SmartBugsCategory): string[] {
  return Object.keys(SMARTBUGS_BY_DETECTOR).filter(
    (d) => SMARTBUGS_BY_DETECTOR[d] === category,
  );
}

export function smartbugsCategoryMeta(category: SmartBugsCategory): SmartBugsCategoryMeta {
  return SMARTBUGS_CATEGORIES.find((c) => c.id === category) ?? SMARTBUGS_CATEGORIES[SMARTBUGS_CATEGORIES.length - 1];
}
