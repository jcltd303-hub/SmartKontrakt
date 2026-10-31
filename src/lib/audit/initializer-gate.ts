/**
 * Live-state gate for unprotected-initializer findings (Fix 37).
 *
 * Why this exists — the 2026-10-25 fork proof
 * (~/workspace/smartkontrakt-fix/initializer-proof/RESULTS.md): all 15
 * stored CRITICAL unprotected-initializer findings were executed
 * against a mainnet fork from a fresh attacker address, and all 15
 * were false positives, in four classes:
 *
 *  (A) already-initialized guard reverts (7) — Aave v1 proxies,
 *      ERC1967 clones, LockToken, VisionToken, a Uniswap V3 pool;
 *  (B) access-control reverts (3) — Manifold BurnRedeem's admin
 *      validation, KailuaTreasury's creator guard (that template is
 *      genuinely never initialized — createdAt() is 0 — but no
 *      arbitrary caller can initialize it), Fuse CEtherDelegator's
 *      "only Fuse admin";
 *  (C) no such entry point on the deployed contract (4) — an internal
 *      library function in Settler's flattened source, a sibling
 *      contract's initialize (Party) attributed to TokenDistributor
 *      records, a contract with no initializer at all;
 *  (D) category errors (2) — Uniswap v4 PoolManager and V3 pool
 *      per-pool initializers. PoolManager's initialize SUCCEEDS: it is
 *      permissionless pool creation, by design, and owner() never
 *      moves.
 *
 * Detector-side, detect.ts now (a) restricts candidates to externally
 * reachable functions of an actual contract (kills Settler's class-C
 * shape at the source) and (b) caps the finding at high with the gate
 * note. This module is the address-path counterpart: the only route
 * back to critical, and it runs on LIVE evidence only.
 *
 * Provenance (class C, address path): when the gathered ABI is the
 * deployed contract's own (Sourcify/Etherscan — never the heuristic
 * reconstruction), a flagged function the ABI does not expose is
 * dropped outright: it belongs to another contract in the compilation.
 *
 * Positive evidence — any ONE of these, with no contradicting
 * initialized evidence, restores critical and marks the finding
 * corroborated (persisted via findings.corroborated, migration 0016):
 *  (a) an initialized-state read shows UNINITIALIZED: a contract's own
 *      `initialized()` / `isInitialized()` marker getter reads false,
 *      or the applicable Initializable storage slot (legacy slot 0
 *      packing for OZ ≤ v4 / ZOS; the ERC-7201 namespaced slot for
 *      OZ v5) decodes _initialized == 0;
 *  (b) a simulated eth_call of the initializer from a fresh address
 *      SUCCEEDS and the initializer's own source (transitively, its
 *      internal callees) writes a privileged state variable
 *      (owner/admin/oracle/… — detect.ts's PRIVILEGED family).
 *
 * Class (D) is why (b) is worded that way: mere call success is NOT
 * evidence. Neither PoolManager nor a V3 pool exposes Initializable
 * state or a marker getter, and their initializers write pool state,
 * not privileged state — a successful simulation changes nothing.
 *
 * Contradicting evidence — a marker getter reading true, an
 * Initializable slot decoding initialized, or a simulated call
 * reverting with an already-initialized reason — vetoes the upgrade
 * outright: the deployed contract is initialized, whatever the source
 * pattern suggested. Any other revert (access control, class B)
 * likewise leaves the finding capped: an arbitrary caller cannot run
 * the initializer, which is the claim the critical would have made.
 *
 * Fail-soft, fail-CLOSED: RPC failure, unparseable evidence, or a
 * probe deadline leaves the finding exactly as the detector stamped
 * it — capped at high, uncorroborated, with a note saying the probe
 * produced no decisive evidence. Nothing here ever throws.
 */
import { keccak256 } from "js-sha3";

import { PRIVILEGED } from "./detect.ts";
import { parseSource, type ContractModel, type FnModel } from "./model.ts";
import { riskScore } from "./risk.ts";
import { executeEthCallFrom, executeStorageRead } from "./simulator.ts";
import type { AbiItem, Finding, Report } from "./types.ts";

/**
 * The simulated caller: the fork-proof harness's fresh attacker
 * (initializer-proof/RESULTS.md). eth_call needs no key — this is only
 * the msg.sender a guard would see.
 */
export const PROBE_CALLER = "0x9D3170e23559aa2d4eF465CF8F344C3fD746C790";

/** Overall probe deadline; partial evidence is used, never a stall. */
export const INITIALIZER_GATE_DEADLINE_MS = 10_000;

/** Legacy Initializable state (OZ ≤ v4, ZOS): slot 0. */
export const LEGACY_INITIALIZABLE_SLOT = "0x" + "0".repeat(64);

/**
 * ERC-7201 namespaced Initializable slot (OpenZeppelin v5):
 * keccak256(abi.encode(uint256(keccak256("openzeppelin.storage.Initializable")) - 1)) & ~0xff
 * = 0xf0c57e16840df040f15088dc2f81fe391c3923bec73e23a9662efc9c229c6a00.
 */
export const ERC7201_INITIALIZABLE_SLOT = erc7201Slot("openzeppelin.storage.Initializable");

function erc7201Slot(namespace: string): string {
  const inner = BigInt("0x" + keccak256(namespace));
  const preImage = (inner - 1n).toString(16).padStart(64, "0");
  const bytes: number[] = [];
  for (let i = 0; i < preImage.length; i += 2) {
    bytes.push(parseInt(preImage.slice(i, i + 2), 16));
  }
  const hashed = BigInt("0x" + keccak256(bytes as unknown as string));
  return "0x" + (hashed & ~0xffn).toString(16).padStart(64, "0");
}

export type InitializerCallFn = (
  address: string,
  calldata: string,
  chainId: string,
  from: string,
) => Promise<{ success: boolean; result?: string; error?: string; errorData?: string }>;

export type InitializerStorageFn = (
  address: string,
  slot: string,
  chainId: string,
) => Promise<{ success: boolean; result?: string; error?: string }>;

export type InitializerGateOpts = {
  /** Injectable eth_call (tests); defaults to simulator's executeEthCallFrom. */
  callFn?: InitializerCallFn;
  /** Injectable storage read (tests); defaults to simulator's executeStorageRead. */
  storageFn?: InitializerStorageFn;
  /** Overall deadline; defaults to INITIALIZER_GATE_DEADLINE_MS. */
  deadlineMs?: number;
  /**
   * Runtime-code reader. Returns the hex code, or null when it could not be read.
   *
   * Without this the gate has no way to tell "the initializer call succeeded" from
   * "there is nothing at this address to revert": eth_call to a codeless address
   * returns SUCCESS with empty data, so `sim.succeeded` becomes true and a critical is
   * restored on evidence that proves nothing. Measured 2026-10-29 on a finding where
   * the target was reported as holding 258 ETH and 0xa7d9e842 returned no code to a
   * direct eth_getCode.
   */
  codeFn?: (address: string, chainId: string) => Promise<string | null>;
};

export type InitializerGateOutcome = {
  /** True when at least one finding reached the live probe. */
  probed: boolean;
  /** Findings restored to critical + corroborated on live evidence. */
  upgraded: number;
  /** Findings dropped by the ABI membership check. */
  dropped: number;
  /**
   * keccak256 of the runtime code the probes ran against, when codeFn was supplied.
   * Recorded so a saved record can say WHICH code its evidence describes — without it a
   * corroborated critical is unbound and cannot be re-checked after an upgrade.
   */
  codeHash: string | null;
  /**
   * True when the runtime code changed between the start and the end of the probe. Every
   * corroboration made in that window is withdrawn, because the answers describe a
   * contract that is no longer deployed.
   */
  codeChanged: boolean;
};

const word = (v: bigint): string => v.toString(16).padStart(64, "0");

/**
 * Minimal ABI encoder for simulated initializer calls. Dummy arguments
 * are inert by construction: addresses get the probe caller (never the
 * zero address — initialize(address(0))-style requires must not be
 * what makes the call fail), every other scalar gets zero, strings and
 * bytes get the empty value. Tuples, arrays and structs return null:
 * the simulation is skipped for that overload. (PoolManager's
 * initialize takes a PoolKey tuple — and its success would prove
 * nothing anyway; see the header.)
 */
export function encodeInitializerCalldata(name: string, inputTypes: string[]): string | null {
  const types: string[] = [];
  const heads: string[] = [];
  const tails: string[] = [];
  let tailBytes = 0;
  for (const raw of inputTypes) {
    const t = raw.trim();
    if (!t || t.includes("(") || t.includes("[") || t === "tuple") return null;
    types.push(t);
    if (t === "address") {
      heads.push("0".repeat(24) + PROBE_CALLER.slice(2).toLowerCase());
    } else if (t === "bool" || /^u?int\d*$/.test(t)) {
      heads.push(word(0n));
    } else if (/^bytes([1-9]|[12][0-9]|3[0-2])$/.test(t)) {
      heads.push("0".repeat(64));
    } else if (t === "string" || t === "bytes") {
      heads.push(word(BigInt(inputTypes.length * 32 + tailBytes)));
      tails.push(word(0n)); // zero length
      tailBytes += 32;
    } else {
      return null;
    }
  }
  const selector = keccak256(`${name}(${types.join(",")})`).slice(0, 8);
  return "0x" + selector + heads.join("") + tails.join("");
}

export type InitializablePattern = {
  /** ERC-7201 namespaced storage (OZ v5): only the 7201 slot is authoritative. */
  erc7201: boolean;
  /** Legacy packed Initializable state (OZ ≤ v4 / ZOS): slot 0 is authoritative. */
  legacy: boolean;
  /** No-arg bool getters reporting initialized state (marker evidence). */
  markerGetters: string[];
};

/**
 * Which live initialized-state evidence a contract can offer, from its
 * source and gathered ABI. A contract with no Initializable pattern and
 * no marker getter (PoolManager, V3 pools, Kailua) can only be judged
 * by the simulation — which is exactly what keeps class (D) capped.
 */
export function detectInitializablePattern(
  source: string,
  abi?: AbiItem[] | null,
): InitializablePattern {
  const erc7201 = source.includes("openzeppelin.storage.Initializable");
  const legacy = !erc7201 && /\bInitializable\b/.test(source);
  const markers = new Set<string>();
  for (const item of abi ?? []) {
    if (!item || item.type !== "function" || !item.name) continue;
    if (!/^(initialized|isInitialized)$/.test(item.name)) continue;
    if ((item.inputs?.length ?? 0) !== 0) continue;
    const outputs = item.outputs ?? [];
    if (outputs.length !== 1 || outputs[0]!.type !== "bool") continue;
    markers.add(item.name);
  }
  // A public bool state variable generates the same getter.
  for (const m of source.matchAll(/\bbool\s+public\s+(initialized|isInitialized)\b/g)) {
    markers.add(m[1]!);
  }
  return { erc7201, legacy, markerGetters: [...markers] };
}

/**
 * Decode an Initializable state slot. Legacy packing (OZ ≤ v4 / ZOS):
 * `_initialized` (bool, later uint8) sits at byte 0 of slot 0. ERC-7201
 * (OZ v5): the Initializable struct packs `uint64 _initialized` at
 * offset 0 of the namespaced slot (type(uint64).max there means
 * _disableInitializers ran — that is initialized, permanently).
 * Returns null on an unreadable word.
 */
export function decodeInitializableSlot(
  raw: string,
  erc7201: boolean,
): "initialized" | "uninitialized" | null {
  const clean = raw.replace(/^0x/, "");
  if (!/^[0-9a-fA-F]{64,}$/.test(clean)) return null;
  let value: bigint;
  try {
    value = BigInt("0x" + clean.slice(0, 64));
  } catch {
    return null;
  }
  if (erc7201) {
    return (value & 0xffffffffffffffffn) === 0n ? "uninitialized" : "initialized";
  }
  return (value & 0xffn) === 0n ? "uninitialized" : "initialized";
}

/** Decode an Error(string) revert reason from raw revert data, if present. */
export function decodeRevertReason(errorData?: string | null, error?: string | null): string {
  if (errorData && errorData.startsWith("0x08c379a0") && errorData.length >= 138) {
    try {
      const len = Number(BigInt("0x" + errorData.slice(74, 138)));
      if (len > 0 && len <= 4096 && errorData.length >= 138 + len * 2) {
        const bytes: number[] = [];
        for (let i = 0; i < len; i++) {
          bytes.push(parseInt(errorData.slice(138 + i * 2, 140 + i * 2), 16));
        }
        const text = new TextDecoder().decode(new Uint8Array(bytes)).trim();
        if (text) return text;
      }
    } catch {
      // fall through to the node's error string
    }
  }
  return (error ?? "").trim();
}

const INITIALIZED_FLAVOR = /already initialized|already been initialized/i;

/**
 * Does this function's source — transitively through the internal
 * functions it calls in the same contract — assign a privileged state
 * variable (detect.ts's PRIVILEGED family)? The control-move half of
 * evidence rule (b): a simulated call that succeeds AND lands here is
 * a setup path an attacker can actually run.
 */
function initializerWritesPrivileged(contract: ContractModel, fn: FnModel): boolean {
  const byName = new Map(contract.functions.map((f) => [f.name, f]));
  const seen = new Set<string>([fn.name]);
  const queue = [fn.name];
  const parts = [fn.source];
  while (queue.length) {
    const cur = byName.get(queue.shift()!);
    if (!cur) continue;
    for (const m of cur.source.matchAll(/\b([A-Za-z_]\w*)\s*\(/g)) {
      const callee = byName.get(m[1]!);
      if (callee && !seen.has(callee.name)) {
        seen.add(callee.name);
        queue.push(callee.name);
        parts.push(callee.source);
      }
    }
  }
  const text = parts.join("\n");
  for (const m of text.matchAll(/\b([A-Za-z_]\w*)\s*(?:[-+*/%&|^]?=|<<=|>>=)(?!=)/g)) {
    if (PRIVILEGED.test(m[1]!)) return true;
  }
  return false;
}

type SimOutcome = {
  attempted: boolean;
  succeeded: boolean;
  /** The chain answered and the call reverted (a transport failure —
   *  RPC down, timeout — is NOT a revert and never lands here). */
  reverted: boolean;
  /** Decoded revert reasons of the failed attempts. */
  revertReasons: string[];
};

type ProbeEvidence = {
  /** Probe jobs launched (markers, slot reads, simulations). Zero
   *  means the contract offered nothing to probe — inconclusive,
   *  not "unavailable". */
  attempted: number;
  /** True when at least one probe got a transport-level answer. */
  rpcAnswered: boolean;
  /** Marker getter results by name (null = unreadable). */
  markers: Map<string, boolean | null>;
  /** Authoritative Initializable slot state, when a pattern applied and read. */
  slotState: "initialized" | "uninitialized" | null;
  slotKind: "erc7201" | "legacy" | null;
  /** Simulation outcomes by flagged function name. */
  sims: Map<string, SimOutcome>;
};

/**
 * Apply the gate to a report's unprotected-initializer findings.
 * Mutates the report in place (findings, inventory notes, riskScore)
 * and returns what it did. NEVER throws.
 */
export async function applyInitializerGate(
  report: Report,
  ctx: { address: string; chainId: string; source: string },
  opts?: InitializerGateOpts,
): Promise<InitializerGateOutcome> {
  const outcome: InitializerGateOutcome = {
    probed: false, upgraded: 0, dropped: 0, codeHash: null, codeChanged: false,
  };
  /** Findings this call corroborated, so a mid-probe upgrade can withdraw them. */
  const corroboratedHere: Finding[] = [];
  try {
    const targets = report.findings.filter(
      (f) => f.detector === "unprotected-initializer" && f.severity === "high" && !!f.locationFn,
    );
    if (targets.length === 0) return outcome;

    // --- Provenance: the deployed ABI membership check (class C). ---
    // Only a real gathered ABI counts — Sourcify/Etherscan describe the
    // contract AT this address; the heuristic reconstruction is built
    // from observed selectors and proves nothing by absence.
    const abi = report.inventory.abi ?? null;
    const abiSource = report.inventory.abiSource ?? null;
    let survivors = targets;
    if ((abiSource === "sourcify" || abiSource === "etherscan") && abi && abi.length > 0) {
      const deployedFns = new Set(
        abi.filter((i) => i?.type === "function" && i.name).map((i) => i.name!),
      );
      const droppedHere = targets.filter((f) => !deployedFns.has(f.locationFn!));
      if (droppedHere.length > 0) {
        const dropSet = new Set<Finding>(droppedHere);
        report.findings = report.findings.filter((f) => !dropSet.has(f));
        for (const f of droppedHere) {
          report.inventory.notes.push(
            `Initializer gate: dropped the '${f.locationFn}' unprotected-initializer flag — the deployed contract's ${abiSource} ABI has no such function. The flagged function belongs to another contract in the same compilation (fork-proof class C).`,
          );
        }
        outcome.dropped += droppedHere.length;
        survivors = targets.filter((f) => !dropSet.has(f));
      }
    }
    if (survivors.length === 0) {
      if (outcome.dropped > 0) report.riskScore = riskScore(report.findings);
      return outcome;
    }

    outcome.probed = true;
    const callFn = opts?.callFn ?? executeEthCallFrom;
    const storageFn = opts?.storageFn ?? executeStorageRead;
    const deadlineMs = opts?.deadlineMs ?? INITIALIZER_GATE_DEADLINE_MS;

    const model = parseSource(ctx.source);
    const pattern = detectInitializablePattern(ctx.source, abi);

    // Refuse to corroborate anything against an address that has no code.
    //
    // eth_call to a codeless address SUCCEEDS with empty return data, which the probe
    // reads as "the initializer call went through". That is the single easiest way to
    // manufacture a corroborated critical, and it happens whenever the address is an
    // EOA, a selfdestructed contract, or a provider answers 0x.
    //
    // Unknown (null) does NOT block: a failed code read must not silently suppress real
    // findings, so this fails open and says so in the note.
    let targetHasNoCode = false;
    /** Runtime code, lowercased without 0x — used for selector presence. */
    let targetCode: string | null = null;
    if (opts?.codeFn) {
      try {
        const code = await opts.codeFn(ctx.address, ctx.chainId);
        if (code !== null) {
          targetCode = code.toLowerCase().replace(/^0x/, "");
          if (targetCode === "" || /^0*$/.test(targetCode)) targetHasNoCode = true;
          else outcome.codeHash = keccak256(targetCode);
        }
      } catch {
        // leave both unset
      }
    }

    /**
     * Does the deployed code actually DISPATCH this selector?
     *
     * A contract with a payable fallback returns SUCCESS for any selector it does not
     * implement. Measured 2026-10-29 on BondedECDSAKeepFactory (0xa7d9e842): its
     * dispatcher default is `fallback() { slot5 += msg.value; }`, so an eth_call carrying
     * `initialize(address,address[],uint256,uint256,uint256,address,address,address)`
     * — 0x79a80491, a selector the factory never implements, only CALLS on the keep it
     * deploys — accepted the call and reported success. That restored a critical and
     * marked it corroborated, on a function the contract does not have.
     *
     * The selector appears verbatim in the dispatcher as a PUSH4, so its absence from
     * the runtime code is proof the function does not exist. Absence is conclusive;
     * presence is not (it could be data), which is why this only ever SUPPRESSES.
     */
    const dispatchesSelector = (selector: string): boolean => {
      if (!targetCode) return true; // unknown code: fail open
      return targetCode.includes(selector);
    };

    // Candidate simulation signatures per flagged name: the deployed
    // ABI's overloads when an ABI exists (deployed truth), else the
    // parsed model's parameter types.
    const simSignatures = new Map<string, string[][]>();
    for (const f of survivors) {
      const name = f.locationFn!;
      const fromAbi = (abi ?? [])
        .filter((i) => i?.type === "function" && i.name === name)
        .map((i) => (i.inputs ?? []).map((input) => input.type ?? ""));
      const fromModel = model.contracts
        .flatMap((c) => c.functions)
        .filter((fn) => fn.name === name)
        .map((fn) => fn.params.map((p) => p.typeName));
      simSignatures.set(name, fromAbi.length > 0 ? fromAbi : fromModel);
    }

    const evidence: ProbeEvidence = {
      attempted: 0,
      rpcAnswered: false,
      markers: new Map(),
      slotState: null,
      slotKind: null,
      sims: new Map(),
    };

    const work = (async () => {
      const jobs: Promise<void>[] = [];

      for (const name of pattern.markerGetters) {
        evidence.attempted += 1;
        jobs.push(
          (async () => {
            try {
              const selector = "0x" + keccak256(`${name}()`).slice(0, 8);
              const call = await callFn(ctx.address, selector, ctx.chainId, PROBE_CALLER);
              if (call.success && call.result && call.result !== "0x") {
                evidence.rpcAnswered = true;
                try {
                  evidence.markers.set(name, BigInt(call.result) !== 0n);
                } catch {
                  evidence.markers.set(name, null);
                }
              } else {
                if (call.success) evidence.rpcAnswered = true;
                evidence.markers.set(name, null);
              }
            } catch {
              evidence.markers.set(name, null);
            }
          })(),
        );
      }

      const slot = pattern.erc7201
        ? ERC7201_INITIALIZABLE_SLOT
        : pattern.legacy
          ? LEGACY_INITIALIZABLE_SLOT
          : null;
      if (slot) {
        evidence.attempted += 1;
        jobs.push(
          (async () => {
            try {
              const read = await storageFn(ctx.address, slot, ctx.chainId);
              if (read.success && read.result) {
                evidence.rpcAnswered = true;
                evidence.slotState = decodeInitializableSlot(read.result, pattern.erc7201);
                evidence.slotKind = pattern.erc7201 ? "erc7201" : "legacy";
              }
            } catch {
              // slotState stays null — inconclusive, fail-closed
            }
          })(),
        );
      }

      for (const [name, overloads] of simSignatures) {
        const sim: SimOutcome = { attempted: false, succeeded: false, reverted: false, revertReasons: [] };
        evidence.sims.set(name, sim);
        const encoded = overloads
          .map((types) => ({
            types,
            data: encodeInitializerCalldata(name, types),
            selector: keccak256(`${name}(${types.join(",")})`).slice(0, 8),
          }))
          .filter((e) => e.data !== null);
        for (const { data, selector } of encoded) {
          evidence.attempted += 1;
          jobs.push(
            (async () => {
              sim.attempted = true;
              try {
                const call = await callFn(ctx.address, data!, ctx.chainId, PROBE_CALLER);
                if (call.success) {
                  evidence.rpcAnswered = true;
                  // A fallback makes every unknown selector "succeed". Only count it
                  // when the code actually dispatches that selector.
                  sim.succeeded = dispatchesSelector(selector);
                } else {
                  // A revert means the chain answered; a transport
                  // failure (RPC unreachable / timeout, no revert
                  // data) means it did not — conflating them would
                  // report "the call reverts" for a dead RPC.
                  const transport =
                    !call.errorData &&
                    !!call.error &&
                    /unreachable|timed out|timeout/i.test(call.error);
                  if (!transport) {
                    evidence.rpcAnswered = true;
                    sim.reverted = true;
                    const reason = decodeRevertReason(call.errorData, call.error);
                    if (reason) sim.revertReasons.push(reason);
                  }
                }
              } catch {
                // transport failure — rpcAnswered untouched
              }
            })(),
          );
        }
      }

      await Promise.allSettled(jobs);
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

    // --- Verdicts. ---
    const markerTrue = [...evidence.markers.values()].some((v) => v === true);
    const markerFalse = [...evidence.markers.entries()].filter(([, v]) => v === false);
    const slotInitialized = evidence.slotState === "initialized";
    const slotUninitialized = evidence.slotState === "uninitialized";

    for (const f of survivors) {
      const name = f.locationFn!;
      const sim = evidence.sims.get(name);
      const simRevertedInitialized =
        !!sim && sim.revertReasons.some((r) => INITIALIZED_FLAVOR.test(r));
      const initializedEvidence = markerTrue || slotInitialized || simRevertedInitialized;
      const stateUninitialized = markerFalse.length > 0 || slotUninitialized;

      const writesPrivileged = model.contracts.some((c) =>
        c.functions
          .filter((fn) => fn.name === name)
          .some((fn) => initializerWritesPrivileged(c, fn)),
      );

      // A target with no code can never produce positive live evidence: the call
      // "succeeded" because there was nothing there to revert. Keep the finding at its
      // capped severity and say why, rather than restoring a critical on nothing.
      const positive =
        !targetHasNoCode &&
        !initializedEvidence &&
        (stateUninitialized || (!!sim?.succeeded && writesPrivileged));

      if (positive) {
        const parts: string[] = [];
        for (const [markerName] of markerFalse) {
          parts.push(`${markerName}() reads false`);
        }
        if (slotUninitialized) {
          parts.push(
            evidence.slotKind === "erc7201"
              ? "the ERC-7201 Initializable slot reads uninitialized"
              : "the Initializable storage slot (slot 0) reads uninitialized",
          );
        }
        if (sim?.succeeded && writesPrivileged && !stateUninitialized) {
          parts.push(
            `a simulated ${name}(…) call from a fresh address (${PROBE_CALLER.slice(0, 6)}…${PROBE_CALLER.slice(-4)}) succeeded and the initializer writes privileged state`,
          );
        } else if (sim?.succeeded && writesPrivileged) {
          parts.push("and a simulated call from a fresh address succeeds");
        }
        f.severity = "critical";
        f.corroborated = true;
        corroboratedHere.push(f);
        f.summary += `\n\n[Initializer gate: LIVE evidence — ${parts.join("; ")}. Critical restored; finding marked corroborated.]`;
        outcome.upgraded += 1;
        continue;
      }

      // Capped: the note records WHY, in the probe's own terms.
      if (initializedEvidence) {
        const detail = markerTrue
          ? "an initialized-state getter reads true"
          : slotInitialized
            ? "the Initializable storage slot reads initialized"
            : `a simulated call reverts "${sim!.revertReasons.find((r) => INITIALIZED_FLAVOR.test(r))}"`;
        f.summary += `\n\n[Initializer gate: live probe — ${detail}, so the deployed contract is already initialized; the source pattern does not apply to it. Kept at high, uncorroborated.]`;
      } else if (sim?.attempted && !sim.succeeded && sim.reverted) {
        const reason = sim.revertReasons[0];
        f.summary += `\n\n[Initializer gate: live probe — a simulated ${name}(…) call from a fresh address reverts${reason ? ` ("${reason}")` : ""}; an arbitrary caller cannot run it on the deployed contract. Kept at high, uncorroborated.]`;
      } else if (!evidence.rpcAnswered && evidence.attempted > 0) {
        f.summary += `\n\n[Initializer gate: live probe unavailable (no RPC answer) — live initialized state not confirmed. Kept at high, uncorroborated.]`;
      } else {
        f.summary += `\n\n[Initializer gate: live probe ran but produced no decisive evidence — no uninitialized state read, and no simulation that both succeeds and moves privileged state (a successful call alone is not evidence: per-pool initializers succeed by design). Kept at high, uncorroborated.]`;
      }
    }

    // --- Binding: the answers must describe the code that is still deployed. ---
    //
    // Every probe above reads a live contract. If the contract is upgraded mid-probe,
    // each answer describes code that no longer exists, and a corroborated critical is
    // then a claim about a contract nobody can find. Ported from the Perplexity incident
    // harness, which refuses any probe result whose runtimeSha256 does not match the one
    // it recorded. We can only compare start against end (the analysis has no stored
    // hash to match), which is enough to catch a change inside the probe window.
    if (opts?.codeFn && outcome.codeHash) {
      try {
        const after = await opts.codeFn(ctx.address, ctx.chainId);
        if (after !== null) {
          const afterHash = keccak256(after.toLowerCase().replace(/^0x/, ""));
          if (afterHash !== outcome.codeHash) {
            outcome.codeChanged = true;
            for (const f of corroboratedHere) {
              f.severity = "high";
              f.corroborated = false;
              f.summary +=
                "\n\n[Initializer gate: WITHDRAWN — the runtime code changed while the probe ran " +
                `(${outcome.codeHash.slice(0, 8)}… -> ${afterHash.slice(0, 8)}…). The evidence ` +
                "describes a contract that is no longer deployed. Kept at high, uncorroborated.]";
            }
            outcome.upgraded = 0;
          }
        }
      } catch {
        // Unreadable second read: keep the corroboration, but the record carries the
        // start hash so a later re-check can tell whether the code moved.
      }
    }

    if (outcome.upgraded > 0) {
      report.riskScore = riskScore(report.findings);
    }
    return outcome;
  } catch {
    // Fail-closed by construction: the detector's capped severity and
    // absent corroboration are already the safe state.
    return outcome;
  }
}
