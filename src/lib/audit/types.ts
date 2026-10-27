import type { AddressValue } from "./value.ts";
import type { LiveStateReport } from "./live-state.ts";
import type { PocProvenance } from "./poc-outcome.ts";
import type { FpMatch } from "./fp-signatures.ts";
import type { ResnetResult } from "./resnet-result.ts";
import type { ReachabilityClass } from "./reachability.ts";

export type Severity = "critical" | "high" | "medium" | "low" | "info";

/**
 * One ABI entry, as returned by Sourcify/Etherscan or rebuilt heuristically.
 * Defined here (not in abi.ts) so the ABI can live on the persisted Inventory
 * without a circular type import.
 */
export type AbiItem = {
  type?: string;
  name?: string;
  inputs?: Array<{ name?: string; type?: string; components?: AbiItem[] }>;
  outputs?: Array<{ name?: string; type?: string; components?: AbiItem[] }>;
  stateMutability?: string;
};

export type Confidence = "high" | "medium" | "low";

export type Finding = {
  id: string;
  severity: Severity;
  swc: string | null;
  title: string;
  confidence: Confidence;
  detector: string;
  summary: string;
  walkthrough: string;
  exploitSolidity: string;
  remediationSolidity: string;
  locationFn: string | null;
  locationLine: number | null;
  snippet: string;
  /** Corroboration marker for presence-only findings (G3): true (or a
   *  non-empty note) when evidence beyond opcode presence ties the
   *  flagged construct to a concrete source-level call site — the state
   *  hasVulnCorroboration (adjudication.ts) promotes the finding with.
   *  Persisted as findings.corroborated (migration 0016); absent/null
   *  on records analyzed before the marker existed. */
  corroborated?: boolean | string | null;
  pocStatus?: string | null;
  pocOutput?: string | null;
  pocDurationMs?: number | null;
  pocRunAt?: string | null;
  pocCode?: string | null;
  /** PoC provenance (G8): where the executed code came from (library
   *  template vs generated) and the verdict it produced, in
   *  poc-outcome.ts's vocabulary. Derived at read time by
   *  findingPocProvenance (poc-outcome.ts) for every stored row — old
   *  rows included — and attached by the archive loaders; absent/null
   *  when the finding has never been run. */
  pocEvidence?: PocProvenance | null;
  /** FP-pattern annotation (G7): set when this finding's shape matches
   *  a CONFIRMED fp_signatures pattern (fp-signatures.ts) — a pattern
   *  derived from findings a human disposed as false_positive.
   *  ANNOTATION ONLY: it never suppresses the finding, changes its
   *  severity, or affects PoC eligibility; it exists so triage can see
   *  "this shape was judged an FP before" at a glance. Derived at read
   *  time by the archive loaders; absent/null when no confirmed
   *  pattern matches (candidate and dismissed patterns never annotate). */
  fpMatch?: FpMatch | null;
  /** Reachability class (Phase 4, 2026-10-27 detection upgrade): the answer
   *  to "who can reach this site?", from reachability.ts. Tagged by
   *  detectSource for findings whose function the model resolves; absent on
   *  internal/private helper sites (attributed to their public entries) and
   *  on records analysed before the tag existed. Additive: it never changes
   *  a severity and never drops a finding — REACHABLE is the class triage
   *  should read first, and the only one that becomes a reported finding. */
  reachability?: ReachabilityClass | null;
};

export type SelectorHit = {
  selector: string;
  signature: string | null;
  /** All known signatures for this selector (collisions), first == signature. */
  signatures?: string[];
};

export type FnSurface = {
  name: string;
  visibility: string;
  mutability: string;
  modifiers: string[];
  line: number | null;
  params: string;
};

export type VarSurface = {
  name: string;
  typeName: string;
  visibility: string;
  line: number | null;
  constOrImmutable: boolean;
};

export type TopicHit = {
  /** '0x' + 64 hex — the keccak256 of the event signature. */
  topic: string;
  /** e.g. 'Transfer(address,address,uint256)'. Null when unresolved. */
  signature: string | null;
};

export type Inventory = {
  /** Missing/error evidence remains distinct from a quiet model. */
  resnetStatus?: {status:"ok"|"error"|"unavailable";error?:string};
  inputKind: "source" | "bytecode";
  /** The compiler-verified contract name (C3, 2026-10-27 detection
   *  upgrade): set from the registry that returned source, null when the
   *  audit is bytecode-only. The UI must show this next to, not instead
   *  of, any product/dashboard label. */
  verifiedName?: string | null;
  /** "label_ok" | "label_mismatch: …" | "label_unverified" — whether the
   *  display label agrees with the verified name. Nine of the
   *  engagement's 32 dashboard labels were provably wrong, so the
   *  disagreement is surfaced rather than resolved silently. */
  labelCheck?: string | null;
  contractNames: string[];
  kindNote: string;
  pragma: string | null;
  compiler: string | null;
  functions: FnSurface[];
  stateVars: VarSurface[];
  events: string[];
  inheritance: string[];
  selectors: SelectorHit[];
  reconstructed: string;
  /** Resolved event topics (PUSH32 candidates matched against the
   * fourbyte_event_signatures table). analyzeBytecode fills every
   * PUSH32 candidate with signature null; enrichment fills the known
   * ones. Absent on records analyzed before fourbyte enrichment existed. */
  topics?: TopicHit[];
  opcodes: { name: string; count: number }[];
  signals: { name: string; count: number }[];
  bytecodeBytes: number | null;
  basicBlocks: number | null;
  proxy: string | null;
  notes: string[];
  disassembly: string;
  /**
   * Native-coin balance (wei, decimal string) of the target at analysis time,
   * read over public JSON-RPC. Null/absent when not read (no RPC answer).
   * Distinct from zero: `"0"` is a confirmed empty balance.
   */
  balanceWei?: string | null;
  /** Native symbol for the chain (ETH / POL / BNB), for display. */
  balanceSymbol?: string | null;
  /**
   * Total USD value of the target at analysis time (native + ERC-20 holdings),
   * from the value layer. Null when not valued; the record's `value_usd` column
   * mirrors this for sorting.
   */
  valueUsd?: number | null;
  /** Full valuation (holdings, prices, sources, completeness). */
  value?: AddressValue | null;
  /**
   * The target's ABI when one was gathered (Sourcify / Etherscan / inferred
   * from selectors + events), stored so a later PoC run in ANY context can
   * tailor its template to the real surface without re-fetching.
   */
  abi?: AbiItem[] | null;
  /** Where the ABI came from: "sourcify" | "etherscan" | "heuristic" | "input". */
  abiSource?: string | null;
  /**
   * Live decisive-state reads (paused / owner / trading flags / fees /
   * limits — live-state.ts), probed over public RPC at analysis time.
   * Attached only for verified-source analyses with at least one high
   * or critical finding: adjudication evidence to check source-argued
   * closures (constructor defaults, initial values) against LIVE
   * values. Persists via inventory_json like balance/value/abi.
   * Null/absent when not probed or no decisive getters exist.
   */
  liveState?: LiveStateReport | null;
};

export type Report = {
  /** Ephemeral on-chain runtime bound to fetched source for Image ML.
   * Outside inventory: archive writers intentionally do not persist it. */
  runtimeBytecode?: { code: string; sourceHash: string };
  label: string;
  inputKind: "source" | "bytecode";
  riskScore: number;
  summary: string;
  inventory: Inventory;
  findings: Finding[];
  aiNarrative: string | null;
  aiStatus: "ok" | "unavailable" | "error";
  /**
   * ResNet1D bytecode screening (resnet-result.ts), attached during the
   * audit — by analyzeAddress when the caller injects a runner (the
   * pipeline worker's Node runner; the browser worker for app flows) or
   * by runAndStore for pasted-bytecode saves. Unlike runtimeBytecode this
   * DOES persist (contract_scans.resnet_json, migration 0018) — it is a
   * small JSON verdict, and the report's riskScore already includes its
   * bounded bonus. Null/absent = not run (no runtime bytecode available,
   * or the model was unavailable in that environment — always fail-soft).
   */
  resnet?: ResnetResult | null;
  /** The contract the analysis actually scoped to (Item 2 selection:
   * onlyContract / deployed-name match / unique most-derived contract),
   * or null when every contract in the file was analyzed. In-memory
   * only — not persisted; the saved contract_name comes from
   * resolveContractDisplayName (probes first). */
  mainContract?: string | null;
  /** True when the input did not parse AND the only findings are the
   * parse-failure INFO (or there are no findings). Such a record
   * analyzed NOTHING and must render "Unparsed", never "Clean".
   * Set by engine.analyzeInput; loadScan/listScanSummaries derive the
   * same state from findings rows for records saved before this field. */
  unparsed?: boolean;
};

export type AstNode = {
  type: string;
  name?: string | null;
  loc?: { start: { line: number } };
  range?: [number, number];
  [key: string]: unknown;
};

/** Outcome of one Foundry fork-PoC run against the Termux local backend. */
export type PocStatus = "passed" | "failed" | "error" | "backend_unreachable" | "skipped" | "no_tests";

export type PocResult = {
  executedSource?: string;
  evidence?: { engine: "foundry"; startedAt: string; finishedAt: string; target: string; chainId: string; sourceHash: string; backendUrl: string; rpcUrls: string[]; testCount: number };
  status: PocStatus;
  /** Forge output (tail-capped) or a short explanation for non-run statuses. */
  logs: string;
  durationMs: number;
  /** ISO timestamp of when the run finished (or was attempted). */
  runAt: string;
  /** Backend-side error message, when status is "error". */
  error?: string;
  /** Total USD value of the target at the pre-run check (migration 0012). */
  valueUsd?: number | null;
};

