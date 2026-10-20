export type Severity = "critical" | "high" | "medium" | "low" | "info";

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
  pocStatus?: string | null;
  pocOutput?: string | null;
  pocDurationMs?: number | null;
  pocRunAt?: string | null;
  pocCode?: string | null;
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
  inputKind: "source" | "bytecode";
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
};

export type Report = {
  label: string;
  inputKind: "source" | "bytecode";
  riskScore: number;
  summary: string;
  inventory: Inventory;
  findings: Finding[];
  aiNarrative: string | null;
  aiStatus: "ok" | "unavailable" | "error";
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
export type PocStatus = "passed" | "failed" | "error" | "backend_unreachable" | "skipped";

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
};

