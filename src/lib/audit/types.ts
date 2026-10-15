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
};

export type SelectorHit = {
  selector: string;
  signature: string | null;
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
  opcodes: { name: string; count: number }[];
  signals: { name: string; count: number }[];
  bytecodeBytes: number | null;
  basicBlocks: number | null;
  proxy: string | null;
  notes: string[];
  disassembly: string;
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
};

export type AstNode = {
  type: string;
  name?: string | null;
  loc?: { start: { line: number } };
  range?: [number, number];
  [key: string]: unknown;
};
