import { analyzeBytecode, looksLikeBytecode } from "./bytecode.ts";
import { detectSource } from "./detect.ts";
import { parseSource, type SourceModel } from "./model.ts";
import { calibrateFindings } from "./severity-calibration.ts";
import type { Finding, Inventory, Report, Severity } from "./types.ts";

const WEIGHT: Record<Severity, number> = {
  critical: 28,
  high: 14,
  medium: 6,
  low: 2,
  info: 0,
};

function scoreOf(findings: Finding[]): number {
  const raw = findings.reduce((sum, f) => sum + WEIGHT[f.severity], 0);
  return Math.min(100, raw);
}

function summarize(findings: Finding[], name: string): string {
  if (findings.length === 0) {
    return `${name} produced no rule hits. That is not a clean bill of health — it means none of the detectors matched. Read the surface map before you trust it.`;
  }
  const crit = findings.filter((f) => f.severity === "critical").length;
  const high = findings.filter((f) => f.severity === "high").length;
  const top = findings[0];
  return `${name}: ${findings.length} finding${findings.length === 1 ? "" : "s"}, ${crit} critical, ${high} high. Lead issue: ${top?.title ?? "—"}.`;
}

function emptyInventory(kind: "source" | "bytecode", note: string): Inventory {
  return {
    inputKind: kind,
    contractNames: [],
    kindNote: note,
    pragma: null,
    compiler: null,
    functions: [],
    stateVars: [],
    events: [],
    inheritance: [],
    selectors: [],
    reconstructed: "",
    opcodes: [],
    signals: [],
    bytecodeBytes: null,
    basicBlocks: null,
    proxy: null,
    notes: [note],
    disassembly: "",
  };
}

export type AnalyzeOptions = {
  /** Address audits only: scope detection to the deployed contract.
   * Paste callers omit this — a pasted file has no deployed contract,
   * so all contracts in the file are analyzed (previous behavior). */
  selectMainContract?: boolean;
  /** On-chain name() probe value, when the caller already has it. Only
   * used when it matches a contract in the file (normalized). The worker
   * and workbench probe in parallel with analysis, so they do not pass
   * this today — the most-derived fallback below does the work instead. */
  deployedName?: string | null;
};

/**
 * Which contract the analysis scopes to (Item 2). Rules, in order:
 *  1. onlyContract, when it names a contract in the file (Sourcify
 *     single-file match: Deed.sol -> contract Deed).
 *  2. deployedName, when its normalized form (lowercase, non-alphanumerics
 *     stripped) equals a contract name's normalized form.
 *  3. When selectMainContract is true: the UNIQUE most-derived contract —
 *     kind is neither "library" nor "interface", and no other contract in
 *     the file lists it in bases. (The deployed contract is the
 *     most-derived one; libraries/utilities are bases, never the target.
 *     The model does not mark abstract contracts, so an abstract
 *     most-derived singleton would be selected — documented limitation.)
 *  4. Otherwise null: analyze every contract (previous behavior).
 * Returns null, never a guess, when rules 1-3 do not resolve.
 */
function selectMainContract(
  model: SourceModel,
  onlyContract: string | null | undefined,
  deployedName: string | null,
  selectMain: boolean,
): string | null {
  const names = new Set(model.contracts.map((c) => c.name));
  if (onlyContract && names.has(onlyContract)) return onlyContract;
  const norm = (s: string) => s.toLowerCase().replace(/[^a-z0-9]/g, "");
  if (deployedName && norm(deployedName) !== "") {
    const hit = model.contracts.find((c) => norm(c.name) === norm(deployedName));
    if (hit) return hit.name;
  }
  if (!selectMain) return null;
  const based = new Set(model.contracts.flatMap((c) => c.bases));
  const candidates = model.contracts.filter(
    (c) =>
      c.kind !== "library" &&
      c.kind !== "interface" &&
      // The synthetic Fragment wrapper is not a real deployed contract.
      c.name !== "Fragment" &&
      !based.has(c.name),
  );
  return candidates.length === 1 ? candidates[0]!.name : null;
}

export function analyzeInput(body: string, label: string, onlyContract?: string | null, opts?: AnalyzeOptions): Report {
  const text = body.replaceAll("\0", "").trim();
  if (looksLikeBytecode(text)) {
    const byte = analyzeBytecode(text);
    const findings = calibrateFindings(byte.findings);
    const name = byte.inventory.contractNames[0] ?? "Bytecode";
    return {
      label,
      inputKind: "bytecode",
      riskScore: scoreOf(findings),
      summary: summarize(findings, name),
      inventory: byte.inventory,
      findings,
      aiNarrative: null,
      aiStatus: "unavailable",
      mainContract: null,
      unparsed: false,
    };
  }

  const model = parseSource(text);
  const mainContract = selectMainContract(
    model,
    onlyContract,
    opts?.deployedName ?? null,
    opts?.selectMainContract ?? false,
  );
  const findings = calibrateFindings(
    model.contracts.length ? detectSource(model, text, mainContract ?? onlyContract) : regexFallback(text),
  );
  const names = model.contracts.map((c) => c.name);
  const notes = [
    model.parseError ?? `Parsed ${model.contracts.length} contract${model.contracts.length === 1 ? "" : "s"}.`,
    "Source was not compiled. Paste runtime bytecode (0x…) for opcode, selector, and proxy inference.",
  ];
  if (model.pragma) notes.unshift(`Pragma ${model.pragma}.`);

  const inventory: Inventory = {
    inputKind: "source",
    contractNames: names,
    kindNote: names.length ? names.map((n, i) => `${model.contracts[i]?.kind ?? "contract"} ${n}`).join(", ") : "Unparsed source",
    pragma: model.pragma,
    compiler: model.versionFloor !== null ? `constraint floor ${formatVer(model.versionFloor)}` : null,
    functions: model.contracts.flatMap((c) =>
      c.functions.map((f) => ({
        name: `${c.name}.${f.name}`,
        visibility: f.visibility === "default" ? "default (public on <0.5)" : f.visibility || "public",
        mutability: f.mutability || "nonpayable",
        modifiers: f.modifiers,
        line: f.line,
        params: f.params.map((p) => `${p.typeName} ${p.name}`.trim()).join(", "),
      })),
    ),
    stateVars: model.contracts.flatMap((c) =>
      c.stateVars.map((v) => ({
        name: `${c.name}.${v.name}`,
        typeName: v.typeName,
        visibility: v.visibility,
        line: v.line,
        constOrImmutable: v.constOrImmutable,
      })),
    ),
    events: model.contracts.flatMap((c) => c.events.map((e) => `${c.name}.${e.name}`)),
    inheritance: model.contracts.flatMap((c) => c.bases.map((b) => `${c.name} is ${b}`)),
    selectors: [],
    reconstructed: "",
    opcodes: [],
    signals: [],
    bytecodeBytes: null,
    basicBlocks: null,
    proxy: null,
    notes,
    disassembly: "",
  };

  const name = (mainContract ?? names[0]) ?? (label || "Contract");
  // Unparsed: no REAL contract was analyzed AND the only findings are
  // the parse-failure INFO (or none). Two shapes:
  //  - 0 contracts: the input failed even fragment-wrapping, so the
  //    findings are regexFallback's (parse INFO, or a real-but-imprecise
  //    tx.origin/delegatecall/selfdestruct hit — which is NOT unparsed).
  //  - A synthetic Fragment contract with no functions/stateVars/
  //    modifiers: a bare enum/struct/error paste the parser wrapped
  //    (the Rocket Pool ENUM case). A Fragment WITH functions is a real
  //    pasted fragment (a lone function) — it was analyzed, so it is
  //    not unparsed even when it produces no findings.
  const noRealContracts =
    model.contracts.length === 0 ||
    model.contracts.every(
      (c) =>
        c.name === "Fragment" &&
        c.functions.length === 0 &&
        c.stateVars.length === 0 &&
        c.modifiers.length === 0,
    );
  const unparsed =
    noRealContracts && (findings.length === 0 || findings.every((f) => f.detector === "parse"));
  return {
    label,
    inputKind: "source",
    riskScore: scoreOf(findings),
    summary: summarize(findings, name),
    inventory,
    findings,
    aiNarrative: null,
    aiStatus: "unavailable",
    mainContract,
    unparsed,
  };
}

function formatVer(v: number): string {
  const major = Math.floor(v / 1_000_000);
  const minor = Math.floor((v % 1_000_000) / 1_000);
  const patch = v % 1_000;
  return `${major}.${minor}.${patch}`;
}

function regexFallback(text: string): Finding[] {
  const findings: Finding[] = [];
  const add = (f: Omit<Finding, "id">) => findings.push({ ...f, id: `r${findings.length + 1}` });
  if (/tx\.origin/.test(text)) {
    add({
      severity: "high",
      swc: "SWC-115",
      title: "tx.origin appears in unparsed source",
      confidence: "medium",
      detector: "tx-origin",
      summary: "The parser could not build an AST, but the text contains tx.origin.",
      walkthrough: "1. tx.origin is the signer, not the caller.\n2. Fix the syntax and re-run so Kiln can place the finding inside a function.",
      exploitSolidity: "",
      remediationSolidity: "require(msg.sender == owner);",
      locationFn: null,
      locationLine: null,
      snippet: "",
    });
  }
  if (/delegatecall/.test(text)) {
    add({
      severity: "high",
      swc: "SWC-112",
      title: "delegatecall appears in unparsed source",
      confidence: "medium",
      detector: "delegatecall",
      summary: "The text contains delegatecall. The parser did not recover a function body, so the target is unverified.",
      walkthrough: "1. Delegatecall shares storage with the caller.\n2. Repair the syntax and re-run.",
      exploitSolidity: "",
      remediationSolidity: "",
      locationFn: null,
      locationLine: null,
      snippet: "",
    });
  }
  if (/selfdestruct|suicide/.test(text)) {
    add({
      severity: "high",
      swc: "SWC-106",
      title: "selfdestruct appears in unparsed source",
      confidence: "medium",
      detector: "selfdestruct",
      summary: "The text mentions selfdestruct but did not parse.",
      walkthrough: "1. Confirm it is guarded by msg.sender.\n2. Re-run after the file parses.",
      exploitSolidity: "",
      remediationSolidity: "",
      locationFn: null,
      locationLine: null,
      snippet: "",
    });
  }
  if (findings.length === 0) {
    add({
      severity: "info",
      swc: null,
      title: "Input did not parse as Solidity or bytecode",
      confidence: "high",
      detector: "parse",
      summary: "Kiln expected a contract or a hex runtime. The paste is neither a clean AST nor an even-length hex string.",
      walkthrough: "1. Paste a full contract, including the pragma, or a 0x-prefixed runtime bytecode.\n2. Fragments are wrapped automatically when they contain a function.",
      exploitSolidity: "",
      remediationSolidity: "",
      locationFn: null,
      locationLine: null,
      snippet: "",
    });
  }
  return findings;
}

export function emptyReport(): Report {
  return {
    label: "",
    inputKind: "source",
    riskScore: 0,
    summary: "",
    inventory: emptyInventory("source", ""),
    findings: [],
    aiNarrative: null,
    aiStatus: "unavailable",
    mainContract: null,
    unparsed: false,
  };
}
