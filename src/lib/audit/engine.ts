import { analyzeBytecode, looksLikeBytecode } from "./bytecode";
import { detectSource } from "./detect";
import { parseSource } from "./model";
import { calibrateFindings } from "./severity-calibration";
import type { Finding, Inventory, Report, Severity } from "./types";

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

export function analyzeInput(body: string, label: string, onlyContract?: string | null): Report {
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
    };
  }

  const model = parseSource(text);
  const findings = calibrateFindings(
    model.contracts.length ? detectSource(model, text, onlyContract) : regexFallback(text),
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

  const name = (onlyContract && names.includes(onlyContract) ? onlyContract : names[0]) ?? (label || "Contract");
  return {
    label,
    inputKind: "source",
    riskScore: scoreOf(findings),
    summary: summarize(findings, name),
    inventory,
    findings,
    aiNarrative: null,
    aiStatus: "unavailable",
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
  };
}
