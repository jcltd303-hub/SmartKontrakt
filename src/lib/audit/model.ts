import parser from "@solidity-parser/parser";
import type { AstNode } from "./types";

export type StateVar = {
  name: string;
  typeName: string;
  visibility: string;
  line: number;
  constOrImmutable: boolean;
};

export type FnModel = {
  name: string;
  visibility: string;
  mutability: string;
  modifiers: string[];
  line: number;
  params: { name: string; typeName: string }[];
  body: AstNode | null;
  source: string;
  isConstructor: boolean;
  isFallback: boolean;
  isReceive: boolean;
};

export type ModModel = {
  name: string;
  line: number;
  source: string;
  body: AstNode | null;
};

export type ContractModel = {
  name: string;
  kind: string;
  bases: string[];
  line: number;
  stateVars: StateVar[];
  functions: FnModel[];
  modifiers: ModModel[];
  events: { name: string; line: number }[];
};

export type SourceModel = {
  pragma: string | null;
  versionFloor: number | null;
  floatingPragma: boolean;
  contracts: ContractModel[];
  parseError: string | null;
  lineDelta: number;
  /** Source string the AST ranges index into (the paste, or a one-line wrapper). */
  parsedSource: string;
};

function typeToString(t: AstNode | null | undefined): string {
  if (!t) return "unknown";
  if (t.type === "ElementaryTypeName" && typeof t.name === "string") return t.name;
  if (t.type === "UserDefinedTypeName") {
    if (typeof t.namePath === "string") return t.namePath;
    if (Array.isArray(t.namePath)) return (t.namePath as string[]).join(".");
  }
  if (t.type === "Mapping") {
    return `mapping(${typeToString(t.keyType as AstNode)} => ${typeToString(t.valueType as AstNode)})`;
  }
  if (t.type === "ArrayTypeName") {
    const len = t.length ? typeToString(t.length as AstNode) : "";
    return `${typeToString(t.baseTypeName as AstNode)}[${len}]`;
  }
  return t.type;
}

function lineOf(node: AstNode | undefined, delta: number): number {
  const line = node?.loc?.start.line ?? 1;
  return Math.max(1, line - delta);
}

function slice(source: string, node: AstNode | null | undefined): string {
  if (!node?.range) return "";
  return source.slice(node.range[0], node.range[1]);
}

function modNames(node: AstNode): string[] {
  const mods = node.modifiers;
  if (!Array.isArray(mods)) return [];
  return mods.map((m) => {
    const mod = m as AstNode;
    if (typeof mod.name === "string") return mod.name;
    const inner = mod.name as AstNode | undefined;
    return typeof inner?.name === "string" ? inner.name : "";
  }).filter(Boolean);
}

function paramsOf(node: AstNode): { name: string; typeName: string }[] {
  const raw = node.parameters;
  const list = Array.isArray(raw) ? raw : ((raw as AstNode | undefined)?.parameters as AstNode[] | undefined);
  if (!Array.isArray(list)) return [];
  return list.filter(Boolean).map((p) => {
    const v = p as AstNode;
    return {
      name: typeof v.name === "string" ? v.name : "",
      typeName: typeToString(v.typeName as AstNode),
    };
  });
}

function parseVersions(value: string): number[] {
  return [...value.matchAll(/(\d+)\.(\d+)\.(\d+)/g)].map(
    (m) => Number(m[1]) * 1_000_000 + Number(m[2]) * 1_000 + Number(m[3]),
  );
}

function build(ast: AstNode, original: string, delta: number): SourceModel {
  const children = (ast.children as AstNode[] | undefined) ?? [];
  const pragmas = children.filter((c) => c.type === "PragmaDirective" && c.name === "solidity");
  const pragma = pragmas.map((p) => String(p.value ?? "")).find(Boolean) ?? null;
  const versions = pragma ? parseVersions(pragma) : [];
  const versionFloor = versions.length ? Math.min(...versions) : null;
  const floating = pragma ? /[\^<>]/.test(pragma) : false;

  const contracts: ContractModel[] = [];
  for (const node of children) {
    if (node.type !== "ContractDefinition") continue;
    const subs = (node.subNodes as AstNode[] | undefined) ?? [];
    const bases = ((node.baseContracts as AstNode[] | undefined) ?? []).map((b) => {
      const base = b.baseName as AstNode | undefined;
      if (!base) return "";
      if (typeof base.namePath === "string") return base.namePath;
      return "";
    }).filter(Boolean);

    const stateVars: StateVar[] = [];
    const functions: FnModel[] = [];
    const modifiers: ModModel[] = [];
    const events: { name: string; line: number }[] = [];

    for (const sub of subs) {
      if (sub.type === "StateVariableDeclaration") {
        const vars = (sub.variables as AstNode[] | undefined) ?? [];
        for (const v of vars) {
          if (!v.name) continue;
          stateVars.push({
            name: v.name,
            typeName: typeToString(v.typeName as AstNode),
            visibility: typeof v.visibility === "string" ? v.visibility : "default",
            line: lineOf(v, delta),
            constOrImmutable: Boolean(v.isDeclaredConst || v.isImmutable),
          });
        }
      } else if (sub.type === "FunctionDefinition") {
        const isConstructor = Boolean(sub.isConstructor);
        const isFallback = Boolean(sub.isFallback) || sub.name === "";
        const isReceive = Boolean(sub.isReceive) || (sub.kind === "receive");
        const name = isConstructor
          ? "constructor"
          : isReceive
            ? "receive"
            : isFallback && !sub.name
              ? "fallback"
              : String(sub.name ?? "fallback");
        functions.push({
          name,
          visibility: typeof sub.visibility === "string" ? sub.visibility : "default",
          mutability: typeof sub.stateMutability === "string" ? sub.stateMutability : "",
          modifiers: modNames(sub),
          line: lineOf(sub, delta),
          params: paramsOf(sub),
          body: (sub.body as AstNode | null) ?? null,
          source: slice(original, sub),
          isConstructor,
          isFallback: name === "fallback",
          isReceive: name === "receive",
        });
      } else if (sub.type === "ModifierDefinition") {
        modifiers.push({
          name: String(sub.name ?? ""),
          line: lineOf(sub, delta),
          source: slice(original, sub),
          body: (sub.body as AstNode | null) ?? null,
        });
      } else if (sub.type === "EventDefinition" && sub.name) {
        events.push({ name: sub.name, line: lineOf(sub, delta) });
      }
    }

    contracts.push({
      name: String(node.name ?? "Contract"),
      kind: String(node.kind ?? "contract"),
      bases,
      line: lineOf(node, delta),
      stateVars,
      functions,
      modifiers,
      events,
    });
  }

  return {
    pragma,
    versionFloor,
    floatingPragma: floating,
    contracts,
    parseError: null,
    lineDelta: delta,
    parsedSource: original,
  };
}

function tryParse(code: string): AstNode {
  return parser.parse(code, { tolerant: true, loc: true, range: true }) as unknown as AstNode;
}

function emptyModel(message: string): SourceModel {
  return {
    pragma: null,
    versionFloor: null,
    floatingPragma: false,
    contracts: [],
    parseError: message,
    lineDelta: 0,
    parsedSource: "",
  };
}

export function parseSource(source: string): SourceModel {
  try {
    const ast = tryParse(source);
    const model = build(ast, source, 0);
    if (model.contracts.length > 0) return model;
  } catch {
    // A bare function: wrap it so the parser has a contract to walk.
  }

  const wrapped = `contract Wrapped {\n${source}\n}`;
  try {
    const ast = tryParse(wrapped);
    const model = build(ast, wrapped, 1);
    model.parseError = "No top-level contract; parsed as a fragment. Line numbers refer to your paste.";
    if (model.contracts.length > 0) {
      for (const c of model.contracts) {
        if (c.name === "Wrapped") c.name = "Fragment";
      }
      return model;
    }
  } catch (err) {
    return emptyModel(err instanceof Error ? err.message : "Could not parse Solidity");
  }
  return emptyModel("No contract found");
}

