import { disassemble, formatDisassembly, type Instruction } from "./disassemble.ts";
import { estimateGasAndDetectDos } from "./gas-estimator.ts";
import { lookupSelector } from "./selectors.ts";
import type { Finding, Inventory, SelectorHit, TopicHit } from "./types.ts";

const IMPL_SLOT = "360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc";
const ADMIN_SLOT = "b53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103";
const BEACON_SLOT = "a3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50";

const SIGNAL_OPS = [
  "SELFDESTRUCT",
  "DELEGATECALL",
  "CALLCODE",
  "CALL",
  "STATICCALL",
  "CREATE",
  "CREATE2",
  "ORIGIN",
  "SSTORE",
  "SLOAD",
  "TIMESTAMP",
  "BLOCKHASH",
  "PREVRANDAO",
  "EXTCODESIZE",
  "GAS",
  "CALLVALUE",
  "BALANCE",
] as const;

export type BytecodeReport = {
  inventory: Inventory;
  findings: Finding[];
};

function hexToBytes(input: string): Uint8Array | null {
  const hex = input.trim().replace(/^0x/i, "").replace(/\s+/g, "");
  if (hex.length < 2 || hex.length % 2 !== 0 || !/^[0-9a-fA-F]+$/.test(hex)) return null;
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i += 1) out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

const AUXDATA_KEYS = new Set(["ipfs", "bzzr0", "bzzr1", "solc", "experimental"]);

/**
 * Structural CBOR validation of a solc auxdata segment: a definite-length
 * map with text keys drawn from the known auxdata set and byte-string (or,
 * for "experimental", boolean) values, consuming the segment EXACTLY.
 * Returns the decoded facts, or null on ANY structural deviation — a tail
 * that is not exactly this shape is code or data, never metadata, and
 * stripping it would silently cut real instructions.
 *
 * Fix 39: the pre-fix check was a latin-1 substring gate ("solc"/"ipfs"/
 * "bzzr" anywhere in the tail bytes). Structural parsing is stricter in
 * what it accepts AND stronger in what it proves: a segment that parses
 * as auxdata is auxdata, so it can be stripped repeatedly (a runtime
 * that embeds another contract's bytecode as data carries the embedded
 * contract's own auxdata tail just inside its own — the presence proof's
 * Maker portal kept a phantom "CALLCODE" byte inside exactly such an
 * inner ipfs hash).
 */
function parseAuxdataSegment(seg: Uint8Array): { compiler: string | null; hasIpfs: boolean } | null {
  let pos = 0;
  const readHead = (): { major: number; arg: number } | null => {
    const b = seg[pos];
    if (b === undefined) return null;
    pos += 1;
    const major = b >> 5;
    const ai = b & 0x1f;
    if (ai < 24) return { major, arg: ai };
    if (ai === 24) {
      const v = seg[pos];
      if (v === undefined) return null;
      pos += 1;
      return { major, arg: v };
    }
    if (ai === 25) {
      if (pos + 2 > seg.length) return null;
      const v = ((seg[pos] ?? 0) << 8) | (seg[pos + 1] ?? 0);
      pos += 2;
      return { major, arg: v };
    }
    if (ai === 26) {
      if (pos + 4 > seg.length) return null;
      let v = 0;
      for (let k = 0; k < 4; k += 1) v = v * 256 + (seg[pos + k] ?? 0);
      pos += 4;
      return { major, arg: v };
    }
    return null; // 64-bit and indefinite forms never occur in auxdata
  };
  const head = readHead();
  if (!head || head.major !== 5 || head.arg < 1 || head.arg > 5) return null;
  let compiler: string | null = null;
  let hasIpfs = false;
  for (let pair = 0; pair < head.arg; pair += 1) {
    const kh = readHead();
    if (!kh || kh.major !== 3 || kh.arg < 1 || kh.arg > 12 || pos + kh.arg > seg.length) return null;
    const key = String.fromCharCode(...seg.slice(pos, pos + kh.arg));
    pos += kh.arg;
    if (!AUXDATA_KEYS.has(key)) return null;
    if (key === "experimental") {
      const v = seg[pos];
      if (v !== 0xf4 && v !== 0xf5) return null;
      pos += 1;
      continue;
    }
    const vh = readHead();
    if (!vh || vh.major !== 2 || pos + vh.arg > seg.length) return null;
    const val = seg.slice(pos, pos + vh.arg);
    pos += vh.arg;
    if (key === "solc") {
      if (val.length !== 3) return null;
      compiler = `${val[0] ?? 0}.${val[1] ?? 0}.${val[2] ?? 0}`;
    }
    if (key === "ipfs") hasIpfs = true;
  }
  if (pos !== seg.length) return null;
  return { compiler, hasIpfs };
}

/** One auxdata strip attempt; null when the tail is not auxdata. */
function stripOneAuxdata(code: Uint8Array): { body: Uint8Array; compiler: string | null; hasIpfs: boolean } | null {
  if (code.length < 4) return null;
  const len = ((code[code.length - 2] ?? 0) << 8) | (code[code.length - 1] ?? 0);
  if (len < 6 || len > code.length - 2) return null;
  const start = code.length - 2 - len;
  const seg = code.slice(start, code.length - 2);
  const parsed = parseAuxdataSegment(seg);
  if (parsed) return { body: code.slice(0, start), compiler: parsed.compiler, hasIpfs: parsed.hasIpfs };
  // Legacy fallback for auxdata shapes the strict parser rejects (an
  // extra unknown key from a newer compiler, say): the pre-Fix-39
  // positive-evidence gate. Real solc metadata always carries a "solc"
  // version entry plus an "ipfs" or "bzzr" hash; without one of those
  // markers, any contract whose last 2 bytes happen to decode as a
  // plausible length + a CBOR-map first byte would get its tail
  // instructions silently cut (~2-4% of metadata-less contracts).
  const first = code[start] ?? 0;
  if (first < 0xa0 || first > 0xbf) return null;
  const latin = String.fromCharCode(...seg);
  const hasSolcMarker = latin.includes("solc");
  const hasIpfsMarker = latin.includes("ipfs");
  const hasBzzrMarker = latin.includes("bzzr");
  if (!hasSolcMarker && !hasIpfsMarker && !hasBzzrMarker) return null;
  const idx = latin.indexOf("solc");
  let compiler: string | null = null;
  if (idx >= 0 && seg[idx + 4] === 0x43) {
    compiler = `${seg[idx + 5] ?? 0}.${seg[idx + 6] ?? 0}.${seg[idx + 7] ?? 0}`;
  }
  return { body: code.slice(0, start), compiler, hasIpfs: hasIpfsMarker };
}

function stripMetadata(code: Uint8Array): { body: Uint8Array; compiler: string | null; hasIpfs: boolean } {
  // Iterate: a runtime can carry more than one auxdata tail (an embedded
  // contract's bytecode keeps its own tail just inside the outer one).
  // The OUTERMOST segment is the deployed contract's own metadata, so
  // its compiler version wins; later rounds only fill gaps.
  let body = code;
  let compiler: string | null = null;
  let hasIpfs = false;
  for (let round = 0; round < 4; round += 1) {
    const once = stripOneAuxdata(body);
    if (!once) break;
    if (compiler === null) compiler = once.compiler;
    hasIpfs = hasIpfs || once.hasIpfs;
    body = once.body;
  }
  return { body, compiler, hasIpfs };
}

function countOps(ins: Instruction[]): Map<string, number> {
  const map = new Map<string, number>();
  for (const i of ins) map.set(i.name, (map.get(i.name) ?? 0) + 1);
  return map;
}

function basicBlocks(ins: Instruction[]): number {
  if (ins.length === 0) return 0;
  const terminals = new Set(["JUMP", "JUMPI", "STOP", "RETURN", "REVERT", "INVALID", "SELFDESTRUCT"]);
  let blocks = 1;
  for (let i = 0; i < ins.length; i += 1) {
    const cur = ins[i];
    if (!cur) continue;
    if (cur.name === "JUMPDEST" && i !== 0) blocks += 1;
    else if (terminals.has(cur.name) && i < ins.length - 1 && ins[i + 1]?.name !== "JUMPDEST") blocks += 1;
  }
  return blocks;
}

/**
 * PUSH32 immediates — candidate event topics. A PUSH32 can be a topic
 * hash, a constant, a slot, or an address; resolution (fourbyte.ts)
 * keeps only the ones matching a known event signature. Taken from the
 * full instruction stream, NOT the capped stored disassembly, so topics
 * in later code are seen. Signatures start null; enrichment fills them.
 */
function topicsOf(ins: Instruction[]): TopicHit[] {
  const seen = new Set<string>();
  const out: TopicHit[] = [];
  for (const cur of ins) {
    if (!cur || cur.name !== "PUSH32" || !cur.imm || cur.imm.length !== 64) continue;
    const topic = `0x${cur.imm.toLowerCase()}`;
    if (seen.has(topic)) continue;
    seen.add(topic);
    out.push({ topic, signature: null });
    if (out.length >= 500) break;
  }
  return out;
}

function selectorsOf(ins: Instruction[]): SelectorHit[] {
  const hits: SelectorHit[] = [];
  const seen = new Set<string>();
  for (let i = 0; i < ins.length; i += 1) {
    const cur = ins[i];
    if (!cur || cur.name !== "PUSH4" || !cur.imm || cur.imm.length !== 8) continue;
    const sel = cur.imm.toLowerCase();
    const known = lookupSelector(sel);
    let nearEq = false;
    for (let j = 1; j <= 4 && i + j < ins.length; j += 1) {
      const n = ins[i + j]?.name;
      if (n === "EQ" || n === "JUMPI") nearEq = true;
    }
    if (!known && !nearEq) continue;
    if (seen.has(sel)) continue;
    seen.add(sel);
    hits.push({ selector: `0x${sel}`, signature: known });
  }
  return hits;
}

function reconstruct(selectors: SelectorHit[]): string {
  if (selectors.length === 0) {
    return "// No Solidity-style dispatcher (PUSH4/EQ) was recovered.\n// The bytecode may be a proxy, a constructor, or hand-written EVM.";
  }
  const lines = [
    "// Inferred from PUSH4 immediates. Known signatures are matched locally;",
    "// unknown selectors keep their raw id. Mutability is not recovered.",
    "interface InferredRuntime {",
  ];
  for (const s of selectors) {
    if (s.signature) {
      const name = s.signature.slice(0, s.signature.indexOf("("));
      lines.push(`    function ${s.signature} external; // ${s.selector}  ${name}`);
    } else {
      lines.push(`    function unknown_${s.selector.slice(2)}() external; // ${s.selector}`);
    }
  }
  lines.push("}");
  return lines.join("\n");
}

function snippetFor(ins: Instruction[], pc: number): string {
  const idx = ins.findIndex((i) => i.pc === pc);
  const start = Math.max(0, idx - 3);
  const end = Math.min(ins.length, (idx < 0 ? 0 : idx) + 5);
  return ins
    .slice(start, end)
    .map((i) => {
      const mark = i.pc === pc ? ">" : " ";
      const imm = i.imm ? ` 0x${i.imm}` : "";
      return `${mark} ${i.pc.toString(16).padStart(4, "0")}  ${i.name}${imm}`;
    })
    .join("\n");
}

let seq = 0;
function finding(partial: Omit<Finding, "id">): Finding {
  seq += 1;
  return { ...partial, id: `b${seq}` };
}

export function decodeHex(input: string): Uint8Array | null {
  return hexToBytes(input);
}

/**
 * Full disassembly for the CFG viewer. The stored inventory.disassembly is
 * capped at 420 instructions (kept small because it is persisted per
 * record), which truncates the CFG for most contracts. This recomputes the
 * full stream in memory — never persisted — from the raw input, with the
 * same metadata strip analyzeBytecode applies.
 */
export function fullDisassembly(raw: string): string {
  const code = hexToBytes(raw);
  if (!code) return "";
  const meta = stripMetadata(code);
  const body = meta.body.length > 0 ? meta.body : code;
  return formatDisassembly(disassemble(body), 20000).text;
}

export function looksLikeBytecode(input: string): boolean {
  const t = input.trim();
  if (/pragma\s+solidity|\bcontract\s+\w+|\bfunction\s+\w+/.test(t)) return false;
  return hexToBytes(t) !== null && t.replace(/\s+/g, "").replace(/^0x/i, "").length >= 2;
}

/**
 * Fix 39 (presence proof): solc leaves the ERC20 Transfer event topic as
 * a verbatim 32-byte word in the tail data region of some runtimes. It
 * is DATA, but a linear sweep that reaches it misaligned reads its
 * second byte (0xf2) as a CALLCODE instruction — 16 of the proof's 21
 * no-CALLCODE contracts carried exactly this artifact, and 72/72 stored
 * bytecode-callcode highs were false. Occurrences consumed as a PUSH32
 * immediate are genuine code (the topic being pushed for a LOG) and are
 * NOT excluded; every other occurrence marks its 32 pcs as data, and no
 * instruction whose pc falls inside may feed an opcode-presence claim.
 */
const TRAILING_CONSTANT_HEX = "ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef";

function trailingConstantDataPcs(hex: string, ins: Instruction[]): Set<number> {
  const pcs = new Set<number>();
  const push32ImmediateAt = new Set<number>();
  for (const i of ins) {
    if (i.name === "PUSH32" && i.imm) push32ImmediateAt.add(i.pc + 1);
  }
  let from = 0;
  for (;;) {
    const idx = hex.indexOf(TRAILING_CONSTANT_HEX, from);
    if (idx < 0) break;
    const byteOff = idx / 2;
    if (!push32ImmediateAt.has(byteOff)) {
      for (let b = byteOff; b < byteOff + 32; b += 1) pcs.add(b);
    }
    from = idx + 2;
  }
  return pcs;
}

/**
 * Operand resolution for DELEGATECALL / CALLCODE sites (Fix 39).
 *
 * The opcode's risk is its TARGET operand, and the presence proof showed
 * the stored highs were standard shapes: EIP-1167 clones (target = a
 * constant embedded in the clone), Safe proxies (target = SLOAD of
 * slot 0), fixed library constants, EIP-1967 slot loads. A bounded
 * abstract interpretation over the instruction stream tracks each stack
 * slot's provenance — constant, storage slot, calldata-derived, self —
 * so a site whose target is provably fixed can be reported as what it
 * is. Anything the tracker cannot follow stays unresolved and keeps the
 * presence-level treatment: fail toward signal, not silence.
 */
type StackTag =
  | { kind: "const"; value: bigint }
  | { kind: "calldata" }
  | { kind: "slot"; key: bigint | null }
  | { kind: "self" }
  | { kind: "opaque" };

type TargetResolution =
  | { cls: "constant"; address: string }
  | { cls: "slot"; label: string }
  | { cls: "self" }
  | { cls: "calldata" }
  | { cls: "unresolved"; why: string };

const OPAQUE: StackTag = { kind: "opaque" };
const ADDRESS_LIMIT = 1n << 160n;

function classifyTarget(tag: StackTag | undefined): TargetResolution {
  if (!tag) return { cls: "unresolved", why: "the operand stack could not be reconstructed at this site" };
  switch (tag.kind) {
    case "const": {
      if (tag.value >= ADDRESS_LIMIT) {
        return { cls: "unresolved", why: "the constant feeding the target is wider than an address" };
      }
      return { cls: "constant", address: `0x${tag.value.toString(16).padStart(40, "0")}` };
    }
    case "slot": {
      if (tag.key === null) return { cls: "unresolved", why: "the target is loaded from a storage slot whose key is not a constant" };
      const slotHex = `0x${tag.key.toString(16).padStart(64, "0")}`;
      if (slotHex === `0x${IMPL_SLOT}`) return { cls: "slot", label: "the EIP-1967 implementation slot" };
      if (slotHex === `0x${BEACON_SLOT}`) return { cls: "slot", label: "the EIP-1967 beacon slot" };
      if (slotHex === `0x${ADMIN_SLOT}`) return { cls: "slot", label: "the EIP-1967 admin slot" };
      if (tag.key === 0n) return { cls: "slot", label: "storage slot 0 (the Safe-style singleton slot)" };
      return { cls: "slot", label: `storage slot ${slotHex.slice(0, 10)}…${slotHex.slice(-4)}` };
    }
    case "self":
      return { cls: "self" };
    case "calldata":
      return { cls: "calldata" };
    default:
      return { cls: "unresolved", why: "the target is computed in a way the operand tracker cannot follow" };
  }
}

function combineTags(a: StackTag, b: StackTag, op: string): StackTag {
  if (a.kind === "const" && b.kind === "const") {
    const mask = (1n << 256n) - 1n;
    try {
      switch (op) {
        case "ADD": return { kind: "const", value: (a.value + b.value) & mask };
        case "SUB": return { kind: "const", value: (a.value - b.value) & mask };
        case "MUL": return { kind: "const", value: (a.value * b.value) & mask };
        case "AND": return { kind: "const", value: a.value & b.value };
        case "OR": return { kind: "const", value: a.value | b.value };
        case "XOR": return { kind: "const", value: a.value ^ b.value };
        default: return OPAQUE;
      }
    } catch {
      return OPAQUE;
    }
  }
  if (a.kind === "calldata" || b.kind === "calldata") return { kind: "calldata" };
  if ((a.kind === "slot" && b.kind === "const") || (b.kind === "slot" && a.kind === "const")) {
    return a.kind === "slot" ? a : b;
  }
  return OPAQUE;
}

const BINARY_OPS = new Set([
  "ADD", "MUL", "SUB", "DIV", "SDIV", "MOD", "SMOD", "EXP", "ADDMOD", "MULMOD",
  "LT", "GT", "SLT", "SGT", "EQ", "AND", "OR", "XOR", "BYTE",
  "SHL", "SHR", "SAR", "SIGNEXTEND",
]);

/** (pops, pushes) for the backward walk. DUP/SWAP return null — handled as permutations. */
function stackEffect(name: string): { pops: number; pushes: number } | null {
  if (name.startsWith("PUSH") || name === "ADDRESS" || name === "CALLER" || name === "CALLVALUE" ||
      name === "CALLDATASIZE" || name === "CODESIZE" || name === "GASPRICE" || name === "RETURNDATASIZE" ||
      name === "COINBASE" || name === "TIMESTAMP" || name === "NUMBER" || name === "PREVRANDAO" ||
      name === "GASLIMIT" || name === "CHAINID" || name === "SELFBALANCE" || name === "BASEFEE" ||
      name === "BLOBBASEFEE" || name === "PC" || name === "MSIZE" || name === "GAS") {
    return { pops: 0, pushes: 1 };
  }
  if (name.startsWith("DUP") || name.startsWith("SWAP")) return null;
  switch (name) {
    case "POP": return { pops: 1, pushes: 0 };
    case "MLOAD": case "SLOAD": case "TLOAD": case "CALLDATALOAD":
    case "BALANCE": case "EXTCODESIZE": case "EXTCODEHASH": case "BLOBHASH": case "BLOCKHASH":
    case "ISZERO": case "NOT":
      return { pops: 1, pushes: 1 };
    case "MSTORE": case "MSTORE8": case "SSTORE": case "TSTORE": case "JUMPI":
    case "RETURN": case "REVERT":
      return { pops: 2, pushes: 0 };
    case "KECCAK256": return { pops: 2, pushes: 1 };
    case "CALLDATACOPY": case "CODECOPY": case "RETURNDATACOPY": case "MCOPY": case "CREATE":
      return { pops: 3, pushes: name === "CREATE" ? 1 : 0 };
    case "EXTCODECOPY": case "CREATE2":
      return { pops: 4, pushes: name === "CREATE2" ? 1 : 0 };
    case "CALL": case "CALLCODE": return { pops: 7, pushes: 1 };
    case "DELEGATECALL": case "STATICCALL": return { pops: 6, pushes: 1 };
    case "JUMP": case "SELFDESTRUCT": return { pops: 1, pushes: 0 };
    case "JUMPDEST": case "STOP": case "INVALID": return { pops: 0, pushes: 0 };
    default:
      if (BINARY_OPS.has(name)) return { pops: 2, pushes: 1 };
      if (name.startsWith("LOG")) return { pops: 2 + Number(name.slice(3) || "0"), pushes: 0 };
      // Opcodes outside the model (undefined bytes in data remnants,
      // newer ops): assume no net effect and keep walking — the
      // alternative, stopping, would unresolve every long window.
      return { pops: 0, pushes: 0 };
  }
}

const TRACE_WINDOW = 600;
const TRACE_DEPTH = 4;

/**
 * Backward provenance slice: which value sits at stack depth `depth`
 * (0 = top) just before stream[i+1]? Walks the stream backward,
 * adjusting the traced depth by each instruction's stack effect, until
 * the value is found to be PRODUCED by an instruction — whose own
 * provenance is then read (recursively for its operands). Walking
 * backward across JUMPDESTs and jumps is deliberate: solc passes stack
 * arguments across internal jumps, and proxies leave the singleton on
 * the stack before the dispatcher branches — a forward window cleared
 * at every jump cannot see either shape.
 */
function traceTag(stream: Instruction[], i: number, depth: number, level: number): StackTag {
  if (level > TRACE_DEPTH) return OPAQUE;
  let d = depth;
  const floor = Math.max(-1, i - TRACE_WINDOW);
  for (let j = i; j > floor; j -= 1) {
    const ins = stream[j];
    if (!ins) continue;
    const name = ins.name;
    if (name.startsWith("SWAP")) {
      const n = Number(name.slice(4));
      if (d === 0) d = n;
      else if (d === n) d = 0;
      continue;
    }
    if (name.startsWith("DUP")) {
      const n = Number(name.slice(3));
      if (d === 0) return traceTag(stream, j - 1, n - 1, level + 1);
      d -= 1;
      continue;
    }
    const eff = stackEffect(name);
    if (!eff) continue;
    if (d < eff.pushes) {
      // The traced value is produced by this instruction.
      if (name.startsWith("PUSH")) {
        try {
          return { kind: "const", value: ins.imm ? BigInt(`0x${ins.imm}`) : 0n };
        } catch {
          return OPAQUE;
        }
      }
      if (name === "CALLDATALOAD") return { kind: "calldata" };
      if (name === "ADDRESS") return { kind: "self" };
      if (name === "SLOAD") {
        const key = traceTag(stream, j - 1, 0, level + 1);
        return { kind: "slot", key: key.kind === "const" ? key.value : null };
      }
      if (name === "MLOAD") {
        const off = traceTag(stream, j - 1, 0, level + 1);
        if (off.kind !== "const") return OPAQUE;
        return traceMemory(stream, j - 1, off.value, level + 1);
      }
      if (BINARY_OPS.has(name)) {
        const a = traceTag(stream, j - 1, 0, level + 1);
        const b = traceTag(stream, j - 1, 1, level + 1);
        return combineTags(a, b, name);
      }
      if (name === "ISZERO" || name === "NOT") {
        const a = traceTag(stream, j - 1, 0, level + 1);
        if (a.kind === "const" && name === "NOT") return { kind: "const", value: ((1n << 256n) - 1n) ^ a.value };
        if (a.kind === "calldata") return { kind: "calldata" };
        if (a.kind === "slot") return a;
        return OPAQUE;
      }
      return OPAQUE;
    }
    d = d - eff.pushes + eff.pops;
  }
  return OPAQUE;
}

/** Who last wrote memory word `offset` before stream[i+1]? */
function traceMemory(stream: Instruction[], i: number, offset: bigint, level: number): StackTag {
  if (level > TRACE_DEPTH) return OPAQUE;
  const floor = Math.max(-1, i - TRACE_WINDOW);
  for (let j = i; j > floor; j -= 1) {
    const ins = stream[j];
    if (!ins) continue;
    if (ins.name === "MSTORE") {
      const off = traceTag(stream, j - 1, 0, level + 1);
      if (off.kind === "const" && off.value === offset) {
        return traceTag(stream, j - 1, 1, level + 1);
      }
      continue;
    }
    if (ins.name === "MSTORE8") {
      const off = traceTag(stream, j - 1, 0, level + 1);
      if (off.kind === "const" && off.value - (off.value % 32n) === offset) return OPAQUE;
      continue;
    }
    if (ins.name === "CALLDATACOPY" || ins.name === "CODECOPY" || ins.name === "RETURNDATACOPY") {
      const dest = traceTag(stream, j - 1, 0, level + 1);
      const size = traceTag(stream, j - 1, 2, level + 1);
      if (dest.kind === "const" && size.kind === "const" && offset >= dest.value && offset < dest.value + size.value) {
        return ins.name === "CALLDATACOPY" ? { kind: "calldata" } : OPAQUE;
      }
      continue;
    }
    if (ins.name === "MCOPY") return OPAQUE;
  }
  return OPAQUE;
}

/**
 * Resolve the target operand of every DELEGATECALL / CALLCODE site in
 * the stream. At the call, the stack is [.., to, gas] with gas on top,
 * so the target is traced at depth 1.
 */
function resolveCallTargets(stream: Instruction[]): Map<number, TargetResolution> {
  const out = new Map<number, TargetResolution>();
  for (let idx = 0; idx < stream.length; idx += 1) {
    const ins = stream[idx];
    if (!ins || (ins.name !== "DELEGATECALL" && ins.name !== "CALLCODE")) continue;
    out.set(ins.pc, classifyTarget(traceTag(stream, idx - 1, 1, 0)));
  }
  return out;
}


export function analyzeBytecode(raw: string): BytecodeReport {
  seq = 0;
  const code = hexToBytes(raw);
  if (!code) {
    return {
      inventory: emptyInventory("Could not decode hex."),
      findings: [],
    };
  }
  const meta = stripMetadata(code);
  const ins = disassemble(meta.body.length > 0 ? meta.body : code);
  const hex = [...(meta.body.length ? meta.body : code)].map((b) => b.toString(16).padStart(2, "0")).join("");
  // Fix 39: opcode-presence claims come from the instruction stream
  // MINUS the pcs inside embedded data regions (the solc
  // trailing-constant word). The full stream still backs the stored
  // disassembly text and the snippet windows — only counts, site lists
  // and detector inputs change, so a byte inside data can never again
  // be claimed as an instruction.
  const dataPcs = trailingConstantDataPcs(hex, ins);
  const codeIns = dataPcs.size > 0 ? ins.filter((i) => !dataPcs.has(i.pc)) : ins;
  const counts = countOps(codeIns);
  const sels = selectorsOf(codeIns);
  const formatted = formatDisassembly(ins, 420);
  const gasStats = estimateGasAndDetectDos(codeIns);
  // Declared here, before the first push (the gas-DoS finding below). It used
  // to be declared further down, which TypeScript rejected as
  // use-before-declaration.
  const findings: Finding[] = [];
  if (gasStats.unboundedStorageWarning) {
    findings.push(
      finding({
        severity: "medium",
        swc: "SWC-128",
        title: "Potential DoS: Unbounded storage access in loop",
        confidence: "medium",
        detector: "gas-estimator-dos",
        summary: `Detected potential unbounded storage access in a loop: ${gasStats.warnings.join(" ")}`,
        walkthrough: "If a loop iterates over an unbounded storage array (e.g., users, recipients), and performs SLOAD/SSTORE per iteration, the transaction will exceed the block gas limit, causing a Denial of Service.",
        exploitSolidity: "contract Attacker { function trigger() external { /* call target repeatedly to bloat array */ } }",
        remediationSolidity: "Use a pull-payment pattern (withdraw pattern) instead of push-payment loops. Limit array sizes.",
        locationFn: "runtime",
        locationLine: null,
        snippet: gasStats.warnings.join("\n"),
      })
    );
  }

  const notes: string[] = [];
  if (meta.compiler) notes.push(`Solidity metadata suffix decoded. Compiler ${meta.compiler}.`);
  else notes.push("No CBOR metadata suffix. This may be creation bytecode, a hand-written runtime, or metadata was stripped.");
  if (meta.hasIpfs) notes.push("Metadata includes an IPFS content hash (the compiler's source fingerprint, not the source itself).");
  notes.push(`${codeIns.length} instructions, ${code.length} input bytes${meta.body.length && meta.body.length !== code.length ? `, ${meta.body.length} after metadata strip` : ""}.`);
  if (dataPcs.size > 0) {
    notes.push(`Excluded ${dataPcs.size} bytes of embedded data (the solc trailing-constant word) from opcode presence counts — bytes inside data are not instructions.`);
  }
  if (hex.startsWith("6080604052")) notes.push("Opens with the usual Solidity free-memory prologue (PUSH1 0x80 / PUSH1 0x40 / MSTORE).");

  let proxy: string | null = null;
  const proxyMatch = hex.match(/363d3d373d3d3d363d73([0-9a-f]{40})5af43d82803e903d91602b57fd5bf3/i);
  if (proxyMatch) {
    proxy = `EIP-1167 minimal proxy. Implementation 0x${proxyMatch[1]}`;
    notes.push(proxy);
  }
  if (hex.includes(IMPL_SLOT)) {
    proxy = proxy ? `${proxy}; EIP-1967 implementation slot present` : "EIP-1967 implementation slot present (transparent / UUPS-style proxy)";
    notes.push("PUSH of the EIP-1967 implementation slot.");
  }
  if (hex.includes(ADMIN_SLOT)) notes.push("EIP-1967 admin slot present.");
  if (hex.includes(BEACON_SLOT)) notes.push("EIP-1967 beacon slot present.");

  const self = counts.get("SELFDESTRUCT") ?? 0;
  const deleg = counts.get("DELEGATECALL") ?? 0;
  const callcode = counts.get("CALLCODE") ?? 0;
  const origin = counts.get("ORIGIN") ?? 0;
  const calls = counts.get("CALL") ?? 0;
  const sstore = counts.get("SSTORE") ?? 0;
  const timestamp = counts.get("TIMESTAMP") ?? 0;
  const create2 = counts.get("CREATE2") ?? 0;

  if (self > 0) {
    const pc = codeIns.find((i) => i.name === "SELFDESTRUCT")?.pc ?? 0;
    findings.push(
      finding({
        // Fix 33: opcode PRESENCE is not a vulnerability. This finding
        // used to be high on presence alone (205 critical/high rows in
        // the archive poll, 0 ever reproduced). Ungated reachability is
        // what earns severity, and bytecode presence does not prove it
        // — the source-level selfdestruct detector carries that when
        // source is available.
        severity: "low",
        swc: "SWC-106",
        title: "SELFDESTRUCT is reachable in the bytecode",
        confidence: "high",
        detector: "bytecode-selfdestruct",
        summary: `Presence only: the runtime contains SELFDESTRUCT ${self} time${self === 1 ? "" : "s"}. Presence is not a vulnerability — a destroy path is normally gated in source this analysis cannot see, and since EIP-6780 the opcode mostly just sweeps the balance. Without source, Kiln cannot prove an access check dominates it, nor that an arbitrary caller can reach it; treat this as a pointer to check the guard, not as a confirmed kill switch.`,
        walkthrough: [
          "1. SELFDESTRUCT (0xff) sends the contract's entire balance to the address on the stack and, in the creating transaction, removes the code from the state.",
          "2. The instruction is present in this bytecode. Presence is not reachability: whether an arbitrary caller can reach it depends on the branch guards before it, which need source or an execution trace to prove. A dispatcher that compares CALLER to a stored owner would usually show SLOAD + EQ + JUMPI before it — confirm that pattern actually guards this pc.",
          "3. After destruction, later calls to the address fail, and a CREATE2 redeploy at the same address can resurrect different code (metamorphic contract).",
        ].join("\n"),
        exploitSolidity: `// Reconstruction from the opcode. Not recovered source.
interface IVictim { function withdraw() external; }

contract DestroyIfOrigin {
    function poke(address payable victim) external {
        // If the bytecode's guard is tx.origin (ORIGIN opcode) rather than
        // CALLER, a malicious contract can trick the owner into calling here,
        // then forward into the victim so SELFDESTRUCT runs with the owner's origin.
        victim.transfer(0);
    }
}`,
        remediationSolidity: `// Prefer a pause + withdraw pattern. If destruction is required,
// gate it on CALLER (msg.sender), not ORIGIN, and a stored owner.
function destroy(address payable to) external {
    require(msg.sender == owner, "owner");
    // On modern chains, selfdestruct no longer removes code (EIP-6780)
    // except in the creating transaction — do not rely on it for upgrades.
    selfdestruct(to);
}`,
        locationFn: "runtime",
        locationLine: null,
        snippet: snippetFor(ins, pc),
      }),
    );
  }

  // Fix 39: DELEGATECALL / CALLCODE are now separate findings whose
  // severity is set by OPERAND RESOLUTION, not presence. The presence
  // proof fork-verified the stored class (delegatecall sample 30/30
  // FP-as-high, callcode 72/72 FP-as-high): the real sites were
  // EIP-1167 clones, Safe singleton loads, EIP-1967 slot loads and
  // fixed library constants. A site whose target provably comes from
  // calldata is the exploitable shape and rates high; a site whose
  // target cannot be resolved keeps the Fix 33 presence-level low with
  // the gap named; every site resolving to a fixed target (constant,
  // known proxy slot, self) makes the finding informational.
  const targetResolutions = resolveCallTargets(codeIns);
  const callOps: { op: "DELEGATECALL" | "CALLCODE"; detector: string; count: number }[] = [
    { op: "DELEGATECALL", detector: "bytecode-delegatecall", count: deleg },
    { op: "CALLCODE", detector: "bytecode-callcode", count: callcode },
  ];
  for (const { op, detector, count } of callOps) {
    if (count === 0) continue;
    const sites = codeIns.filter((i) => i.name === op);
    const siteRes = sites.map(
      (s) => targetResolutions.get(s.pc) ?? ({ cls: "unresolved", why: "the site was outside the tracked stream" } as TargetResolution),
    );
    const dynamicSites = siteRes.filter((r) => r.cls === "calldata").length;
    const unresolvedSites = siteRes.filter((r) => r.cls === "unresolved");
    const fixedDesc: string[] = [];
    for (const r of siteRes) {
      if (r.cls === "constant") {
        fixedDesc.push(
          proxyMatch && r.address.toLowerCase() === `0x${(proxyMatch[1] ?? "").toLowerCase()}`
            ? `the EIP-1167 embedded implementation ${r.address}`
            : `fixed address ${r.address}`,
        );
      } else if (r.cls === "slot") fixedDesc.push(r.label);
      else if (r.cls === "self") fixedDesc.push("the contract itself (ADDRESS)");
    }
    const uniqueFixed = [...new Set(fixedDesc)];
    const fixedList = uniqueFixed.join("; ");
    const hasSlot = siteRes.some((r) => r.cls === "slot");
    const slotCaveat = hasSlot
      ? " A slot target's contents are set by whoever controls the slot's setter — bytecode cannot show that guard, so the residual risk lives in the setter, not in this call; confirm the setter is access-controlled."
      : "";
    const severity = dynamicSites > 0 ? "high" : unresolvedSites.length > 0 ? "low" : "info";
    const pc = sites[0]?.pc ?? 0;
    const isInfo = severity === "info";
    const isDynamic = severity === "high";
    findings.push(
      finding({
        severity,
        swc: "SWC-112",
        title: isInfo
          ? `${op} to a fixed target (${uniqueFixed.length === 1 ? (uniqueFixed[0] ?? "fixed target") : "fixed targets"})`
          : `${op} executes foreign code in this contract's storage`,
        confidence: "high",
        detector,
        summary: isInfo
          ? `Target resolved from the instruction stream: every ${op} site (${count}) targets ${fixedList}. A fixed target is the standard proxy / library shape — the callee is chosen at deployment, not by the caller — so the opcode's presence is informational, not a vulnerability.${op === "CALLCODE" ? " A genuine CALLCODE with a constant target is the pre-0.5 library-linkage shape; solc ≥0.5 and Vyper never emit CALLCODE." : ""}${slotCaveat}`
          : isDynamic
            ? `Target resolved from the instruction stream: at least one ${op} site takes its target from calldata. A caller-supplied target is exactly the exploitable shape — the callee runs with this contract's storage, balance, and msg.sender, so an attacker's code can overwrite storage arbitrarily. ${op} appears ${count} time${count === 1 ? "" : "s"} in this runtime.`
            : `Presence only: ${op} appears ${count} time${count === 1 ? "" : "s"} in this runtime. Presence is not a vulnerability — the callee runs with this contract's storage, balance, and msg.sender, which is exactly how standard proxies and library calls are supposed to work. It becomes an exploit when the target address is caller-supplied or writable. Target resolution: ${uniqueFixed.length > 0 ? `${count - unresolvedSites.length} of ${count} sites resolve to fixed targets (${fixedList}); ` : ""}the target operand could not be resolved at ${unresolvedSites.length} site${unresolvedSites.length === 1 ? "" : "s"} (${[...new Set(unresolvedSites.map((r) => (r.cls === "unresolved" ? r.why : "")))].join("; ")}) — severity stays at the presence level rather than dropping on an unproven negative.`,
        walkthrough: isInfo
          ? [
              `1. ${op} keeps the caller's storage and msg.sender, unlike CALL.`,
              `2. At every site the target resolves to ${fixedList} — fixed at deployment, not supplied by the caller, so no caller can redirect execution to attacker code through this site.`,
              hasSlot
                ? "3. The remaining question is the slot's setter: audit who can write the slot and whether that write is access-controlled."
                : "3. Audit the target contract instead: the risk lives in the code being called, and in whether that code can be replaced (metamorphic implementation) underneath this contract.",
              proxy ? `4. Proxy shape also detected: ${proxy}.` : "4. No EIP-1167 / EIP-1967 pattern was obvious — a fixed library-style call is the usual explanation for this shape.",
            ].join("\n")
          : [
              `1. ${op} keeps the caller's storage and msg.sender, unlike CALL.`,
              "2. A writable target (an argument, or a slot the caller can set) means the attacker deploys code that SSTOREs over owner, balances, or an implementation pointer.",
              "3. Even a fixed target is an upgrade footgun: that address's code is the implementation, and a metamorphic implementation changes the logic underneath.",
              proxy ? `4. Proxy shape also detected: ${proxy}. Confirm the implementation slot is not writable by arbitrary callers.` : "4. No EIP-1167 / EIP-1967 pattern was obvious — this may be an explicit delegatecall helper, which is higher risk than a standard proxy.",
            ].join("\n"),
        exploitSolidity: isInfo
          ? ""
          : `// 1. Malicious Implementation payload matching victim slot 0 layout
contract MultiStepSmash {
    address public owner;
    function seizeAndDrain(address token, address payable recipient) external {
        owner = msg.sender;
        if (address(this).balance > 0) {
            recipient.transfer(address(this).balance);
        }
        if (token != address(0)) {
            (bool ok, bytes memory balData) = token.staticcall(abi.encodeWithSignature("balanceOf(address)", address(this)));
            if (ok && balData.length >= 32) {
                uint256 bal = abi.decode(balData, (uint256));
                if (bal > 0) token.call(abi.encodeWithSignature("transfer(address,uint256)", recipient, bal));
            }
        }
    }
}

interface IVictim { function migrate(address impl, bytes calldata data) external; }

// 2. Orchestrator executing atomic takeover and drain
contract AdvancedTake {
    function go(address victim) external {
        MultiStepSmash smash = new MultiStepSmash();
        bytes memory payload = abi.encodeWithSignature("seizeAndDrain(address,address)", address(0), payable(msg.sender));
        IVictim(victim).migrate(address(smash), payload);
    }
}`,
        remediationSolidity: isInfo
          ? `// No change needed at this call site: the target is fixed at deployment.
// Audit the target contract itself, and gate any setter that can change
// the target or the slot it is loaded from.`
          : `// EIP-1967 Storage Slot Isolation + Strict Implementation Whitelist
bytes32 private constant _IMPLEMENTATION_SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
mapping(address => bool) public allowedImplementations;

function forward(address newImpl, bytes calldata data) external onlyOwner returns (bytes memory) {
    require(allowedImplementations[newImpl], "Unauthorized implementation");
    assembly { sstore(_IMPLEMENTATION_SLOT, newImpl) }
    (bool ok, bytes memory ret) = newImpl.delegatecall(data);
    require(ok, "Delegatecall failed");
    return ret;
}`,
        locationFn: "runtime",
        locationLine: null,
        snippet: snippetFor(ins, pc),
      }),
    );
  }

  if (origin > 0) {
    const pc = codeIns.find((i) => i.name === "ORIGIN")?.pc ?? 0;
    findings.push(
      finding({
        severity: "medium",
        swc: "SWC-115",
        title: "ORIGIN (tx.origin) is used",
        confidence: "high",
        detector: "bytecode-origin",
        summary: "The ORIGIN opcode reads tx.origin. Phishing contracts can satisfy an origin check while msg.sender is the attacker's contract.",
        walkthrough: [
          "1. ORIGIN is the externally owned account that signed the transaction. CALLER is the immediate caller.",
          "2. If a branch does ORIGIN / CALLER / EQ and then SELFDESTRUCT or CALL with value, a malicious contract the owner interacts with can forward the call and pass the check.",
          "3. Prefer SLOAD of an owner slot compared to CALLER.",
        ].join("\n"),
        exploitSolidity: `contract Phish {
    function lure(address victim) external {
        // Owner clicks this. tx.origin is the owner; victim sees CALLER = this contract.
        (bool ok, ) = victim.call(abi.encodeWithSignature("withdraw()"));
        ok;
    }
}`,
        remediationSolidity: `require(msg.sender == owner, "owner"); // CALLER, never ORIGIN`,
        locationFn: "runtime",
        locationLine: null,
        snippet: snippetFor(ins, pc),
      }),
    );
  }

  // Item 4: dedupe identical bytecode findings. The same CALL-popped
  // shape compiled N times (one per call site) is ONE grouped finding
  // reporting the count and every distinct location — not N identical
  // rows. Grouping key = detector + title shape (opcode name); every
  // grouped finding shares severity, SWC, summary template, walkthrough,
  // exploit, and remediation, so nothing material is merged away. All
  // pcs are listed in the summary/walkthrough; per-site snippets are
  // capped at 10 with a "+M more sites" note.
  const unchecked = uncheckedCalls(codeIns);
  const uncheckedByName = new Map<string, { pc: number }[]>();
  for (const hit of unchecked) {
    const group = uncheckedByName.get(hit.name) ?? [];
    group.push(hit);
    uncheckedByName.set(hit.name, group);
  }
  for (const [opName, hits] of uncheckedByName) {
    const pcs = hits.map((h) => `0x${h.pc.toString(16)}`);
    const countNote =
      hits.length > 1 ? ` Found at ${hits.length} sites (pcs ${pcs.join(", ")}).` : "";
    findings.push(
      finding({
        severity: "medium",
        swc: "SWC-104",
        title:
          hits.length > 1
            ? `${opName} return value is popped (×${hits.length})`
            : `${opName} return value is popped`,
        confidence: "medium",
        detector: "bytecode-unchecked-call",
        summary: `${opName} pushes a success flag and a following POP discards it before any ISZERO/JUMPI. A reverting callee looks like success.${countNote}`,
        walkthrough: [
          `1. ${opName} pushes 1 on success and 0 on failure. It does not revert the caller by itself.`,
          "2. The next instructions POP that flag, so both outcomes fall through.",
          "3. A callee that reverts (or returns false) still lets the caller continue into SSTORE or another value transfer.",
          ...(hits.length > 1 ? [`4. Call sites (pcs): ${pcs.join(", ")}.`] : []),
        ].join("\n"),
        exploitSolidity: `contract Reverts {
    receive() external payable { revert("no"); }
}
// If the victim pops the CALL result, sending value here still "succeeds"
// from the victim's point of view and accounting is updated anyway.`,
        remediationSolidity: `(bool ok, ) = target.call{value: amount}("");
require(ok, "call failed");`,
        locationFn: "runtime",
        locationLine: null,
        snippet:
          hits
            .slice(0, 10)
            .map((h) => `--- pc 0x${h.pc.toString(16)} ---\n${snippetFor(ins, h.pc)}`)
            .join("\n") +
          (hits.length > 10 ? `\n... and ${hits.length - 10} more sites (see walkthrough for all pcs)` : ""),
      }),
    );
  }

  if (calls > 0 && sstore > 0) {
    findings.push(
      finding({
        severity: "medium",
        swc: "SWC-107",
        title: "Both CALL and SSTORE are present",
        confidence: "low",
        detector: "bytecode-reentrancy-shape",
        summary: "The bytecode both performs external calls and writes storage. Order is not recovered precisely, so classic reentrancy cannot be ruled out. Review paths where CALL happens before SSTORE that debits the sender.",
        walkthrough: [
          "1. A reentrant callee gets control before the call returns.",
          "2. If the debit SSTORE is ordered after CALL, the second entry still sees the old credit and withdraws again.",
          "3. This finding is a shape warning, not a proof. A checks-effects-interactions ordering, or a reentrancy lock (SLOAD/SSTORE around the call), clears it.",
        ].join("\n"),
        exploitSolidity: `contract Reenter {
    uint256 n;
    receive() external payable {
        if (n++ < 3) {
            (bool ok, ) = msg.sender.call(abi.encodeWithSignature("withdraw()"));
            ok;
        }
    }
    function start(address victim) external payable {
        (bool ok, ) = victim.call{value: msg.value}(abi.encodeWithSignature("deposit()"));
        ok;
        (bool ok2, ) = victim.call(abi.encodeWithSignature("withdraw()"));
        ok2;
    }
}`,
        remediationSolidity: `uint256 private locked;
modifier nonReentrant() {
    require(locked == 0);
    locked = 1;
    _;
    locked = 0;
}`,
        locationFn: "runtime",
        locationLine: null,
        snippet: "",
      }),
    );
  }

  if (timestamp > 0) {
    const pc = codeIns.find((i) => i.name === "TIMESTAMP")?.pc ?? 0;
    findings.push(
      finding({
        severity: "low",
        swc: "SWC-116",
        title: "TIMESTAMP is read",
        confidence: "medium",
        detector: "bytecode-timestamp",
        summary: "block.timestamp is miner-influenced by a few seconds. Fine for long delays; unsafe as a randomness or exact-deadline source.",
        walkthrough: [
          "1. PREVRANDAO / BLOCKHASH nearby would make this a weak-randomness issue rather than a delay.",
          "2. A JUMPI on TIMESTAMP is an unlock or expiry. Confirm the window is hours, not one block.",
        ].join("\n"),
        exploitSolidity: `// A validator can nudge timestamp ~15s to win a one-block "random" check:
// uint256 roll = uint256(keccak256(abi.encode(block.timestamp))) % 100;`,
        remediationSolidity: `// Commit-reveal or a VRF. Do not hash block.timestamp for a winner.`,
        locationFn: "runtime",
        locationLine: null,
        snippet: snippetFor(ins, pc),
      }),
    );
  }

  if (create2 > 0) {
    findings.push(
      finding({
        severity: "info",
        swc: "SWC-106",
        title: "CREATE2 is present",
        confidence: "high",
        detector: "bytecode-create2",
        summary: "CREATE2 can redeploy different code to an address that previously selfdestructed (pre-EIP-6780, and still in the creating transaction). Treat the resulting address as untrusted unless you pin the init code hash.",
        walkthrough: ["1. Address = keccak(0xff, deployer, salt, initcodehash).", "2. If init code is caller-supplied, the attacker chooses the deployed bytecode."].join("\n"),
        exploitSolidity: "",
        remediationSolidity: `bytes32 expected = keccak256(type(Impl).creationCode);
require(keccak256(initCode) == expected, "init code");`,
        locationFn: "runtime",
        locationLine: null,
        snippet: "",
      }),
    );
  }

  if (meta.compiler) {
    const [maj, min] = meta.compiler.split(".").map((n) => Number(n));
    const v = (maj ?? 0) * 1_000_000 + (min ?? 0) * 1_000 + (Number(meta.compiler.split(".")[2]) || 0);
    if (v > 0 && v < 8_000) {
      findings.push(
        finding({
          // Fix 32: severity is low, matching the source-side
          // old-compiler note. The poll behind this batch found the
          // metadata/compiler family stored at critical/high ~1,300
          // times; the version alone exploits nothing.
          severity: "low",
          swc: "SWC-101",
          title: `Metadata reports solc ${meta.compiler}`,
          confidence: "high",
          detector: "bytecode-metadata",
          summary: "Compilers before 0.8.0 do not revert on overflow. Arithmetic in this bytecode is unchecked unless the source used SafeMath. This is a toolchain-hygiene note, not a vulnerability: the version alone exploits nothing — unchecked arithmetic is covered by its own findings.",
          walkthrough: ["1. The CBOR metadata suffix ends with the solc version as three bytes.", `2. Decoded version ${meta.compiler} is older than 0.8.0.`, "3. Balance updates that add msg.value can wrap."].join("\n"),
          exploitSolidity: `// On 0.7 and earlier, type(uint256).max + 1 == 0.
// A credit of type(uint256).max - 1 plus a 2-wei deposit wraps to 1.`,
          remediationSolidity: `pragma solidity ^0.8.24; // checked arithmetic by default`,
          locationFn: null,
          locationLine: null,
          snippet: "",
        }),
      );
    }
  }

  if (proxyMatch) {
    findings.push(
      finding({
        severity: "info",
        swc: null,
        title: "EIP-1167 minimal proxy",
        confidence: "high",
        detector: "bytecode-proxy",
        summary: proxy ?? "Minimal proxy clone.",
        walkthrough: [
          "1. The clone delegatecalls every call to the implementation baked into the bytecode.",
          "2. Audit the implementation, not the clone. If that implementation is upgradeable or metamorphic, every clone follows it.",
        ].join("\n"),
        exploitSolidity: "",
        remediationSolidity: "",
        locationFn: null,
        locationLine: null,
        snippet: "",
      }),
    );
  }

  const signals = SIGNAL_OPS.filter((name) => (counts.get(name) ?? 0) > 0).map((name) => ({
    name,
    count: counts.get(name) ?? 0,
  }));

  // Full census, NOT a top-N list: the Bytecode tab sums this array for
  // OPCODES PARSED and looks up sensitive opcodes (CALL, SELFDESTRUCT,
  // ...) by name. A top-14 slice made every opcode outside the top 14
  // read as 0 — a Deed with a real SELFDESTRUCT showed SELFDESTRUCT 0.
  const opcodes = [...counts.entries()]
    .sort((a, b) => b[1] - a[1])
    .map(([name, count]) => ({ name, count }));

  const inventory: Inventory = {
    inputKind: "bytecode",
    contractNames: proxy ? ["MinimalProxy"] : ["Runtime"],
    kindNote: meta.compiler ? `Runtime bytecode, solc ${meta.compiler}` : "Bytecode (no compiler metadata)",
    pragma: null,
    compiler: meta.compiler,
    functions: sels.map((s) => ({
      name: s.signature ?? s.selector,
      visibility: "external",
      mutability: "unknown",
      modifiers: [],
      line: null,
      params: s.signature?.slice(s.signature.indexOf("(") + 1, -1) ?? "",
    })),
    stateVars: [],
    events: [],
    inheritance: [],
    selectors: sels,
    reconstructed: reconstruct(sels),
    topics: topicsOf(codeIns),
    opcodes,
    signals,
    bytecodeBytes: code.length,
    basicBlocks: basicBlocks(codeIns),
    proxy,
    notes,
    disassembly: formatted.text,
  };

  return { inventory, findings };
}

function uncheckedCalls(ins: Instruction[]): { name: string; pc: number }[] {
  const calls = new Set(["CALL", "DELEGATECALL", "STATICCALL", "CALLCODE"]);
  const hits: { name: string; pc: number }[] = [];
  for (let i = 0; i < ins.length; i += 1) {
    const cur = ins[i];
    if (!cur || !calls.has(cur.name)) continue;
    let popped = false;
    let checked = false;
    for (let j = 1; j <= 4 && i + j < ins.length; j += 1) {
      const n = ins[i + j]?.name;
      if (n === "ISZERO" || n === "JUMPI") {
        checked = true;
        break;
      }
      if (n === "POP") {
        popped = true;
        break;
      }
    }
    if (popped && !checked) hits.push({ name: cur.name, pc: cur.pc });
  }
  return hits;
}

function emptyInventory(note: string): Inventory {
  return {
    inputKind: "bytecode",
    contractNames: [],
    kindNote: "Undecodable",
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
