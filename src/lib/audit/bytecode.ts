import { disassemble, formatDisassembly, type Instruction } from "./disassemble.ts";
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

function stripMetadata(code: Uint8Array): { body: Uint8Array; compiler: string | null; hasIpfs: boolean } {
  if (code.length < 4) return { body: code, compiler: null, hasIpfs: false };
  const len = ((code[code.length - 2] ?? 0) << 8) | (code[code.length - 1] ?? 0);
  if (len < 6 || len > code.length - 2) return { body: code, compiler: null, hasIpfs: false };
  const start = code.length - 2 - len;
  const first = code[start] ?? 0;
  if (first < 0xa0 || first > 0xbf) return { body: code, compiler: null, hasIpfs: false };
  const meta = code.slice(start, code.length - 2);
  const latin = String.fromCharCode(...meta);
  // Require positive evidence this tail is really compiler metadata.
  // Without this, any contract whose last 2 bytes happen to decode as a
  // plausible length + a CBOR-map first byte gets its tail instructions
  // silently cut — ~2-4% of metadata-less contracts. Real solc metadata
  // always carries a "solc" version entry plus an "ipfs" or "bzzr" hash.
  const hasSolcMarker = latin.includes("solc");
  const hasIpfsMarker = latin.includes("ipfs");
  const hasBzzrMarker = latin.includes("bzzr");
  if (!hasSolcMarker && !hasIpfsMarker && !hasBzzrMarker) {
    return { body: code, compiler: null, hasIpfs: false };
  }
  const idx = latin.indexOf("solc");
  let compiler: string | null = null;
  if (idx >= 0 && meta[idx + 4] === 0x43) {
    const major = meta[idx + 5] ?? 0;
    const minor = meta[idx + 6] ?? 0;
    const patch = meta[idx + 7] ?? 0;
    compiler = `${major}.${minor}.${patch}`;
  }
  const hasIpfs = latin.includes("ipfs");
  return { body: code.slice(0, start), compiler, hasIpfs };
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
  return hexToBytes(t) !== null && t.replace(/\s+/g, "").replace(/^0x/i, "").length >= 8;
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
  const counts = countOps(ins);
  const sels = selectorsOf(ins);
  const formatted = formatDisassembly(ins, 420);
  const hex = [...(meta.body.length ? meta.body : code)].map((b) => b.toString(16).padStart(2, "0")).join("");

  const notes: string[] = [];
  if (meta.compiler) notes.push(`Solidity metadata suffix decoded. Compiler ${meta.compiler}.`);
  else notes.push("No CBOR metadata suffix. This may be creation bytecode, a hand-written runtime, or metadata was stripped.");
  if (meta.hasIpfs) notes.push("Metadata includes an IPFS content hash (the compiler's source fingerprint, not the source itself).");
  notes.push(`${ins.length} instructions, ${code.length} input bytes${meta.body.length && meta.body.length !== code.length ? `, ${meta.body.length} after metadata strip` : ""}.`);
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

  const findings: Finding[] = [];
  const self = counts.get("SELFDESTRUCT") ?? 0;
  const deleg = counts.get("DELEGATECALL") ?? 0;
  const callcode = counts.get("CALLCODE") ?? 0;
  const origin = counts.get("ORIGIN") ?? 0;
  const calls = counts.get("CALL") ?? 0;
  const sstore = counts.get("SSTORE") ?? 0;
  const timestamp = counts.get("TIMESTAMP") ?? 0;
  const create2 = counts.get("CREATE2") ?? 0;

  if (self > 0) {
    const pc = ins.find((i) => i.name === "SELFDESTRUCT")?.pc ?? 0;
    findings.push(
      finding({
        severity: "high",
        swc: "SWC-106",
        title: "SELFDESTRUCT is reachable in the bytecode",
        confidence: "high",
        detector: "bytecode-selfdestruct",
        summary: `The runtime executes SELFDESTRUCT ${self} time${self === 1 ? "" : "s"}. Without source, Kiln cannot prove an access check dominates it. Anyone who can satisfy the preceding branch can delete the contract and send the balance away.`,
        walkthrough: [
          "1. SELFDESTRUCT (0xff) sends the contract's entire balance to the address on the stack and removes the code from the state.",
          "2. The instruction is present in this bytecode, so some execution path can reach it. A dispatcher that compares CALLER to a stored owner would usually show SLOAD + EQ + JUMPI before it — confirm that pattern actually guards this pc.",
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

  if (deleg > 0 || callcode > 0) {
    const op = deleg > 0 ? "DELEGATECALL" : "CALLCODE";
    const pc = ins.find((i) => i.name === op)?.pc ?? 0;
    findings.push(
      finding({
        severity: "high",
        swc: "SWC-112",
        title: `${op} executes foreign code in this contract's storage`,
        confidence: "high",
        detector: deleg > 0 ? "bytecode-delegatecall" : "bytecode-callcode",
        summary: `${op} appears ${deleg + callcode} time${deleg + callcode === 1 ? "" : "s"}. The callee runs with this contract's storage, balance, and msg.sender. If the target address is caller-controlled, storage can be overwritten arbitrarily.`,
        walkthrough: [
          `1. ${op} keeps the caller's storage and msg.sender, unlike CALL.`,
          "2. A writable target (an argument, or a slot the caller can set) means the attacker deploys code that SSTOREs over owner, balances, or an implementation pointer.",
          "3. Even a fixed target is an upgrade footgun: that address's code is the implementation, and a metamorphic implementation changes the logic underneath.",
          proxy ? `4. Proxy shape also detected: ${proxy}. Confirm the implementation slot is not writable by arbitrary callers.` : "4. No EIP-1167 / EIP-1967 pattern was obvious — this may be an explicit delegatecall helper, which is higher risk than a standard proxy.",
        ].join("\n"),
        exploitSolidity: `// 1. Malicious Implementation payload matching victim slot 0 layout
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
        remediationSolidity: `// EIP-1967 Storage Slot Isolation + Strict Implementation Whitelist
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
    const pc = ins.find((i) => i.name === "ORIGIN")?.pc ?? 0;
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
  const unchecked = uncheckedCalls(ins);
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
    const pc = ins.find((i) => i.name === "TIMESTAMP")?.pc ?? 0;
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
          severity: "high",
          swc: "SWC-101",
          title: `Metadata reports solc ${meta.compiler}`,
          confidence: "high",
          detector: "bytecode-metadata",
          summary: "Compilers before 0.8.0 do not revert on overflow. Arithmetic in this bytecode is unchecked unless the source used SafeMath.",
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
    topics: topicsOf(ins),
    opcodes,
    signals,
    bytecodeBytes: code.length,
    basicBlocks: basicBlocks(ins),
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
