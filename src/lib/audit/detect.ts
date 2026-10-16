import type { AstNode, Finding, Severity } from "./types";
import type { ContractModel, FnModel, ModModel, SourceModel, StateVar } from "./model";
import { withAccessControlCap } from "./severity-calibration";

type ExtKind =
  | "call"
  | "delegatecall"
  | "staticcall"
  | "callcode"
  | "send"
  | "transfer"
  | "erc20"
  | "member"
  | "selfdestruct";

type ExtCall = {
  kind: ExtKind;
  line: number;
  checked: boolean;
  sendsValue: boolean;
  target: string;
  targetIsParam: boolean;
  targetIsConst: boolean;
  argCount: number;
  raw: string;
};

type Flow = {
  seen: ExtCall | null;
  sawWrite: boolean;
  sawCall: boolean;
  callThenWrite: boolean;
  writeThenCall: boolean;
};

const ASSIGN = new Set(["=", "+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", "<<=", ">>="]);
const LOW_LEVEL = new Set(["call", "delegatecall", "staticcall", "callcode", "send", "transfer"]);
const BUILTIN = new Set([
  "require", "assert", "revert", "keccak256", "sha256", "ripemd160", "ecrecover",
  "addmod", "mulmod", "gasleft", "blockhash", "encode", "encodePacked",
  "encodeWithSignature", "encodeWithSelector", "encodeCall", "concat", "push", "pop",
]);

const PRIVILEGED = /^(owner|admin|governor|implementation|pendingOwner|operator|oracle|beacon|logic|feeRecipient|treasury)$/;

function lineOf(node: AstNode | undefined, delta: number, fallback: number): number {
  const raw = node?.loc?.start.line ?? fallback + delta;
  return Math.max(1, raw - delta);
}

function sliceOf(source: string, node: AstNode | undefined): string {
  if (!node?.range) return "";
  return source.slice(node.range[0], node.range[1]).replace(/\s+/g, " ").trim();
}

function snippet(source: string, astLine: number, delta: number): string {
  const lines = source.split("\n");
  const start = Math.max(0, astLine - 5);
  const end = Math.min(lines.length, astLine + 4);
  return lines
    .slice(start, end)
    .map((text, i) => {
      const raw = start + i + 1;
      const mark = raw === astLine ? ">" : " ";
      return `${mark} ${String(Math.max(1, raw - delta)).padStart(4, " ")}  ${text}`;
    })
    .join("\n");
}

function rootIdent(node: AstNode | undefined): string | null {
  if (!node) return null;
  if (node.type === "Identifier" && typeof node.name === "string") return node.name;
  if (node.type === "IndexAccess") return rootIdent(node.base as AstNode);
  if (node.type === "MemberAccess") return rootIdent(node.expression as AstNode);
  if (node.type === "FunctionCall") return rootIdent(node.expression as AstNode);
  if (node.type === "TupleExpression") return null;
  return null;
}

function unwrapCallee(expr: AstNode): { member: string | null; base: AstNode | null; named?: AstNode } {
  if (expr.type === "NameValueExpression") {
    const inner = expr.expression as AstNode;
    const next = unwrapCallee(inner);
    return { ...next, named: (expr.arguments as AstNode) ?? next.named };
  }
  if (expr.type === "MemberAccess") {
    return { member: String(expr.memberName ?? ""), base: expr.expression as AstNode };
  }
  if (expr.type === "Identifier") return { member: String(expr.name ?? ""), base: null };
  return { member: null, base: null };
}

function namedValue(named: AstNode | undefined, key: string): boolean {
  if (!named || !Array.isArray(named.names)) return false;
  return (named.names as string[]).includes(key);
}

function isAuthed(fn: FnModel): boolean {
  if (fn.modifiers.some((m) => /onlyowner|onlyadmin|onlyrole|onlygovernor|onlyauth|requiresauth|authorized|onlyminter|onlyoperator|onlyguardian/i.test(m))) {
    return true;
  }
  const src = fn.source;
  if (/_checkOwner\s*\(|_requireOwner\s*\(|onlyOwner\s*\(/.test(src)) return true;
  if (/msg\.sender\s*==\s*[A-Za-z_]/.test(src) && !/tx\.origin/.test(src)) return true;
  if (/require\s*\(\s*msg\.sender\s*==/.test(src)) return true;
  return false;
}

function hasGuard(fn: FnModel): boolean {
  return fn.modifiers.some((m) => /nonreentrant|noreentrant|reentrancyguard/i.test(m));
}

function usesCredit(fn: FnModel): boolean {
  return /balances\s*\[|_balances\s*\[|deposits\s*\[|credits\s*\[/.test(fn.source);
}

let seq = 0;
function make(
  partial: Omit<Finding, "id">,
): Finding {
  seq += 1;
  return { id: `s${seq}`, ...partial };
}

export function detectSource(model: SourceModel, displaySource: string): Finding[] {
  seq = 0;
  const findings: Finding[] = [];
  const seen = new Set<string>();
  const push = (f: Finding) => {
    const key = `${f.detector}|${f.locationFn}|${f.locationLine}|${f.title}`;
    if (seen.has(key)) return;
    seen.add(key);
    findings.push(f);
  };

  const parsed = model.parsedSource;
  const delta = model.lineDelta;

  if (/[\u202A-\u202E\u2066-\u2069]/.test(displaySource)) {
    push(make({
      severity: "high",
      swc: "SWC-130",
      title: "Bidirectional-override characters in the source",
      confidence: "high",
      detector: "rtl-override",
      summary: "The paste contains Unicode bidi overrides (U+202A–U+202E or isolates). They can make a reviewer read an address or a name backwards.",
      walkthrough: "1. Strip the source to ASCII and re-read every address literal.\n2. A right-to-left override inside a comment or string can hide the real callee.",
      exploitSolidity: "",
      remediationSolidity: "// Reject the file. Re-type literals by hand from a known-good copy.",
      locationFn: null,
      locationLine: null,
      snippet: "",
    }));
  }

  if (model.floatingPragma && model.pragma) {
    push(make({
      severity: "low",
      swc: "SWC-103",
      title: "Floating pragma",
      confidence: "high",
      detector: "floating-pragma",
      summary: `Pragma \`${model.pragma}\` does not pin a compiler. A later solc in that range can change bytecode, metadata, or bug exposure.`,
      walkthrough: "1. Floating constraints (^, >=, <) let the build pick whatever solc the environment has.\n2. Pin the exact version you audited, and commit the compiler settings.",
      exploitSolidity: "",
      remediationSolidity: `pragma solidity ${model.versionFloor ? formatVer(model.versionFloor) : "0.8.24"};`,
      locationFn: null,
      locationLine: 1,
      snippet: snippet(parsed, 1 + delta, delta),
    }));
  }

  if (model.versionFloor !== null && model.versionFloor < 8_000) {
    push(make({
      severity: "high",
      swc: "SWC-101",
      title: "Compiler is older than 0.8.0",
      confidence: "high",
      detector: "old-compiler",
      summary: "Solidity before 0.8.0 does not revert on overflow or underflow. Any balance math without SafeMath can wrap.",
      walkthrough: [
        "1. `balances[msg.sender] += msg.value` wraps at 2^256-1.",
        "2. A balance near the max, plus a small deposit, becomes a tiny balance and breaks the invariant.",
        "3. Underflow on a subtraction is the usual stolen-credit path: `0 - 1` becomes the maximum uint.",
      ].join("\n"),
      exploitSolidity: `// 0.7.6 arithmetic
uint256 credit = type(uint256).max - 1;
credit += 2; // equals 1. The deposit was not rejected.`,
      remediationSolidity: "pragma solidity ^0.8.24;\n// or wrap every balance update in SafeMath on 0.7.x",
      locationFn: null,
      locationLine: 1,
      snippet: "",
    }));
  }

  if (model.versionFloor !== null && model.versionFloor < 5_000) {
    const defaults = model.contracts.flatMap((c) => c.functions.filter((f) => f.visibility === "default" && !f.isConstructor));
    if (defaults.length) {
      push(make({
        severity: "high",
        swc: "SWC-100",
        title: "Functions default to public",
        confidence: "high",
        detector: "default-visibility",
        summary: `Before 0.5.0 a function with no visibility is public. ${defaults.map((f) => f.name).join(", ")} ${defaults.length === 1 ? "is" : "are"} callable by anyone.`,
        walkthrough: "1. The compiler treats the missing keyword as public, not internal.\n2. A helper that moves ether or sets storage is then an external entrypoint.",
        exploitSolidity: "",
        remediationSolidity: "function helper() internal { /* ... */ }",
        locationFn: defaults[0]?.name ?? null,
        locationLine: defaults[0]?.line ?? null,
        snippet: "",
      }));
    }
  }

  for (const contract of model.contracts) {
    if (contract.kind === "interface") continue;
    scanContract(contract, model, parsed, delta, push);
  }

  const rank: Record<Severity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  findings.sort((a, b) => rank[a.severity] - rank[b.severity] || (a.locationLine ?? 0) - (b.locationLine ?? 0));
  return findings.slice(0, 40);
}

function formatVer(v: number): string {
  const major = Math.floor(v / 1_000_000);
  const minor = Math.floor((v % 1_000_000) / 1_000);
  const patch = v % 1_000;
  return `${major}.${minor}.${patch}`;
}

function scanContract(
  contract: ContractModel,
  model: SourceModel,
  parsed: string,
  delta: number,
  push: (f: Finding) => void,
) {
  const stateNames = new Set(contract.stateVars.map((v) => v.name));
  const byName = new Map(contract.functions.map((f) => [f.name, f]));

  const direct = new Map<string, { writes: Set<string>; external: boolean; callees: Set<string> }>();
  for (const fn of contract.functions) {
    direct.set(fn.name, profile(fn, stateNames, byName));
  }
  // Fixpoint: internal calls inherit writes and external-ness.
  let moved = true;
  while (moved) {
    moved = false;
    for (const fn of contract.functions) {
      const row = direct.get(fn.name);
      if (!row) continue;
      for (const callee of row.callees) {
        const other = direct.get(callee);
        if (!other) continue;
        if (other.external && !row.external) {
          row.external = true;
          moved = true;
        }
        for (const w of other.writes) {
          if (!row.writes.has(w)) {
            row.writes.add(w);
            moved = true;
          }
        }
      }
    }
  }

  for (const mod of contract.modifiers) {
    if (/tx\.origin/.test(mod.source)) {
      push(make({
        severity: "high",
        swc: "SWC-115",
        title: `Modifier ${mod.name} trusts tx.origin`,
        confidence: "high",
        detector: "tx-origin",
        summary: "An authorization modifier compares tx.origin. Any contract the authorized account calls can forward into a protected function.",
        walkthrough: originWalk(mod.name),
        exploitSolidity: originExploit(contract.name, "withdraw"),
        remediationSolidity: originFix(),
        locationFn: mod.name,
        locationLine: mod.line,
        snippet: mod.source.split("\n").slice(0, 12).join("\n"),
      }));
    }
  }

  let anyPayable = false;
  let anyValueSend = false;
  const reenterWrites = new Map<string, { fn: string; call: ExtCall }>();

  for (const fn of contract.functions) {
    if (fn.mutability === "payable" || fn.isReceive) anyPayable = true;
    if (!fn.body) continue;
    const authed = isAuthed(fn) || fn.isConstructor;
    const flow = walkFn(fn, contract, model, stateNames, byName, direct, parsed, delta, push, authed);
    if (flow.sawCall && flowSends(flow)) anyValueSend = true;
    if (/(\.call\s*\{[^}]*value|\.transfer\s*\(|\.send\s*\()/.test(fn.source)) anyValueSend = true;

    if (flow.callThenWrite && flow.seen) {
      const guarded = hasGuard(fn);
      const severity: Severity = guarded
        ? "low"
        : flow.seen.sendsValue || flow.seen.kind === "call" || flow.seen.kind === "delegatecall"
          ? "critical"
          : flow.seen.kind === "member" || flow.seen.kind === "erc20"
            ? "medium"
            : "high";
      push(withAccessControlCap(make({
        severity,
        swc: "SWC-107",
        title: guarded
          ? `State is written after an external call in ${fn.name}, but a reentrancy guard is present`
          : `Reentrancy: ${fn.name} updates state after an external call`,
        confidence: guarded ? "medium" : "high",
        detector: "reentrancy",
        summary: guarded
          ? `${fn.name} still does the external call before the storage update. The guard should hold, but the ordering is the bug the guard is papering over.`
          : `${fn.name} hands control to another contract at line ${flow.seen.line}, then writes storage. The callee can re-enter and observe the stale values.`,
        walkthrough: reentrancyWalk(contract.name, fn, flow.seen),
        exploitSolidity: reentrancyExploit(contract.name, fn.name),
        remediationSolidity: reentrancyFix(fn.name),
        locationFn: fn.name,
        locationLine: flow.seen.line,
        snippet: snippet(parsed, flow.seen.line + delta, delta),
      }), authed));
      for (const w of direct.get(fn.name)?.writes ?? []) reenterWrites.set(w, { fn: fn.name, call: flow.seen });
    } else if (flow.writeThenCall && flow.sawCall && /for\s*\(|while\s*\(/.test(fn.source)) {
      push(make({
        severity: "medium",
        swc: "SWC-107",
        title: `External call inside a loop in ${fn.name}`,
        confidence: "medium",
        detector: "reentrancy",
        summary: "The loop both writes storage and calls out. Even if this iteration updates first, the callback can re-enter before later iterations finish.",
        walkthrough: reentrancyWalk(contract.name, fn, flow.seen),
        exploitSolidity: reentrancyExploit(contract.name, fn.name),
        remediationSolidity: reentrancyFix(fn.name),
        locationFn: fn.name,
        locationLine: fn.line,
        snippet: snippet(parsed, fn.line + delta, delta),
      }));
    }

    scanSimple(fn, contract, model, parsed, delta, authed, push);
  }

  for (const [varName, info] of reenterWrites) {
    const variable = contract.stateVars.find((v) => v.name === varName);
    if (variable?.visibility === "public") {
      push(make({
        severity: "high",
        swc: "SWC-107",
        title: `Read-only reentrancy on ${varName}()`,
        confidence: "medium",
        detector: "read-only-reentrancy",
        summary: `${info.fn} calls out before ${varName} is updated, and ${varName} is a public getter. A view consumer (a vault, a price, a collateral check) can read the stale value mid-callback.`,
        walkthrough: [
          `1. ${info.fn} transfers control at line ${info.call.line} via ${info.call.kind}.`,
          `2. ${varName} still holds the pre-call value, because the write happens after the call returns.`,
          `3. The attacker's receive() calls a second protocol whose quote reads ${contract.name}.${varName}().`,
          "4. That second protocol prices collateral or shares off the stale number and can be borrowed against.",
        ].join("\n"),
        exploitSolidity: `interface IVictim { function ${varName}(address) external view returns (uint256); function ${info.fn}() external; }
interface ILender { function borrowAgainst(address vault, address user) external; }
contract ReadOnlyAttack {
    function attack(address victim, address lender) external {
        IVictim(victim).${info.fn}();
    }
    receive() external payable {
        ILender(msg.sender).borrowAgainst(msg.sender, address(this));
    }
}`,
        remediationSolidity: `// Update ${varName} before the call, and add a nonReentrant guard
// so view methods used as oracles are not observable mid-call.
modifier nonReentrant() {
    require(locked == 0);
    locked = 1;
    _;
    locked = 0;
}`,
        locationFn: `${varName}()`,
        locationLine: variable.line,
        snippet: snippet(parsed, variable.line + delta, delta),
      }));
    }
  }

  if (anyPayable && !anyValueSend) {
    push(make({
      severity: "medium",
      swc: "SWC-132",
      title: `${contract.name} can receive ether it cannot send`,
      confidence: "medium",
      detector: "locked-ether",
      summary: "A payable function, receive, or fallback accepts ETH, and nothing in the contract transfers value out. The balance is stuck.",
      walkthrough: "1. Ether arrives through a payable entry.\n2. No call{value}, transfer, or send exists on this contract.\n3. There is no recovery path. Selfdestruct elsewhere does not help once the code is deployed.",
      exploitSolidity: "",
      remediationSolidity: `function rescue(address payable to) external onlyOwner {
    (bool ok, ) = to.call{value: address(this).balance}("");
    require(ok);
}`,
      locationFn: null,
      locationLine: contract.line,
      snippet: "",
    }));
  }

  const ownerDrain = contract.functions.some((fn) => isAuthed(fn) && /address\(this\)\.balance/.test(fn.source) && /\.call\{|\.transfer\(/.test(fn.source));
  if (ownerDrain) {
    push(make({
      severity: "low",
      swc: null,
      title: `${contract.name} lets one privileged key move the whole balance`,
      confidence: "high",
      detector: "centralization",
      summary: "An authenticated function can forward address(this).balance. That is a rug path if the key is an EOA, a hot wallet, or a single signer.",
      walkthrough: "1. The function is gated, so this is not an unauthenticated theft.\n2. It is still a single point of failure: the key, not the rules, controls user funds.\n3. A timelock, a multisig, or a capped withdrawal changes the trust assumption.",
      exploitSolidity: "",
      remediationSolidity: `// Two-step: queue the withdrawal, execute after a delay.
// Or cap it: require(amount <= address(this).balance / 10);`,
      locationFn: null,
      locationLine: contract.line,
      snippet: "",
    }));
  }

  if (contract.bases.some((b) => /upgrade|proxy|erc1967/i.test(b)) && !contract.stateVars.some((v) => v.name === "__gap")) {
    push(make({
      severity: "low",
      swc: null,
      title: `${contract.name} looks upgradeable and has no storage gap`,
      confidence: "low",
      detector: "storage-gap",
      summary: "Inheritance from a proxy/upgrade base without a uint256[N] __gap means a later variable shifts every slot in child contracts.",
      walkthrough: "1. Upgradeable layouts are append-only.\n2. Inserting a variable in a base contract moves the child's slots and silently corrupts balances.\n3. Reserve a gap and shrink it when you add a variable.",
      exploitSolidity: "",
      remediationSolidity: "uint256[50] private __gap;",
      locationFn: null,
      locationLine: contract.line,
      snippet: "",
    }));
  }
}

function flowSends(flow: Flow): boolean {
  return Boolean(flow.seen?.sendsValue);
}

function profile(fn: FnModel, stateNames: Set<string>, byName: Map<string, FnModel>) {
  const writes = new Set<string>();
  const callees = new Set<string>();
  let external = false;
  const visit = (node: unknown) => {
    if (!node || typeof node !== "object") return;
    if (Array.isArray(node)) {
      node.forEach(visit);
      return;
    }
    const n = node as AstNode;
    if (n.type === "BinaryOperation" && typeof n.operator === "string" && ASSIGN.has(n.operator)) {
      const id = rootIdent(n.left as AstNode);
      if (id && stateNames.has(id)) writes.add(id);
    }
    if (n.type === "UnaryOperation" && (n.operator === "++" || n.operator === "--" || n.operator === "delete")) {
      const id = rootIdent(n.subExpression as AstNode);
      if (id && stateNames.has(id)) writes.add(id);
    }
    if (n.type === "FunctionCall") {
      const callee = unwrapCallee(n.expression as AstNode);
      if (callee.member && LOW_LEVEL.has(callee.member)) external = true;
      if (callee.member === "push" || callee.member === "pop") {
        const id = rootIdent(callee.base ?? undefined);
        if (id && stateNames.has(id)) writes.add(id);
      }
      if (!callee.base && callee.member && byName.has(callee.member) && callee.member !== fn.name) {
        callees.add(callee.member);
      }
      if (callee.base && rootIdent(callee.base) === "this") external = true;
    }
    if (n.type === "AssemblyCall" && n.functionName === "sstore") writes.add("*");
    for (const [k, v] of Object.entries(n)) {
      if (k === "loc" || k === "range") continue;
      if (v && typeof v === "object") visit(v);
    }
  };
  visit(fn.body);
  return { writes, external, callees };
}

function walkFn(
  fn: FnModel,
  contract: ContractModel,
  model: SourceModel,
  stateNames: Set<string>,
  byName: Map<string, FnModel>,
  direct: Map<string, { writes: Set<string>; external: boolean; callees: Set<string> }>,
  parsed: string,
  delta: number,
  push: (f: Finding) => void,
  authed: boolean,
): Flow {
  const flow: Flow = { seen: null, sawWrite: false, sawCall: false, callThenWrite: false, writeThenCall: false };
  const consts = new Set(contract.stateVars.filter((v) => v.constOrImmutable).map((v) => v.name));
  const params = new Set(fn.params.map((p) => p.name).filter(Boolean));

  const noteWrite = (node: AstNode | undefined) => {
    const id = rootIdent(node);
    const assembly = node?.type === "AssemblyCall";
    if (!assembly && (!id || !stateNames.has(id))) return;
    flow.sawWrite = true;
    if (flow.seen) flow.callThenWrite = true;
  };

  const noteCall = (call: ExtCall) => {
    flow.sawCall = true;
    if (flow.sawWrite && !flow.callThenWrite) flow.writeThenCall = true;
    if (!flow.seen) flow.seen = call;
    if (!call.checked && (call.kind === "call" || call.kind === "send" || call.kind === "delegatecall" || call.kind === "staticcall" || call.kind === "callcode")) {
      push(make({
        severity: call.kind === "send" ? "medium" : "high",
        swc: "SWC-104",
        title: `${fn.name} ignores the ${call.kind} result`,
        confidence: "high",
        detector: "unchecked-call",
        summary: `The ${call.kind} at line ${call.line} is used as a statement. A false or revert from the callee does not stop the rest of ${fn.name}.`,
        walkthrough: [
          `1. \`.call\`, \`.send\`, \`.delegatecall\` return false on failure. They do not revert the caller.`,
          "2. Discarding that bool means the following state update runs anyway.",
          "3. For an ether payout, the accounting says the user was paid when they were not — or the reverse, if the update already happened and a later assumption depends on success.",
        ].join("\n"),
        exploitSolidity: `contract Reject {
    receive() external payable { revert("nope"); }
}
// Point the payout at this contract. The victim still records the withdrawal.`,
        remediationSolidity: `(bool ok, ) = target.call{value: amount}("");
require(ok, "transfer failed");`,
        locationFn: fn.name,
        locationLine: call.line,
        snippet: snippet(parsed, call.line + delta, delta),
      }));
    }
    if (call.kind === "delegatecall" || call.kind === "callcode") {
      const severity: Severity = call.targetIsParam ? "critical" : call.targetIsConst ? "medium" : "high";
      push(withAccessControlCap(make({
        severity,
        swc: "SWC-112",
        title: call.targetIsParam
          ? `${fn.name} delegatecalls a caller-supplied address`
          : `${fn.name} delegatecalls ${call.target || "another contract"}`,
        confidence: "high",
        detector: "delegatecall",
        summary: "Delegatecall runs the target's code against this contract's storage. A writable target can overwrite owner, balances, or any other slot.",
        walkthrough: delegateWalk(fn.name, call),
        exploitSolidity: delegateExploit(contract.name),
        remediationSolidity: `address public immutable implementation;\nfunction exec(bytes calldata data) external onlyOwner {
    (bool ok, ) = implementation.delegatecall(data);
    require(ok);
}`,
        locationFn: fn.name,
        locationLine: call.line,
        snippet: snippet(parsed, call.line + delta, delta),
      }), authed));
    }
    if (call.kind === "erc20" && !call.checked) {
      push(make({
        severity: "high",
        swc: "SWC-104",
        title: `${fn.name} ignores an ERC-20 bool`,
        confidence: "medium",
        detector: "erc20-unchecked",
        summary: "transfer or transferFrom is used as a statement. Tokens that return false instead of reverting (including some USDT-like tokens, and any token that can fail a fee) look successful.",
        walkthrough: "1. The ERC-20 spec allows returning false.\n2. A statement-level call discards the bool.\n3. The contract then mints credit, releases collateral, or burns a position the token never moved.",
        exploitSolidity: `contract FalseToken {
    function transfer(address, uint256) external pure returns (bool) { return false; }
}`,
        remediationSolidity: `import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
using SafeERC20 for IERC20;
token.safeTransfer(to, amount);`,
        locationFn: fn.name,
        locationLine: call.line,
        snippet: snippet(parsed, call.line + delta, delta),
      }));
    }
    if ((call.kind === "transfer" || call.kind === "send") && call.sendsValue) {
      push(make({
        severity: "low",
        swc: "SWC-134",
        title: `${fn.name} forwards ether with a 2300-gas stipend`,
        confidence: "high",
        detector: "eth-gas-stipend",
        summary: "address.transfer and address.send forward 2300 gas. A receiving contract whose fallback uses more than that — a cold SLOAD is enough after Berlin — cannot be paid, and send's false return is easy to ignore.",
        walkthrough: "1. The stipend was meant as a reentrancy mitigation. It is not enough anymore, and it breaks legitimate receivers.\n2. Use call{value} and a reentrancy guard, and check the bool.",
        exploitSolidity: "",
        remediationSolidity: `(bool ok, ) = to.call{value: amount}("");
require(ok, "pay");`,
        locationFn: fn.name,
        locationLine: call.line,
        snippet: snippet(parsed, call.line + delta, delta),
      }));
    }
  };

  const noteExpr = (expr: unknown, asStatement: boolean) => {
    if (!expr || typeof expr !== "object") return;
    const node = expr as AstNode;
    if (node.type === "BinaryOperation" && typeof node.operator === "string" && ASSIGN.has(node.operator)) {
      noteExpr(node.right, false);
      noteWrite(node.left as AstNode);
      return;
    }
    if (node.type === "UnaryOperation" && (node.operator === "++" || node.operator === "--" || node.operator === "delete")) {
      noteWrite(node.subExpression as AstNode);
      return;
    }
    if (node.type === "FunctionCall") {
      const args = (node.arguments as unknown[]) ?? [];
      args.forEach((a) => noteExpr(a, false));
      const callee = unwrapCallee(node.expression as AstNode);
      const member = callee.member;
      if (member && (LOW_LEVEL.has(member) || member === "selfdestruct" || member === "suicide" || (!BUILTIN.has(member) && callee.base))) {
        const baseName = rootIdent(callee.base ?? undefined);
        const target = sliceOf(parsed, callee.base ?? undefined);
        const sendsValue = namedValue(callee.named, "value") || member === "transfer" || member === "send";
        let kind: ExtKind = "member";
        if (member === "call") kind = "call";
        else if (member === "delegatecall") kind = "delegatecall";
        else if (member === "staticcall") kind = "staticcall";
        else if (member === "callcode") kind = "callcode";
        else if (member === "send") kind = "send";
        else if (member === "transfer" && args.length <= 1) kind = "transfer";
        else if (member === "transfer" || member === "transferFrom") kind = "erc20";
        else if (member === "selfdestruct" || member === "suicide") kind = "selfdestruct";
        else if (rootIdent(callee.base ?? undefined) === "this" || (baseName && !stateNames.has(baseName) && baseName !== "abi" && baseName !== "msg" && baseName !== "block")) {
          kind = "member";
        } else if (baseName && stateNames.has(baseName)) kind = "member";
        else kind = "member";

        const isLow = kind === "call" || kind === "delegatecall" || kind === "staticcall" || kind === "callcode" || kind === "send" || kind === "transfer" || kind === "selfdestruct" || kind === "erc20";
        const internal = !callee.base && member && byName.has(member);
        if (!internal && (isLow || kind === "member") && member && !BUILTIN.has(member)) {
          // Skip obvious value-type methods and type conversions.
          if (member !== "push" && member !== "pop") {
            const checked = kind === "transfer" || kind === "selfdestruct" ? true : !asStatement;
            noteCall({
              kind,
              line: lineOf(node, delta, fn.line),
              checked,
              sendsValue: sendsValue && kind !== "erc20",
              target,
              targetIsParam: Boolean(baseName && (params.has(baseName) || baseName === "msg")),
              targetIsConst: Boolean(baseName && consts.has(baseName)),
              argCount: args.length,
              raw: sliceOf(parsed, node),
            });
          }
        }
        if ((member === "push" || member === "pop") && baseName && stateNames.has(baseName)) noteWrite(callee.base ?? undefined);
        if (internal && member) {
          const info = direct.get(member);
          if (info?.external) {
            noteCall({
              kind: "call",
              line: lineOf(node, delta, fn.line),
              checked: true,
              sendsValue: true,
              target: member,
              targetIsParam: false,
              targetIsConst: false,
              argCount: args.length,
              raw: member + "()",
            });
          }
          if (info && info.writes.size > 0) {
            flow.sawWrite = true;
            if (flow.seen) flow.callThenWrite = true;
          }
        }
      }
      if (namedValue(callee.named, "gas")) {
        push(make({
          severity: "low",
          swc: "SWC-134",
          title: `${fn.name} sets a fixed gas stipend`,
          confidence: "medium",
          detector: "hardcoded-gas",
          summary: "A named `gas:` argument caps the callee. If the cap is too low the call fails; if the failure is ignored, state still updates.",
          walkthrough: "1. The `gas` option replaces the 63/64 rule with a hard cap.\n2. Opcode repricing (EIP-2929 and later) makes old constants wrong.",
          exploitSolidity: "",
          remediationSolidity: `// Omit gas: unless you have a measured, documented reason.\n(bool ok, ) = target.call{value: amount}(data);\nrequire(ok);`,
          locationFn: fn.name,
          locationLine: lineOf(node, delta, fn.line),
          snippet: snippet(parsed, (node.loc?.start.line ?? fn.line + delta), delta),
        }));
      }
      if (member === "encodePacked" && args.length >= 2) {
        const dynamic = args.some((a) => {
          const id = rootIdent(a as AstNode);
          const p = fn.params.find((x) => x.name === id);
          const s = contract.stateVars.find((x) => x.name === id);
          const t = p?.typeName ?? s?.typeName ?? "";
          return /string|bytes|\[\]/.test(t) && !/bytes32|bytes16|bytes4/.test(t);
        });
        if (dynamic) {
          push(make({
            severity: "medium",
            swc: "SWC-133",
            title: `${fn.name} hashes abi.encodePacked dynamic arguments`,
            confidence: "medium",
            detector: "encode-packed",
            summary: "encodePacked concatenates without lengths. Two dynamic values (string, bytes, arrays) can be rearranged by the caller so different inputs share one hash.",
            walkthrough: [
              "1. encodePacked(string a, string b) is just the raw bytes of a followed by b.",
              '2. ("ab","c") and ("a","bc") produce the same payload and the same keccak.',
              "3. If that hash is a signature preimage, an allowance, or a commitment, the collision is the exploit.",
            ].join("\n"),
            exploitSolidity: `// Both hash to the same digest:
keccak256(abi.encodePacked("ab", "c"));
keccak256(abi.encodePacked("a", "bc"));`,
            remediationSolidity: `bytes32 hash = keccak256(abi.encode(id, note)); // length-prefixed`,
            locationFn: fn.name,
            locationLine: lineOf(node, delta, fn.line),
            snippet: snippet(parsed, (node.loc?.start.line ?? fn.line + delta), delta),
          }));
        }
      }
      const amountOut = namedAmountZero(callee.named);
      if (amountOut) {
        push(make({
          severity: "high",
          swc: null,
          title: `${fn.name} sets a zero slippage bound`,
          confidence: "medium",
          detector: "slippage",
          summary: "A named amountOutMin (or amount0Min/amount1Min) argument is zero. The swap can be sandwiched to any price.",
          walkthrough: "1. The router will accept any output, including one wei.\n2. An attacker sandwiches the transaction: front-run to move the pool, let this call through, back-run to restore the price.\n3. Pass a caller-supplied minimum and deadline.",
          exploitSolidity: "",
          remediationSolidity: `router.swapExactTokensForTokens(amountIn, amountOutMin, path, to, deadline);`,
          locationFn: fn.name,
          locationLine: lineOf(node, delta, fn.line),
          snippet: snippet(parsed, (node.loc?.start.line ?? fn.line + delta), delta),
        }));
      }
      return;
    }
    if (node.type === "AssemblyCall" && node.functionName === "sstore") {
      const args = (node.arguments as AstNode[] | undefined) ?? [];
      const slot = rootIdent(args[0]);
      if (slot && params.has(slot)) {
        push(withAccessControlCap(make({
          severity: "critical",
          swc: "SWC-124",
          title: `${fn.name} SSTOREs to a caller-chosen slot`,
          confidence: "high",
          detector: "assembly-param-sstore",
          summary: "The first argument of sstore is a function parameter. The caller picks the storage slot and can overwrite owner or balances.",
          walkthrough: "1. sstore(slot, value) writes `value` to absolute slot `slot`.\n2. Slot 0 is often the owner. Slot 1 is often the first mapping's length or a packed address.\n3. There is no bounds check an ordinary assignment would have given you.",
          exploitSolidity: `// If the function is public: victim.write(0, uint256(uint160(attacker)));`,
          remediationSolidity: `// Do not take a raw slot from the caller.\nbalances[msg.sender] = amount;`,
          locationFn: fn.name,
          locationLine: lineOf(node, delta, fn.line),
          snippet: snippet(parsed, (node.loc?.start.line ?? fn.line + delta), delta),
        }), authed));
      } else {
        noteWrite(node);
        push(make({
          severity: "medium",
          swc: "SWC-124",
          title: `${fn.name} writes storage from assembly`,
          confidence: "medium",
          detector: "assembly-sstore",
          summary: "An inline sstore bypasses the type checker. Confirm the slot is a constant the layout actually owns.",
          walkthrough: "1. Assembly storage writes do not follow struct or mapping packing unless you replicate it.\n2. A wrong slot corrupts an adjacent variable with no revert.",
          exploitSolidity: "",
          remediationSolidity: "// Prefer a normal assignment unless this is a measured, reviewed hot path.",
          locationFn: fn.name,
          locationLine: lineOf(node, delta, fn.line),
          snippet: snippet(parsed, (node.loc?.start.line ?? fn.line + delta), delta),
        }));
      }
      return;
    }
    for (const [k, v] of Object.entries(node)) {
      if (k === "loc" || k === "range" || k === "type") continue;
      if (v && typeof v === "object") noteExpr(v, false);
    }
  };

  const scanStmts = (stmts: AstNode[], local: Flow) => {
    for (const stmt of stmts) scanStmt(stmt, local);
  };

  const scanStmt = (stmt: AstNode, local: Flow) => {
    // Run expression analysis against `local` by temporarily swapping — we use the outer `flow`
    // object the closures close over. Callers pass `flow` or we mutate a provided flow by
    // assigning into the closed-over one. To support branches we rebind via copy-back below.
    if (stmt.type === "Block" || stmt.type === "UncheckedStatement") {
      const block = (stmt.type === "UncheckedStatement" ? stmt.block : stmt) as AstNode;
      const inner = (block.statements as AstNode[] | undefined) ?? [];
      if (stmt.type === "UncheckedStatement") flagUnchecked(fn, stmt, model, parsed, delta, push);
      scanStmts(inner, local);
      return;
    }
    if (stmt.type === "IfStatement") {
      noteExpr(stmt.condition, false);
      const before = snapshot(flow);
      scanStmtOrBlock(stmt.trueBody as AstNode | undefined);
      const left = snapshot(flow);
      restore(flow, before);
      scanStmtOrBlock(stmt.falseBody as AstNode | undefined);
      const right = snapshot(flow);
      flow.seen = left.seen ?? right.seen ?? before.seen;
      flow.sawWrite = left.sawWrite || right.sawWrite || before.sawWrite;
      flow.sawCall = left.sawCall || right.sawCall || before.sawCall;
      flow.callThenWrite = left.callThenWrite || right.callThenWrite || before.callThenWrite;
      flow.writeThenCall = left.writeThenCall || right.writeThenCall || before.writeThenCall;
      return;
    }
    if (stmt.type === "ForStatement" || stmt.type === "WhileStatement" || stmt.type === "DoWhileStatement") {
      noteExpr(stmt.conditionExpression ?? stmt.condition, false);
      noteExpr(stmt.initExpression, false);
      noteExpr(stmt.loopExpression, false);
      if (/msg\.value/.test(sliceOf(parsed, stmt))) {
        push(make({
          severity: "high",
          swc: "SWC-132",
          title: `${fn.name} uses msg.value inside a loop`,
          confidence: "high",
          detector: "msg-value-loop",
          summary: "msg.value does not decrease per iteration. Each pass can credit the same ether again.",
          walkthrough: "1. The caller attaches ETH once.\n2. Every loop iteration reads the same msg.value and adds it to a balance or uses it as a payment.\n3. N iterations mint N times the deposit.",
          exploitSolidity: `// deposit(address[] users) payable { for (...) balances[users[i]] += msg.value; }`,
          remediationSolidity: `uint256 remaining = msg.value;\nfor (uint256 i; i < users.length; ++i) {\n    balances[users[i]] += share;\n    remaining -= share;\n}`,
          locationFn: fn.name,
          locationLine: lineOf(stmt, delta, fn.line),
          snippet: snippet(parsed, (stmt.loc?.start.line ?? fn.line + delta), delta),
        }));
      }
      scanStmtOrBlock(stmt.body as AstNode | undefined);
      return;
    }
    if (stmt.type === "ExpressionStatement") {
      const expr = stmt.expression as AstNode;
      if (expr?.type === "FunctionCall") noteExpr(expr, true);
      else noteExpr(expr, false);
      return;
    }
    if (stmt.type === "VariableDeclarationStatement") {
      noteExpr(stmt.initialValue, false);
      return;
    }
    if (stmt.type === "ReturnStatement") {
      noteExpr(stmt.expression, false);
      return;
    }
    if (stmt.type === "InlineAssemblyStatement") {
      noteExpr(stmt.body, false);
      return;
    }
    noteExpr(stmt, false);
  };

  const scanStmtOrBlock = (node: AstNode | undefined) => {
    if (!node) return;
    if (node.type === "Block") scanStmts((node.statements as AstNode[]) ?? [], flow);
    else scanStmt(node, flow);
  };

  // The `local` parameter is unused by design: branches restore `flow` explicitly.
  void scanStmts;
  if (fn.body?.type === "Block") scanStmts((fn.body.statements as AstNode[]) ?? [], flow);
  else if (fn.body) scanStmt(fn.body, flow);

  // Admin / ether paths that the walker doesn't phrase as a single finding.
  const sends = /call\s*\{[^}]*value|\.transfer\s*\(|\.send\s*\(/.test(fn.source);
  if (sends && !authed && !/ecrecover\s*\(/.test(fn.source) && !fn.isConstructor && fn.visibility !== "internal" && fn.visibility !== "private" && !usesCredit(fn) && fn.mutability !== "view" && fn.mutability !== "pure") {
    push(make({
      severity: "critical",
      swc: "SWC-105",
      title: `${fn.name} sends ether with no access check`,
      confidence: "medium",
      detector: "unprotected-ether",
      summary: `${fn.name} moves ETH and neither authenticates msg.sender nor debits a per-user balance. If the recipient or the amount is not strictly the caller's own credit, this is an open drain.`,
      walkthrough: [
        `1. ${fn.name} is ${fn.visibility || "public"} and has no onlyOwner-style modifier and no msg.sender == owner check.`,
        "2. The body contains a value-bearing call, transfer, or send.",
        "3. There is no balances[msg.sender] debit, so this is not a normal withdrawal of the caller's own credit.",
        "4. Call it directly. If it transfers address(this).balance or pays an address argument, the contract is drainable.",
      ].join("\n"),
      exploitSolidity: `interface IVictim { function ${fn.name}(address payable to) external; }\ncontract Drain {\n    function go(address victim, address payable me) external {\n        IVictim(victim).${fn.name}(me);\n    }\n}`,
      remediationSolidity: `function ${fn.name}(address payable to) external onlyOwner {\n    (bool ok, ) = to.call{value: address(this).balance}("");\n    require(ok);\n}`,
      locationFn: fn.name,
      locationLine: fn.line,
      snippet: snippet(parsed, fn.line + delta, delta),
    }));
  }

  return flow;
}

function snapshot(flow: Flow): Flow {
  return { ...flow, seen: flow.seen };
}

function restore(flow: Flow, snap: Flow) {
  flow.seen = snap.seen;
  flow.sawWrite = snap.sawWrite;
  flow.sawCall = snap.sawCall;
  flow.callThenWrite = snap.callThenWrite;
  flow.writeThenCall = snap.writeThenCall;
}

function namedAmountZero(named: AstNode | undefined): boolean {
  if (!named || !Array.isArray(named.names) || !Array.isArray(named.arguments)) return false;
  const names = named.names as string[];
  const args = named.arguments as AstNode[];
  for (let i = 0; i < names.length; i += 1) {
    if (!/amountOutMin|amount0Min|amount1Min|minOut/i.test(names[i] ?? "")) continue;
    const arg = args[i];
    if (arg?.type === "NumberLiteral" && (arg.number === "0" || arg.number === "0x0")) return true;
  }
  return false;
}

function flagUnchecked(
  fn: FnModel,
  stmt: AstNode,
  model: SourceModel,
  parsed: string,
  delta: number,
  push: (f: Finding) => void,
) {
  if (model.versionFloor !== null && model.versionFloor < 8_000) return;
  const text = sliceOf(parsed, stmt);
  const onlyInc = !/[^+]\+[^+]/.test(text) && !text.includes("-") && !text.includes("*") && !text.includes("/");
  push(make({
    severity: onlyInc ? "info" : "medium",
    swc: "SWC-101",
    title: onlyInc ? `${fn.name} has an unchecked increment` : `${fn.name} disables overflow checks`,
    confidence: "high",
    detector: "unchecked-block",
    summary: onlyInc
      ? "An unchecked block only bumps a counter. That is a common loop pattern and is safe if the bound cannot approach 2^256."
      : "An unchecked block wraps instead of reverting. Balances and amounts inside it can overflow.",
    walkthrough: "1. `unchecked { ... }` restores pre-0.8 wrapping for every + - * inside it.\n2. A balance written there can skip from max to zero.\n3. Keep unchecked for measured loop indexes only.",
    exploitSolidity: onlyInc ? "" : "unchecked { credit += deposit; } // wraps",
    remediationSolidity: onlyInc ? "" : "credit += deposit; // checked on 0.8+",
    locationFn: fn.name,
    locationLine: lineOf(stmt, delta, fn.line),
    snippet: snippet(parsed, (stmt.loc?.start.line ?? fn.line + delta), delta),
  }));
}

function scanSimple(
  fn: FnModel,
  contract: ContractModel,
  model: SourceModel,
  parsed: string,
  delta: number,
  authed: boolean,
  push: (f: Finding) => void,
) {
  const src = fn.source;
  if (/tx\.origin/.test(src)) {
    push(make({
      severity: "high",
      swc: "SWC-115",
      title: `${fn.name} authenticates with tx.origin`,
      confidence: "high",
      detector: "tx-origin",
      summary: "tx.origin is the signer of the transaction, not the caller. A contract the signer uses can reenter this function and pass the check.",
      walkthrough: originWalk(fn.name),
      exploitSolidity: originExploit(contract.name, fn.name),
      remediationSolidity: originFix(),
      locationFn: fn.name,
      locationLine: fn.line,
      snippet: snippet(parsed, fn.line + delta, delta),
    }));
  }

  if (/\bselfdestruct\s*\(|\bsuicide\s*\(/.test(src)) {
    push(make({
      severity: authed ? "high" : "critical",
      swc: "SWC-106",
      title: authed ? `${fn.name} can selfdestruct` : `${fn.name} selfdestructs without an access check`,
      confidence: "high",
      detector: "selfdestruct",
      summary: authed
        ? "A privileged caller can destroy the contract and send away the balance. On chains that still honor deletion outside the creating transaction this is final; either way the balance moves."
        : "selfdestruct is reachable without an owner check. The balance can be forced to an attacker-chosen address.",
      walkthrough: "1. selfdestruct sends the full balance to its argument and, where deletion still applies, removes the code.\n2. A public function with no msg.sender check is an open kill switch.\n3. Combined with CREATE2, the address can be redeployed with different code.",
      exploitSolidity: authed ? "" : `interface IVictim { function ${fn.name}(address payable to) external; }`,
      remediationSolidity: `function close(address payable to) external onlyOwner {\n    // Prefer a normal withdraw. selfdestruct is not an upgrade strategy after EIP-6780.\n    selfdestruct(to);\n}`,
      locationFn: fn.name,
      locationLine: fn.line,
      snippet: snippet(parsed, fn.line + delta, delta),
    }));
  }

  const initName = /^init(ialize)?$/.test(fn.name);
  if (initName && !authed && !fn.modifiers.some((m) => /initializer|reinitializer/i.test(m)) && !/require\s*\(\s*!?\s*initialized/.test(src)) {
    push(make({
      severity: "critical",
      swc: null,
      title: `${fn.name} can be called by anyone, more than once`,
      confidence: "high",
      detector: "unprotected-initializer",
      summary: "Initializer functions replace the constructor on proxies. Without an initializer modifier or a one-shot flag check, anyone can reset the owner or oracle, and they can do it again later.",
      walkthrough: [
        `1. ${fn.name} is ${fn.visibility || "public"} and writes privileged storage.`,
        "2. Nothing reverts when it has already been called.",
        "3. On a proxy, the implementation's constructor never ran, so this function is the whole setup path — and it is open.",
        "4. Front-run the deploy: call initialize before the deployer and become the owner.",
      ].join("\n"),
      exploitSolidity: `interface IVictim { function initialize(address) external; }\ncontract FrontRun {\n    function snipe(address proxy, address me) external {\n        IVictim(proxy).initialize(me);\n    }\n}`,
      remediationSolidity: `import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";\nfunction initialize(address _oracle) external initializer {\n    require(_oracle != address(0));\n    oracle = _oracle;\n}`,
      locationFn: fn.name,
      locationLine: fn.line,
      snippet: snippet(parsed, fn.line + delta, delta),
    }));
  }

  const writesPriv = contract.stateVars.some((v) => PRIVILEGED.test(v.name) && new RegExp(`\\b${v.name}\\s*=`).test(src));
  const adminName = /^(mint|burn|setOwner|transferOwnership|upgrade|upgradeTo|upgradeToAndCall|pause|unpause|setFee|setTax|setOracle|setImplementation|execute)$/.test(fn.name);
  if (!initName && (writesPriv || adminName) && !authed && !fn.isConstructor && fn.visibility !== "internal" && fn.visibility !== "private" && fn.mutability !== "view" && fn.mutability !== "pure") {
    push(make({
      severity: adminName || writesPriv ? "critical" : "high",
      swc: "SWC-105",
      title: `${fn.name} changes privileged state without an access check`,
      confidence: "medium",
      detector: "unprotected-admin",
      summary: `${fn.name} is externally callable and writes an owner, oracle, implementation, or other privileged variable — or its name is an admin action — and Kiln found no msg.sender check.`,
      walkthrough: `1. Confirm there is no inherited modifier the parser missed. Bases: ${contract.bases.join(", ") || "(none)"}.\n2. If the function really is open, call it and take the role.\n3. Add onlyOwner, or a role check, and a zero-address check on the new value.`,
      exploitSolidity: `interface IVictim { function ${fn.name}(address next) external; }`,
      remediationSolidity: `function ${fn.name}(address next) external onlyOwner {\n    require(next != address(0));\n    owner = next;\n    emit OwnershipTransferred(msg.sender, next);\n}`,
      locationFn: fn.name,
      locationLine: fn.line,
      snippet: snippet(parsed, fn.line + delta, delta),
    }));
  }

  if (fn.name === "_authorizeUpgrade" && !authed) {
    push(make({
      severity: "critical",
      swc: null,
      title: "_authorizeUpgrade is not restricted",
      confidence: "high",
      detector: "unprotected-admin",
      summary: "UUPS upgrades call _authorizeUpgrade. If it is empty or open, anyone can replace the implementation.",
      walkthrough: "1. upgradeToAndCall is public on the UUPS base.\n2. The only gate is this function.\n3. An empty body, or one that does not check msg.sender, hands out the upgrade.",
      exploitSolidity: `function attack(address proxy, address evil) external {\n    IUUPS(proxy).upgradeToAndCall(evil, "");\n}`,
      remediationSolidity: `function _authorizeUpgrade(address) internal override onlyOwner {}`,
      locationFn: fn.name,
      locationLine: fn.line,
      snippet: snippet(parsed, fn.line + delta, delta),
    }));
  }

  if (/ecrecover\s*\(/.test(src)) {
    if (!/7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0/i.test(src) && !/\bs\s*(<=|<)/.test(src)) {
      push(make({
        severity: "medium",
        swc: "SWC-117",
        title: `${fn.name} does not bind the signature's s value`,
        confidence: "medium",
        detector: "signature-malleability",
        summary: "ecrecover accepts both s and secp256k1n - s for many signatures. Without an s < n/2 check, one approval can be replayed as a second distinct signature.",
        walkthrough: "1. A signature (v, r, s) has a malleable twin (v', r, n - s).\n2. Both recover the same signer on many libraries, but the bytes differ.\n3. A mapping keyed by the signature hash, rather than by a nonce, treats them as two uses.",
        exploitSolidity: `// n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141\n// s2 = n - s; flip v between 27 and 28. ecrecover returns the same signer.`,
        remediationSolidity: `require(uint256(s) <= 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0, "s");\nrequire(v == 27 || v == 28, "v");`,
        locationFn: fn.name,
        locationLine: fn.line,
        snippet: snippet(parsed, fn.line + delta, delta),
      }));
    }
    if (!/nonce|deadline|chainid|chain\.id|domainSeparator|used\[/i.test(src)) {
      push(make({
        severity: "medium",
        swc: "SWC-121",
        title: `${fn.name} verifies a signature with no nonce or deadline`,
        confidence: "medium",
        detector: "signature-replay",
        summary: "The digest does not appear to include a nonce, a deadline, or a domain separator. The same signature can be reused, possibly on another chain.",
        walkthrough: "1. ecrecover only tells you who signed the hash.\n2. If the hash is just the arguments, the signer cannot prevent a second submission.\n3. Include chainid, the verifying-contract address, a nonce that increments, and a deadline.",
        exploitSolidity: `// Submit the same (user, amount, v, r, s) again after the first claim pays.`,
        remediationSolidity: `bytes32 digest = keccak256(abi.encodePacked(\n    "\\x19\\x01", DOMAIN_SEPARATOR(), keccak256(abi.encode(TYPEHASH, user, amount, nonces[user]++, deadline))\n));\nrequire(block.timestamp <= deadline, "expired");`,
        locationFn: fn.name,
        locationLine: fn.line,
        snippet: snippet(parsed, fn.line + delta, delta),
      }));
    }
  }

  if (/getReserves\s*\(|\.slot0\s*\(|latestRoundData\s*\(|latestAnswer\s*\(/.test(src) && !/^(getReserves|slot0|latestRoundData|latestAnswer)$/.test(fn.name)) {
    push(make({
      severity: "high",
      swc: null,
      title: `${fn.name} prices off a spot oracle`,
      confidence: "medium",
      detector: "oracle-spot",
      summary: "A reserves read, a Uniswap v3 slot0, or a spot Chainlink-style answer is used directly. Spot reserves move inside a single transaction; a stale or unchecked oracle answer is the other half of this class.",
      walkthrough: "1. Borrow via a flash loan, move the pool, and read the new price in the same call.\n2. Anything that mints, borrows, or liquidates on that number is wrong for one block — which is long enough.\n3. Use a TWAP, or Chainlink with a freshness and min/max answer check. Never use slot0 or getReserves as a price.",
      exploitSolidity: `// Inside a flash swap callback:\nuint256 fake = victim.quote(pair);\n// fake reflects the pool you just skewed. Borrow against it, then repay the swap.`,
      remediationSolidity: `(uint80 roundId, int256 answer,, uint256 updatedAt,) = feed.latestRoundData();\nrequire(answer > 0 && updatedAt >= block.timestamp - 1 hours, "stale");\nrequire(feed.getAnswer(roundId) == answer);`,
      locationFn: fn.name,
      locationLine: fn.line,
      snippet: snippet(parsed, fn.line + delta, delta),
    }));
  }

  if (/(price|quote|rate)/i.test(fn.name) && /address\(this\)\.balance|\.balance\b/.test(src)) {
    push(make({
      severity: "medium",
      swc: "SWC-120",
      title: `${fn.name} treats a token or ether balance as a price`,
      confidence: "medium",
      detector: "balance-as-price",
      summary: "A raw balance can be pushed up with a direct transfer, including in the same transaction. It is not a manipulation-resistant price.",
      walkthrough: "1. Donate tokens or ETH straight to the contract.\n2. balance increases with no share mint.\n3. The next caller buys shares too cheap, or collateral looks too thick.",
      exploitSolidity: `// victim.price() returns address(this).balance.\n// Send 1 wei or 1e24 wei first, depending on which way the formula breaks.`,
      remediationSolidity: "// Price from a TWAP or an oracle. Use an internal accounting variable, not address(this).balance.",
      locationFn: fn.name,
      locationLine: fn.line,
      snippet: snippet(parsed, fn.line + delta, delta),
    }));
  }

  if (hasDivThenMul(fn.body)) {
    push(make({
      severity: "medium",
      swc: null,
      title: `${fn.name} divides before it multiplies`,
      confidence: "high",
      detector: "div-before-mul",
      summary: "Integer division truncates. Doing it before a multiply throws away precision and, in a share or price formula, donates value to the next caller or rounds a payout to zero.",
      walkthrough: "1. (a / b) * c truncates a/b first.\n2. If a < b the whole product is zero.\n3. Multiply first, then divide: (a * c) / b. Watch the overflow on the product if you are below 0.8 or inside unchecked.",
      exploitSolidity: `// (100 / 300) * 1e18 == 0\n// (100 * 1e18) / 300        == 3.33e17`,
      remediationSolidity: `return (uint256(a) * 1e18) / uint256(b);`,
      locationFn: fn.name,
      locationLine: fn.line,
      snippet: snippet(parsed, fn.line + delta, delta),
    }));
  }

  if (/==\s*address\(this\)\.balance|address\(this\)\.balance\s*==|balance\s*==/.test(src)) {
    push(make({
      severity: "medium",
      swc: "SWC-132",
      title: `${fn.name} requires an exact balance`,
      confidence: "medium",
      detector: "strict-balance",
      summary: "A strict equality on a balance is broken by a force-fed ether transfer (selfdestruct, or a coinbase payment). The requirement then bricks the function.",
      walkthrough: "1. Anyone can increase a contract's ETH balance without calling it.\n2. require(address(this).balance == expected) starts failing permanently.\n3. Compare against an internal accounted variable, or use >=.",
      exploitSolidity: `selfdestruct(payable(victim)); // balance is now expected + 1`,
      remediationSolidity: `require(accounted == expected, "accounting");`,
      locationFn: fn.name,
      locationLine: fn.line,
      snippet: snippet(parsed, fn.line + delta, delta),
    }));
  }

  const timestamp = /block\.timestamp|\bnow\b|block\.prevrandao|block\.difficulty|blockhash\s*\(/.test(src);
  const randomish = timestamp && (/%|\bkeccak256\s*\(/.test(src) || /random|winner|lottery|raffle/i.test(fn.name + src));
  if (randomish) {
    push(make({
      severity: "high",
      swc: "SWC-120",
      title: `${fn.name} draws randomness from the chain`,
      confidence: "medium",
      detector: "weak-randomness",
      summary: "block.timestamp, prevrandao, difficulty, or blockhash is mixed into a number someone can bias. Miners and searchers see it before they decide to include the transaction.",
      walkthrough: "1. The inputs are known in the mempool, or nudgeable by the block producer.\n2. A caller who dislikes the result waits a block or uses a different sender.\n3. Use a VRF, or commit-reveal with a penalty.",
      exploitSolidity: `// Wait until uint256(keccak256(abi.encode(block.timestamp, msg.sender))) % n == winningIndex.`,
      remediationSolidity: "// Chainlink VRF, or a commit in block n revealed in block n+k.",
      locationFn: fn.name,
      locationLine: fn.line,
      snippet: snippet(parsed, fn.line + delta, delta),
    }));
  } else if (/block\.timestamp|\bnow\b/.test(src) && /(require|if)\s*\(/.test(src)) {
    push(make({
      severity: "low",
      swc: "SWC-116",
      title: `${fn.name} branches on block.timestamp`,
      confidence: "medium",
      detector: "timestamp",
      summary: "A timestamp check is fine for multi-hour windows. It is a soft gate around a single block: producers can shift it by roughly 15 seconds.",
      walkthrough: "1. Identify whether the window is a long vest or a one-block race.\n2. If funds move the moment the timestamp crosses a line, a producer can include or exclude the winning transaction.",
      exploitSolidity: "",
      remediationSolidity: "// Keep timestamp gates for coarse deadlines only.",
      locationFn: fn.name,
      locationLine: fn.line,
      snippet: snippet(parsed, fn.line + delta, delta),
    }));
  }

  if (/extcodesize/.test(src)) {
    push(make({
      severity: "medium",
      swc: null,
      title: `${fn.name} uses extcodesize as an identity check`,
      confidence: "low",
      detector: "extcodesize",
      summary: "extcodesize(addr) == 0 is true for EOAs and also for a contract that is still inside its constructor. It does not prove the caller is an EOA once they call you from a constructor.",
      walkthrough: "1. During construction, the address has no code yet.\n2. A constructor can call this function and pass the check, then finish deploying.\n3. Do not use it for security. If you must block contracts, accept the constructor bypass explicitly.",
      exploitSolidity: `contract Bypass {\n    constructor(address victim) {\n        Victim(victim).mint(); // extcodesize(address(this)) == 0 here\n    }\n}`,
      remediationSolidity: "// Drop the check, or use tx.origin == msg.sender only with eyes open (it has its own phishing problem).",
      locationFn: fn.name,
      locationLine: fn.line,
      snippet: snippet(parsed, fn.line + delta, delta),
    }));
  }

  for (const p of fn.params) {
    if (p.name && contract.stateVars.some((v) => v.name === p.name)) {
      push(make({
        severity: "low",
        swc: "SWC-119",
        title: `${fn.name} shadows state variable ${p.name}`,
        confidence: "high",
        detector: "shadowing",
        summary: `Parameter ${p.name} hides the state variable of the same name. An assignment may update the local and leave storage unchanged.`,
        walkthrough: "1. Inside the function the name binds to the parameter.\n2. `p = msg.sender` does not change storage.\n3. Rename the parameter.",
        exploitSolidity: "",
        remediationSolidity: `function ${fn.name}(address _${p.name}) external { ${p.name} = _${p.name}; }`,
        locationFn: fn.name,
        locationLine: fn.line,
        snippet: snippet(parsed, fn.line + delta, delta),
      }));
      break;
    }
  }

  if (/\.(transferFrom)\s*\(/.test(src) && /balances\s*\[[^\]]+\]\s*(\+=|=)/.test(src) && !/balanceOf/.test(src)) {
    push(make({
      severity: "low",
      swc: null,
      title: `${fn.name} assumes a transfer moved the full amount`,
      confidence: "low",
      detector: "fee-on-transfer",
      summary: "The function credits an input amount after transferFrom and never measures the balance delta. Fee-on-transfer and rebasing tokens desynchronize the books.",
      walkthrough: "1. transferFrom returns success but the contract receives less than `amount`.\n2. The internal balance still increases by `amount`.\n3. Later withdrawals pay out more than the contract holds.",
      exploitSolidity: "",
      remediationSolidity: `uint256 beforeBal = token.balanceOf(address(this));\ntoken.safeTransferFrom(msg.sender, address(this), amount);\nuint256 received = token.balanceOf(address(this)) - beforeBal;\nbalances[msg.sender] += received;`,
      locationFn: fn.name,
      locationLine: fn.line,
      snippet: snippet(parsed, fn.line + delta, delta),
    }));
  }

  const addrWrite = contract.stateVars.find((v) => v.typeName === "address" && new RegExp(`\\b${v.name}\\s*=\\s*${fn.params.find((p) => p.typeName === "address")?.name}\\b`).test(src));
  if (addrWrite && !/address\s*\(\s*0\s*\)/.test(src) && !fn.isConstructor) {
    push(make({
      severity: "medium",
      swc: null,
      title: `${fn.name} can set ${addrWrite.name} to the zero address`,
      confidence: "medium",
      detector: "zero-address",
      summary: `An address argument is stored in ${addrWrite.name} with no address(0) check. A zero owner or oracle bricks every later authorization or price read.`,
      walkthrough: "1. The parameter is written straight into storage.\n2. address(0) then passes `signer == oracle` style checks for the wrong reason, or makes onlyOwner permanently false.\n3. require(next != address(0)).",
      exploitSolidity: "",
      remediationSolidity: `require(next != address(0), "zero");\n${addrWrite.name} = next;`,
      locationFn: fn.name,
      locationLine: fn.line,
      snippet: snippet(parsed, fn.line + delta, delta),
    }));
  }

  if (writesOwner(src, contract) && !/emit\s+/.test(src) && !fn.isConstructor) {
    push(make({
      severity: "info",
      swc: null,
      title: `${fn.name} changes an authority variable without an event`,
      confidence: "medium",
      detector: "missing-event",
      summary: "Owner, admin, or oracle is reassigned and the function emits nothing. Off-chain monitors will not see the rotation.",
      walkthrough: "1. Events are how indexers notice privilege changes.\n2. Emit the previous and next value.",
      exploitSolidity: "",
      remediationSolidity: "emit OwnershipTransferred(previous, next);",
      locationFn: fn.name,
      locationLine: fn.line,
      snippet: "",
    }));
  }

  for (const v of contract.stateVars) {
    if (/password|secret|privatekey|apikey|seedphrase|mnemonic/i.test(v.name)) {
      push(make({
        severity: "info",
        swc: "SWC-136",
        title: `${v.name} looks like a secret stored on-chain`,
        confidence: "medium",
        detector: "private-secret",
        summary: "Storage is public. private and internal only change the compiler's accessor rules. The value is readable with eth_getStorageAt.",
        walkthrough: "1. Deploy, then read the slot.\n2. Nothing in the contract can hide a key from a node.\n3. Keep secrets off-chain or store a hash and reveal later.",
        exploitSolidity: "",
        remediationSolidity: "bytes32 public commitment; // keccak256(secret), not the secret",
        locationFn: null,
        locationLine: v.line,
        snippet: snippet(parsed, v.line + delta, delta),
      }));
    }
  }
}

function writesOwner(src: string, contract: ContractModel): boolean {
  return contract.stateVars.some((v) => PRIVILEGED.test(v.name) && new RegExp(`\\b${v.name}\\s*=`).test(src));
}

function hasDivThenMul(body: AstNode | null): boolean {
  let hit = false;
  const visit = (node: unknown, parentMul: boolean) => {
    if (!node || typeof node !== "object" || hit) return;
    if (Array.isArray(node)) {
      node.forEach((n) => visit(n, parentMul));
      return;
    }
    const n = node as AstNode;
    const isMul = n.type === "BinaryOperation" && n.operator === "*";
    if (isMul && (isDivNode(n.left) || isDivNode(n.right))) hit = true;
    for (const [k, v] of Object.entries(n)) {
      if (k === "loc" || k === "range") continue;
      if (v && typeof v === "object") visit(v, isMul || parentMul);
    }
  };
  visit(body, false);
  return hit;
}

function isDivNode(node: unknown): boolean {
  const n = unwrapExpr(node);
  return Boolean(n && n.type === "BinaryOperation" && n.operator === "/");
}

function unwrapExpr(node: unknown): AstNode | null {
  if (!node || typeof node !== "object") return null;
  const n = node as AstNode;
  if (n.type === "TupleExpression" && Array.isArray(n.components) && n.components.length === 1) {
    return unwrapExpr(n.components[0]);
  }
  return n;
}

function originWalk(name: string): string {
  return [
    `1. ${name} reads tx.origin, the EOA that signed the outer transaction.`,
    "2. msg.sender can be a contract. The check does not notice.",
    "3. The victim is persuaded to call an attacker contract (a fake 'claim' or approval helper).",
    "4. That contract calls this function. tx.origin is still the victim, so the check passes, and the attacker is the one who receives the side effect.",
  ].join("\n");
}

function originExploit(contractName: string, fn: string): string {
  return `interface IVictim { function ${fn}(address payable to) external; }

contract Phish {
    function lure(address victim, address payable me) external {
        // The owner calls lure(). tx.origin inside ${contractName} is the owner.
        IVictim(victim).${fn}(me);
    }
}`;
}

function originFix(): string {
  return `require(msg.sender == owner, "owner");`;
}

function reentrancyWalk(contractName: string, fn: FnModel, call: ExtCall | null): string {
  return [
    `1. ${contractName}.${fn.name} reaches an external call${call ? ` (${call.kind} at line ${call.line})` : ""}.`,
    "2. The callee's fallback or receive runs before this function finishes.",
    "3. Storage that the call depends on — a balance, a paid flag, a share total — is updated only after the call returns, so the re-entering call still sees the old value.",
    "4. Repeat until the ether or the credit is gone. A sibling function that reads the same storage can be used instead of calling this function again.",
  ].join("\n");
}

function reentrancyExploit(contractName: string, fn: string): string {
  return `interface IVictim { function deposit() external payable; function ${fn}() external; }

contract Reenter {
    IVictim victim;
    uint256 hits;
    constructor(address v) { victim = IVictim(v); }
    function attack() external payable {
        victim.deposit{value: msg.value}();
        victim.${fn}();
    }
    receive() external payable {
        if (hits++ < 5 && address(victim).balance > 0) victim.${fn}();
    }
}`;
}

function reentrancyFix(fn: string): string {
  return `// Checks, then effects, then interaction.
function ${fn}() external nonReentrant {
    uint256 amount = balances[msg.sender];
    balances[msg.sender] = 0;
    (bool ok, ) = msg.sender.call{value: amount}("");
    require(ok);
}`;
}

function delegateWalk(fn: string, call: ExtCall): string {
  return [
    `1. ${fn} delegatecalls ${call.target || "the target"} at line ${call.line}.`,
    "2. The target's code executes with this contract's storage and the original msg.sender.",
    call.targetIsParam
      ? "3. The target is a function argument, so the caller chooses the code. They point it at a contract that writes slot 0."
      : "3. If that address is changeable, whoever can change it owns this contract.",
    "4. A successful return only means the foreign code did not revert. It says nothing about which slots it wrote.",
  ].join("\n");
}

function delegateExploit(contractName: string): string {
  return `contract StorageSmash {
    address public owner; // slot 0, same layout assumption
    function seize() external { owner = msg.sender; }
}

interface IVictim { function migrate(address impl, bytes calldata data) external; }

contract Take {
    function go(address victim) external {
        StorageSmash smash = new StorageSmash();
        IVictim(victim).migrate(address(smash), abi.encodeWithSignature("seize()"));
    }
}
// ${contractName}'s slot 0 is now the attacker.`;
}

export function contractSurface(model: SourceModel) {
  return model.contracts.map((c) => ({
    name: c.name,
    kind: c.kind,
    bases: c.bases,
    stateVars: c.stateVars,
    functions: c.functions.map((f) => ({
      name: f.name,
      visibility: f.visibility,
      mutability: f.mutability,
      modifiers: f.modifiers,
      line: f.line,
      params: f.params.map((p) => `${p.typeName} ${p.name}`.trim()).join(", "),
    })),
    events: c.events,
  }));
}

export type { StateVar, ModModel };
