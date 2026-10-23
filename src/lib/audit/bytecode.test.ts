// src/lib/audit/bytecode.test.ts
//
// Producer tests for the bytecode analyzer (G4). Every consumer of
// these findings had tests; the producer had none. Pinned here:
// - each presence family emits with the detector / severity /
//   confidence the adjudication scope rules assume (Fix 33's demotions
//   included: opcode PRESENCE is low, never critical/high);
// - the snippet shape: a presence finding's snippet IS a disassembly
//   window — pc-prefixed opcode lines in exactly the format
//   adjudication.ts's DISASSEMBLY_LINE_RE matches. That shape is the
//   fact that defeated the original corroboration heuristic, so it is
//   pinned as a contract between the two modules;
// - presence findings carry locationFn "runtime" (the other half of
//   that contract).
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { analyzeBytecode, looksLikeBytecode } from "./bytecode.ts";
import type { Finding } from "./types.ts";

// The mirror of adjudication.ts's DISASSEMBLY_LINE_RE. If snippetFor's
// format ever drifts from this, corroboration-by-snippet breaks
// silently — this test is where the drift gets caught.
const DISASSEMBLY_LINE_RE = /^\s*>?\s*[0-9a-f]{4}\s{2}[A-Z][A-Z0-9]*(\s|$)/m;

const byDetector = (findings: Finding[], detector: string) =>
  findings.find((f) => f.detector === detector);

describe("analyzeBytecode — presence emissions", () => {
  it("SELFDESTRUCT (0xff) emits bytecode-selfdestruct, low, SWC-106, high confidence", () => {
    const { findings } = analyzeBytecode("ff");
    const f = byDetector(findings, "bytecode-selfdestruct");
    assert.ok(f);
    assert.equal(f.severity, "low"); // Fix 33: presence is not a vulnerability
    assert.equal(f.swc, "SWC-106");
    assert.equal(f.confidence, "high");
    assert.equal(f.title, "SELFDESTRUCT is reachable in the bytecode");
    assert.equal(f.locationFn, "runtime");
  });

  it("DELEGATECALL (0xf4) emits bytecode-delegatecall, low, SWC-112", () => {
    const { findings } = analyzeBytecode("f4");
    const f = byDetector(findings, "bytecode-delegatecall");
    assert.ok(f);
    assert.equal(f.severity, "low"); // Fix 33: the archive's largest FP class, demoted
    assert.equal(f.swc, "SWC-112");
    assert.equal(f.confidence, "high");
    assert.equal(f.title, "DELEGATECALL executes foreign code in this contract's storage");
    assert.equal(f.locationFn, "runtime");
  });

  it("CALLCODE (0xf2) alone emits bytecode-callcode (not delegatecall)", () => {
    const { findings } = analyzeBytecode("f2");
    const f = byDetector(findings, "bytecode-callcode");
    assert.ok(f);
    assert.equal(f.severity, "low");
    assert.equal(f.title, "CALLCODE executes foreign code in this contract's storage");
    assert.equal(byDetector(findings, "bytecode-delegatecall"), undefined);
  });

  it("ORIGIN (0x32) emits bytecode-origin, medium, SWC-115", () => {
    const { findings } = analyzeBytecode("32");
    const f = byDetector(findings, "bytecode-origin");
    assert.ok(f);
    assert.equal(f.severity, "medium");
    assert.equal(f.swc, "SWC-115");
    assert.equal(f.title, "ORIGIN (tx.origin) is used");
    assert.equal(f.locationFn, "runtime");
  });

  it("a popped CALL emits bytecode-unchecked-call, medium, SWC-104", () => {
    // CALL followed immediately by POP: the success flag is discarded.
    const { findings } = analyzeBytecode("f150");
    const f = byDetector(findings, "bytecode-unchecked-call");
    assert.ok(f);
    assert.equal(f.severity, "medium");
    assert.equal(f.swc, "SWC-104");
    assert.equal(f.confidence, "medium");
    assert.match(f.title, /^CALL return value is popped/);
  });

  it("a checked CALL (ISZERO before POP) does NOT emit bytecode-unchecked-call", () => {
    // CALL, ISZERO, POP: the flag is inspected first — no finding.
    const { findings } = analyzeBytecode("f11550");
    assert.equal(byDetector(findings, "bytecode-unchecked-call"), undefined);
  });

  it("CALL + SSTORE emits the bytecode-reentrancy-shape warning, medium, LOW confidence, empty snippet", () => {
    const { findings } = analyzeBytecode("f155");
    const f = byDetector(findings, "bytecode-reentrancy-shape");
    assert.ok(f);
    assert.equal(f.severity, "medium");
    assert.equal(f.swc, "SWC-107");
    assert.equal(f.confidence, "low");
    assert.equal(f.title, "Both CALL and SSTORE are present");
    assert.equal(f.snippet, "");
  });

  it("TIMESTAMP (0x42) emits bytecode-timestamp, low, SWC-116", () => {
    const { findings } = analyzeBytecode("42");
    const f = byDetector(findings, "bytecode-timestamp");
    assert.ok(f);
    assert.equal(f.severity, "low");
    assert.equal(f.swc, "SWC-116");
    assert.equal(f.title, "TIMESTAMP is read");
    assert.equal(f.locationFn, "runtime");
  });

  it("CREATE2 (0xf5) emits bytecode-create2, info", () => {
    const { findings } = analyzeBytecode("f5");
    const f = byDetector(findings, "bytecode-create2");
    assert.ok(f);
    assert.equal(f.severity, "info");
    assert.equal(f.title, "CREATE2 is present");
  });

  it("an unbounded storage loop emits gas-estimator-dos, medium, SWC-128", () => {
    // JUMPDEST; SLOAD; PUSH1 0x00; JUMP — a backward jump over storage.
    const { findings } = analyzeBytecode("5b54600056");
    const f = byDetector(findings, "gas-estimator-dos");
    assert.ok(f);
    assert.equal(f.severity, "medium");
    assert.equal(f.swc, "SWC-128");
    assert.equal(f.locationFn, "runtime");
  });

  it("the EIP-1167 minimal-proxy shape emits bytecode-proxy, info, and names the inventory", () => {
    const impl = "bebebebebebebebebebebebebebebebebebebebe";
    const { findings, inventory } = analyzeBytecode(
      `363d3d373d3d3d363d73${impl}5af43d82803e903d91602b57fd5bf3`,
    );
    const f = byDetector(findings, "bytecode-proxy");
    assert.ok(f);
    assert.equal(f.severity, "info");
    assert.equal(f.title, "EIP-1167 minimal proxy");
    assert.deepEqual(inventory.contractNames, ["MinimalProxy"]);
    assert.match(inventory.proxy ?? "", /EIP-1167 minimal proxy/);
  });

  it("CBOR metadata with solc < 0.8 emits bytecode-metadata, low; solc 0.8 does not", () => {
    // body PUSH1 0x00; metadata: a2 64 'solc' 43 <0.7.6>; length 0x000a.
    const old = analyzeBytecode("6000a264736f6c6343000706000a");
    const f = byDetector(old.findings, "bytecode-metadata");
    assert.ok(f);
    assert.equal(f.severity, "low"); // Fix 32: toolchain hygiene, not a vuln
    assert.equal(f.title, "Metadata reports solc 0.7.6");
    assert.equal(old.inventory.compiler, "0.7.6");
    assert.equal(f.locationFn, null);

    const modern = analyzeBytecode("6000a264736f6c6343000800000a");
    assert.equal(byDetector(modern.findings, "bytecode-metadata"), undefined);
    assert.equal(modern.inventory.compiler, "0.8.0");
  });

  it("no presence opcodes → no presence findings; undecodable input → empty, honest inventory", () => {
    const quiet = analyzeBytecode("60006000"); // two PUSH1s, nothing else
    assert.equal(quiet.findings.length, 0);
    assert.equal(quiet.inventory.inputKind, "bytecode");

    const bad = analyzeBytecode("not hex at all");
    assert.deepEqual(bad.findings, []);
    assert.equal(bad.inventory.kindNote, "Undecodable");
  });
});

describe("analyzeBytecode — the snippetFor disassembly-window contract", () => {
  it("a presence finding's snippet IS a disassembly window (the shape that defeated snippet corroboration)", () => {
    const { findings } = analyzeBytecode("f4");
    const f = byDetector(findings, "bytecode-delegatecall");
    assert.ok(f);
    // Single instruction: the window is exactly the marked pc line.
    assert.equal(f.snippet, "> 0000  DELEGATECALL");
    assert.match(f.snippet, DISASSEMBLY_LINE_RE);
  });

  it("the window carries up to 3 instructions before and 4 after, with the target line marked", () => {
    // PUSH1 0x00 (pc 0), DELEGATECALL (pc 2): two lines, target marked.
    const { findings } = analyzeBytecode("6000f4");
    const f = byDetector(findings, "bytecode-delegatecall");
    assert.ok(f);
    assert.equal(f.snippet, "  0000  PUSH1 0x00\n> 0002  DELEGATECALL");
    for (const line of f.snippet.split("\n")) {
      assert.match(line, DISASSEMBLY_LINE_RE);
    }
  });
});

describe("looksLikeBytecode", () => {
  it("accepts hex and rejects source-shaped input", () => {
    assert.equal(looksLikeBytecode("0x6000604052"), true);
    assert.equal(looksLikeBytecode("contract Foo { function bar() public {} }"), false);
    assert.equal(looksLikeBytecode("hello world"), false);
  });
});
