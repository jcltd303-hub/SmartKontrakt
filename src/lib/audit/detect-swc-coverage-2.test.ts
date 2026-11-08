import test from "node:test";
import assert from "node:assert/strict";
import { parseSource } from "./model.ts";
import { detectSource } from "./detect.ts";
import type { Finding } from "./types.ts";

/**
 * Regression fixtures for the SWC coverage batch, second half
 * (Fixes 52–58 in detect.ts, analyzer 2026-11-06.26), implementing
 * SWC-COVERAGE-CODER-BRIEF.md. Every detector proves BOTH directions:
 * the registry shape flags AND the corrected shape stays silent.
 * With this batch the engine covers all 37 SWC ids.
 */

function analyze(src: string): Finding[] {
  const model = parseSource(src);
  assert.equal(model.parseError, null);
  return detectSource(model, src);
}

function byDetector(findings: Finding[], detector: string): Finding[] {
  return findings.filter((f) => f.detector === detector);
}

// ---------- Fix 52: SWC-110 ----------

test("SWC-110: assert on a parameter flags", () => {
  const findings = analyze(`
    pragma solidity ^0.8.0;
    contract A {
      function f(uint256 amt) public pure { assert(amt > 0); }
    }
  `);
  const hits = byDetector(findings, "assert-violation");
  assert.equal(hits.length, 1);
  assert.equal(hits[0].swc, "SWC-110");
});

test("SWC-110: assert on msg.sender flags", () => {
  const findings = analyze(`
    pragma solidity ^0.8.0;
    contract A {
      address owner;
      function f() public view { assert(msg.sender == owner); }
    }
  `);
  assert.equal(byDetector(findings, "assert-violation").length, 1);
});

test("SWC-110: an invariant assert over state stays silent", () => {
  const findings = analyze(`
    pragma solidity ^0.8.0;
    contract A {
      uint256 total;
      uint256 a;
      uint256 b;
      function f() public { total = a + b; assert(total == a + b); }
    }
  `);
  assert.equal(byDetector(findings, "assert-violation").length, 0);
});

test("SWC-110: require-only validation stays silent", () => {
  const findings = analyze(`
    pragma solidity ^0.8.0;
    contract A {
      function f(uint256 amt) public pure { require(amt > 0); }
    }
  `);
  assert.equal(byDetector(findings, "assert-violation").length, 0);
});

// ---------- Fix 53: SWC-123 ----------

test("SWC-123: a self-comparing require flags", () => {
  const findings = analyze(`
    pragma solidity ^0.8.0;
    contract A {
      uint256 x;
      function f() public view { require(x == x); }
    }
  `);
  const hits = byDetector(findings, "requirement-violation");
  assert.equal(hits.length, 1);
  assert.equal(hits[0].swc, "SWC-123");
});

test("SWC-123: a constant require flags", () => {
  const findings = analyze(`
    pragma solidity ^0.8.0;
    contract A {
      function f() public pure { require(true, "ok"); }
    }
  `);
  assert.equal(byDetector(findings, "requirement-violation").length, 1);
});

test("SWC-123: real requires stay silent", () => {
  const findings = analyze(`
    pragma solidity ^0.8.0;
    contract A {
      address owner;
      function f(uint256 amount) public view {
        require(amount > 0);
        require(msg.sender == owner);
      }
    }
  `);
  assert.equal(byDetector(findings, "requirement-violation").length, 0);
});

// ---------- Fix 56: SWC-125 ----------

test("SWC-125: contested base functions without an override flag", () => {
  const findings = analyze(`
    pragma solidity ^0.8.0;
    contract A { function foo() public pure returns (uint256) { return 1; } }
    contract B { function foo() public pure returns (uint256) { return 2; } }
    contract C is A, B { }
  `);
  const hits = byDetector(findings, "inheritance-order");
  assert.equal(hits.length, 1);
  assert.equal(hits[0].swc, "SWC-125");
  assert.match(hits[0].summary, /foo/);
});

test("SWC-125: an explicit override in the derived contract stays silent", () => {
  const findings = analyze(`
    pragma solidity ^0.8.0;
    contract A { function foo() public pure virtual returns (uint256) { return 1; } }
    contract B { function foo() public pure virtual returns (uint256) { return 2; } }
    contract C is A, B {
      function foo() public pure override(A, B) returns (uint256) { return 3; }
    }
  `);
  assert.equal(byDetector(findings, "inheritance-order").length, 0);
});

test("SWC-125: single inheritance stays silent", () => {
  const findings = analyze(`
    pragma solidity ^0.8.0;
    contract A { function foo() public pure returns (uint256) { return 1; } }
    contract C is A { }
  `);
  assert.equal(byDetector(findings, "inheritance-order").length, 0);
});

// ---------- Fix 54: SWC-126 ----------

test("SWC-126: an unstipulated call with dependent bookkeeping flags", () => {
  const findings = analyze(`
    pragma solidity ^0.8.0;
    contract R {
      bool done;
      function relay(address t, bytes calldata d) public {
        (bool ok, ) = t.call(d);
        require(ok);
        done = true;
      }
    }
  `);
  const hits = byDetector(findings, "gas-griefing");
  assert.equal(hits.length, 1);
  assert.equal(hits[0].swc, "SWC-126");
});

test("SWC-126: a gas stipulation stays silent", () => {
  const findings = analyze(`
    pragma solidity ^0.8.0;
    contract R {
      bool done;
      function relay(address t, bytes calldata d) public {
        (bool ok, ) = t.call{gas: 100000}(d);
        require(ok);
        done = true;
      }
    }
  `);
  assert.equal(byDetector(findings, "gas-griefing").length, 0);
});

test("SWC-126: call + require with no state write stays silent (the OZ sendValue shape)", () => {
  const findings = analyze(`
    pragma solidity ^0.8.0;
    contract R {
      function sendValue(address payable recipient, uint256 amount) public {
        (bool success, ) = recipient.call{value: amount}("");
        require(success, "Address: unable to send value");
      }
    }
  `);
  assert.equal(byDetector(findings, "gas-griefing").length, 0);
});

test("SWC-126: returning the call result directly stays silent", () => {
  const findings = analyze(`
    pragma solidity ^0.8.0;
    contract R {
      function f(address t) public returns (bool) {
        (bool ok, ) = t.call("");
        return ok;
      }
    }
  `);
  assert.equal(byDetector(findings, "gas-griefing").length, 0);
});

// ---------- Fix 57: SWC-127 ----------

test("SWC-127: a function-type variable plus assembly flags", () => {
  const findings = analyze(`
    pragma solidity ^0.8.0;
    contract J {
      function(uint256) internal handler;
      function f() public { assembly { } }
    }
  `);
  const hits = byDetector(findings, "function-type-jump");
  assert.equal(hits.length, 1);
  assert.equal(hits[0].swc, "SWC-127");
});

test("SWC-127: a function-type variable without assembly stays silent", () => {
  const findings = analyze(`
    pragma solidity ^0.8.0;
    contract J {
      function(uint256) internal handler;
      function g(uint256 x) internal { }
      function f() public { handler = g; }
    }
  `);
  assert.equal(byDetector(findings, "function-type-jump").length, 0);
});

test("SWC-127: assembly without a function-type variable stays silent", () => {
  const findings = analyze(`
    pragma solidity ^0.8.0;
    contract J {
      function f() public { assembly { } }
    }
  `);
  assert.equal(byDetector(findings, "function-type-jump").length, 0);
});

// ---------- Fix 55: SWC-129 ----------

test("SWC-129: =+ inside a loop over a computed value flags", () => {
  const findings = analyze(`
    pragma solidity ^0.8.0;
    contract T {
      uint256 total;
      function add(uint256[] memory fees) public {
        for (uint256 i = 0; i < fees.length; i++) { total =+ fees[i]; }
      }
    }
  `);
  const hits = byDetector(findings, "typographical-error");
  assert.equal(hits.length, 1);
  assert.equal(hits[0].swc, "SWC-129");
});

test("SWC-129: =- on a variable that accumulates elsewhere flags", () => {
  const findings = analyze(`
    pragma solidity ^0.8.0;
    contract T {
      uint256 total;
      function add(uint256 fee) public { total += fee; }
      function sub(uint256 fee) public { total =- fee; }
    }
  `);
  assert.equal(byDetector(findings, "typographical-error").length, 1);
});

test("SWC-129: a signed literal assignment stays silent", () => {
  const findings = analyze(`
    pragma solidity ^0.8.0;
    contract T {
      function f() public pure returns (int256) { int256 x = -1; return x; }
    }
  `);
  assert.equal(byDetector(findings, "typographical-error").length, 0);
});

test("SWC-129: correct compound assignment stays silent", () => {
  const findings = analyze(`
    pragma solidity ^0.8.0;
    contract T {
      uint256 total;
      function add(uint256 fee) public { total += fee; }
      function sub(uint256 fee) public { total -= fee; }
    }
  `);
  assert.equal(byDetector(findings, "typographical-error").length, 0);
});

// ---------- Fix 58: SWC-135 ----------

test("SWC-135: a discarded comparison flags", () => {
  const findings = analyze(`
    pragma solidity ^0.8.0;
    contract E {
      uint256 a;
      uint256 b;
      function f() public { a == b; }
    }
  `);
  const hits = byDetector(findings, "code-no-effects");
  assert.equal(hits.length, 1);
  assert.equal(hits[0].swc, "SWC-135");
});

test("SWC-135: an assignment stays silent", () => {
  const findings = analyze(`
    pragma solidity ^0.8.0;
    contract E {
      uint256 a;
      uint256 b;
      function f() public { a = b; }
    }
  `);
  assert.equal(byDetector(findings, "code-no-effects").length, 0);
});

test("SWC-135: delete statements and the bare-this idiom stay silent", () => {
  const findings = analyze(`
    pragma solidity ^0.8.0;
    contract E {
      mapping(uint256 => address) owners;
      function burn(uint256 id) public { delete owners[id]; }
      function data() public view returns (bytes memory) {
        this;
        return msg.data;
      }
    }
  `);
  assert.equal(byDetector(findings, "code-no-effects").length, 0);
});

test("SWC-135: comparisons in conditions and increments stay silent", () => {
  const findings = analyze(`
    pragma solidity ^0.8.0;
    contract E {
      uint256 a;
      uint256 b;
      function f() public {
        if (a == b) { a = 1; }
        require(a == b);
      }
      function g() public { uint256 i = 0; i++; }
    }
  `);
  assert.equal(byDetector(findings, "code-no-effects").length, 0);
});
