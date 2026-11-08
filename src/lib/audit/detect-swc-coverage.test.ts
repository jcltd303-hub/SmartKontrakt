import test from "node:test";
import assert from "node:assert/strict";
import { parseSource } from "./model.ts";
import { detectSource } from "./detect.ts";
import type { Finding } from "./types.ts";

/**
 * Regression fixtures for the SWC coverage batch, first half
 * (Fixes 45–51 in detect.ts, analyzer 2026-11-06.25). Every detector
 * must prove BOTH directions: the real registry shape flags AND the
 * corrected shape stays silent.
 *
 * The classes: SWC-102 (old-compiler re-stamp), SWC-108 (state
 * variable default visibility), SWC-109 (uninitialized storage
 * pointer — the shape that killed CryptoRoulette 0xfb6e71e0's play()
 * in the vet program), SWC-111 (deprecated Solidity), SWC-113 (DoS
 * with failed call), SWC-128 (DoS with block gas limit), SWC-131
 * (unused variables).
 */

function analyze(src: string): Finding[] {
  const model = parseSource(src);
  assert.equal(model.parseError, null);
  return detectSource(model, src);
}

function byDetector(findings: Finding[], detector: string): Finding[] {
  return findings.filter((f) => f.detector === detector);
}

// ---------- Fix 45: SWC-102 ----------

test("SWC-102: old-compiler findings are stamped SWC-102, not SWC-101", () => {
  const findings = analyze(`
    pragma solidity ^0.7.6;
    contract Old {
      uint256 public x;
      function set(uint256 v) public { x = v; }
    }
  `);
  const hits = byDetector(findings, "old-compiler");
  assert.equal(hits.length, 1);
  assert.equal(hits[0].swc, "SWC-102");
});

// ---------- Fix 46: SWC-108 ----------

test("SWC-108: a state variable with no visibility flags", () => {
  const findings = analyze(`
    pragma solidity ^0.8.0;
    contract C {
      uint256 total;
      uint256 public shown;
      function f() public { shown = total; }
    }
  `);
  const hits = byDetector(findings, "state-var-default-visibility");
  assert.equal(hits.length, 1);
  assert.equal(hits[0].swc, "SWC-108");
  assert.match(hits[0].summary, /total/);
  assert.doesNotMatch(hits[0].summary, /shown/);
});

test("SWC-108: explicit visibilities stay silent", () => {
  const findings = analyze(`
    pragma solidity ^0.8.0;
    contract C {
      uint256 private total;
      uint256 public shown;
      function f() public { shown = total; }
    }
  `);
  assert.equal(byDetector(findings, "state-var-default-visibility").length, 0);
});

// ---------- Fix 47: SWC-109 ----------

test("SWC-109: an uninitialized struct local pre-0.5 flags", () => {
  const findings = analyze(`
    pragma solidity ^0.4.25;
    contract Game {
      struct Entry { uint256 bet; address player; }
      uint256 secret;
      function play() public {
        Entry e;
        e.bet = 1;
      }
    }
  `);
  const hits = byDetector(findings, "uninitialized-storage-pointer");
  assert.equal(hits.length, 1);
  assert.equal(hits[0].swc, "SWC-109");
  assert.equal(hits[0].severity, "high");
});

test("SWC-109: an uninitialized array local pre-0.5 flags", () => {
  const findings = analyze(`
    pragma solidity ^0.4.25;
    contract A {
      uint256 x;
      function f() public {
        uint256[] arr;
        arr.push(1);
      }
    }
  `);
  assert.equal(byDetector(findings, "uninitialized-storage-pointer").length, 1);
});

test("SWC-109: an explicit memory local stays silent", () => {
  const findings = analyze(`
    pragma solidity ^0.4.25;
    contract Game {
      struct Entry { uint256 bet; address player; }
      uint256 secret;
      function play() public {
        Entry memory e;
        e.bet = 1;
      }
    }
  `);
  assert.equal(byDetector(findings, "uninitialized-storage-pointer").length, 0);
});

test("SWC-109: the rule is version-gated off at 0.5+", () => {
  const findings = analyze(`
    pragma solidity ^0.8.24;
    contract Game {
      struct Entry { uint256 bet; address player; }
      uint256 secret;
      function play() public {
        Entry e;
        e.bet = 1;
      }
    }
  `);
  assert.equal(byDetector(findings, "uninitialized-storage-pointer").length, 0);
});

// ---------- Fix 48: SWC-111 ----------

test("SWC-111: suicide and sha3 flag as deprecated", () => {
  const findings = analyze(`
    pragma solidity ^0.4.25;
    contract Old {
      function kill() public { suicide(msg.sender); }
      function h() public { bytes32 y = sha3("abc"); }
    }
  `);
  const hits = byDetector(findings, "deprecated-solidity");
  assert.equal(hits.length, 2);
  assert.equal(hits[0].swc, "SWC-111");
});

test("SWC-111: modern spellings stay silent", () => {
  const findings = analyze(`
    pragma solidity ^0.8.24;
    contract Modern {
      function kill() public { selfdestruct(payable(msg.sender)); }
      function h() public pure returns (bytes32) { return keccak256("abc"); }
    }
  `);
  assert.equal(byDetector(findings, "deprecated-solidity").length, 0);
});

// ---------- Fix 49: SWC-113 ----------

test("SWC-113: pushing transfers in a loop over a collection flags", () => {
  const findings = analyze(`
    pragma solidity ^0.8.0;
    contract Pay {
      address payable[] payees;
      function distribute() public {
        for (uint256 i = 0; i < payees.length; i++) {
          payees[i].transfer(1 ether);
        }
      }
    }
  `);
  const hits = byDetector(findings, "dos-failed-call");
  assert.equal(hits.length, 1);
  assert.equal(hits[0].swc, "SWC-113");
});

test("SWC-113: the pull pattern stays silent", () => {
  const findings = analyze(`
    pragma solidity ^0.8.0;
    contract Pull {
      mapping(address => uint256) pending;
      function withdraw() public {
        uint256 amt = pending[msg.sender];
        pending[msg.sender] = 0;
        payable(msg.sender).transfer(amt);
      }
    }
  `);
  assert.equal(byDetector(findings, "dos-failed-call").length, 0);
});

// ---------- Fix 50: SWC-128 ----------

test("SWC-128: a loop bounded by a storage array's length flags", () => {
  const findings = analyze(`
    pragma solidity ^0.8.0;
    contract Reg {
      address[] users;
      function count() public view returns (uint256) {
        uint256 n = 0;
        for (uint256 i = 0; i < users.length; i++) { n += 1; }
        return n;
      }
    }
  `);
  const hits = byDetector(findings, "dos-block-gas-limit");
  assert.equal(hits.length, 1);
  assert.equal(hits[0].swc, "SWC-128");
});

test("SWC-128: a loop over a memory parameter stays silent", () => {
  const findings = analyze(`
    pragma solidity ^0.8.0;
    contract B {
      function f(address[] memory xs) public pure returns (uint256) {
        uint256 n = 0;
        for (uint256 i = 0; i < xs.length; i++) { n += 1; }
        return n;
      }
    }
  `);
  assert.equal(byDetector(findings, "dos-block-gas-limit").length, 0);
});

test("SWC-128: a fixed literal bound over a storage array stays silent", () => {
  const findings = analyze(`
    pragma solidity ^0.8.0;
    contract C2 {
      uint256[] vals;
      function g() public {
        for (uint256 i = 0; i < 10; i++) { vals[i] = i; }
      }
    }
  `);
  assert.equal(byDetector(findings, "dos-block-gas-limit").length, 0);
});

// ---------- Fix 51: SWC-131 ----------

test("SWC-131: an unused state variable flags", () => {
  const findings = analyze(`
    pragma solidity ^0.8.0;
    contract D {
      uint256 private dead;
      uint256 public alive;
      function f() public { alive = 1; }
    }
  `);
  const hits = byDetector(findings, "unused-variable");
  assert.equal(hits.length, 1);
  assert.equal(hits[0].swc, "SWC-131");
  assert.match(hits[0].summary, /dead/);
});

test("SWC-131: a used state variable stays silent", () => {
  const findings = analyze(`
    pragma solidity ^0.8.0;
    contract D {
      uint256 private kept;
      function f() public { kept = 1; }
      function g() public view returns (uint256) { return kept; }
    }
  `);
  assert.equal(byDetector(findings, "unused-variable").length, 0);
});

test("SWC-131: an ignored parameter flags, a used one does not", () => {
  const findings = analyze(`
    pragma solidity ^0.8.0;
    contract E {
      function f(uint256 used, uint256 orphan) public pure returns (uint256) {
        return used;
      }
    }
  `);
  const hits = byDetector(findings, "unused-variable");
  assert.equal(hits.length, 1);
  assert.match(hits[0].title, /orphan/);
  assert.doesNotMatch(hits[0].title, /used/);
});

test("SWC-131: all-used parameters stay silent", () => {
  const findings = analyze(`
    pragma solidity ^0.8.0;
    contract E {
      function f(uint256 a, uint256 b) public pure returns (uint256) {
        return a + b;
      }
    }
  `);
  assert.equal(byDetector(findings, "unused-variable").length, 0);
});
