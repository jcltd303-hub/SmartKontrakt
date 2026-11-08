import test from "node:test";
import assert from "node:assert/strict";
import { parseSource } from "./model.ts";
import { detectSource } from "./detect.ts";
import type { Finding } from "./types.ts";

/**
 * Regression fixtures for Fixes 59–60 (analyzer 2026-11-07.27), from
 * the SmartBugs Curated benchmark run of 2026-11-07: Fix 44's
 * pseudo-constructor caught only 1 of the dataset's 5 incorrect-
 * constructor exemplars, and SWC-124 had no source-level rule at
 * all (0 of 2 exemplars). Every shape proves BOTH directions: the
 * exemplar flags AND the corrected/legitimate shape stays silent.
 */

function analyze(src: string): Finding[] {
  const model = parseSource(src);
  assert.equal(model.parseError, null);
  return detectSource(model, src);
}

function byDetector(findings: Finding[], detector: string): Finding[] {
  return findings.filter((f) => f.detector === detector);
}

// ---------- Fix 59: SWC-118 widening ----------

test("SWC-118: containment — IamMissing in Missing flags (name1)", () => {
  const findings = analyze(`
    pragma solidity ^0.4.24;
    contract Missing {
      address private owner;
      function IamMissing() public { owner = msg.sender; }
    }
  `);
  const hits = byDetector(findings, "pseudo-constructor");
  assert.equal(hits.length, 1);
  assert.equal(hits[0].swc, "SWC-118");
  assert.equal(hits[0].severity, "high");
});

test("SWC-118: case-folded exact name flags — missing() in Missing (name2)", () => {
  // The one exemplar Fix 44 caught; the Fix 59 working-constructor
  // gate must not disarm it — solc honors only an EXACT case match
  // as a constructor, so `missing` is an ordinary public function.
  const findings = analyze(`
    pragma solidity ^0.4.24;
    contract Missing {
      address private owner;
      function missing() public { owner = msg.sender; }
    }
  `);
  const hits = byDetector(findings, "pseudo-constructor");
  assert.equal(hits.length, 1);
  assert.equal(hits[0].swc, "SWC-118");
});

test("SWC-118: a function literally named Constructor flags (name3)", () => {
  const findings = analyze(`
    pragma solidity ^0.4.24;
    contract Missing {
      address private owner;
      function Constructor() public { owner = msg.sender; }
    }
  `);
  const hits = byDetector(findings, "pseudo-constructor");
  assert.equal(hits.length, 1);
  assert.equal(hits[0].swc, "SWC-118");
});

test("SWC-118: containment + creator — initWallet in Wallet flags (wallet_03)", () => {
  const findings = analyze(`
    pragma solidity ^0.4.24;
    contract Wallet {
      address creator;
      function initWallet() public { creator = msg.sender; }
    }
  `);
  const hits = byDetector(findings, "pseudo-constructor");
  assert.equal(hits.length, 1);
  assert.equal(hits[0].severity, "high");
});

test("SWC-118: absent constructor — DynamicPyramid in Rubixi flags at the lower tier", () => {
  const findings = analyze(`
    pragma solidity ^0.4.15;
    contract Rubixi {
      address private creator;
      function DynamicPyramid() public { creator = msg.sender; }
    }
  `);
  const hits = byDetector(findings, "pseudo-constructor");
  assert.equal(hits.length, 1);
  assert.equal(hits[0].swc, "SWC-118");
  // No name relation at all: one tier below the name-matched shape.
  assert.equal(hits[0].severity, "medium");
  assert.equal(hits[0].confidence, "low");
});

test("SWC-118: absent constructor with owner + mint flags high", () => {
  const findings = analyze(`
    pragma solidity ^0.4.24;
    contract Vault {
      address owner;
      mapping(address => uint256) balances;
      function initialize() public {
        owner = msg.sender;
        balances[msg.sender] += 1000;
      }
    }
  `);
  const hits = byDetector(findings, "pseudo-constructor");
  assert.equal(hits.length, 1);
  assert.equal(hits[0].severity, "high");
  assert.equal(hits[0].confidence, "medium");
});

test("SWC-118: name-matched with owner + mint stays critical (ALIVA shape)", () => {
  const findings = analyze(`
    pragma solidity ^0.4.18;
    contract ALIVA {
      address owner;
      uint256 totalSupply;
      function AlivaToken() public {
        owner = msg.sender;
        totalSupply += 1000000;
      }
    }
  `);
  const hits = byDetector(findings, "pseudo-constructor");
  assert.equal(hits.length, 1);
  assert.equal(hits[0].severity, "critical");
  assert.equal(hits[0].confidence, "high");
});

test("SWC-118: a real name-based constructor disarms the absent shape", () => {
  const findings = analyze(`
    pragma solidity ^0.4.24;
    contract Token {
      address owner;
      function Token() public { owner = msg.sender; }
      function setOwner(address o) public { owner = o; }
    }
  `);
  assert.equal(byDetector(findings, "pseudo-constructor").length, 0);
});

test("SWC-118: a constructor inherited from an in-source base disarms the absent shape", () => {
  const findings = analyze(`
    pragma solidity ^0.4.24;
    contract Base {
      function Base() public { }
    }
    contract Child is Base {
      address admin;
      function setup() public { admin = msg.sender; }
    }
  `);
  assert.equal(byDetector(findings, "pseudo-constructor").length, 0);
});

test("SWC-118: absent shape is pre-0.5 only — 0.8 initialize stays silent here", () => {
  const findings = analyze(`
    pragma solidity ^0.8.0;
    contract Vault {
      address owner;
      constructor() { owner = msg.sender; }
      function initialize() public { owner = msg.sender; }
    }
  `);
  assert.equal(byDetector(findings, "pseudo-constructor").length, 0);
});

test("SWC-118: an authed look-alike stays silent", () => {
  const findings = analyze(`
    pragma solidity ^0.4.24;
    contract Missing {
      address private owner;
      modifier onlyOwner { require(msg.sender == owner); _; }
      function IamMissing() public onlyOwner { owner = msg.sender; }
    }
  `);
  assert.equal(byDetector(findings, "pseudo-constructor").length, 0);
});

test("SWC-118: a substring verb with no privileged effect stays silent", () => {
  const findings = analyze(`
    pragma solidity ^0.4.24;
    contract Art {
      uint256 count;
      function start() public { count += 1; }
    }
  `);
  assert.equal(byDetector(findings, "pseudo-constructor").length, 0);
});

test("SWC-118: reverse-prefix stays excluded — burn in BurnableToken", () => {
  const findings = analyze(`
    pragma solidity ^0.8.0;
    contract BurnableToken {
      uint256 totalSupply;
      function burn(uint256 a) public { totalSupply += a; }
    }
  `);
  assert.equal(byDetector(findings, "pseudo-constructor").length, 0);
});

test("SWC-118: a super-call to an authed base initializer disarms the absent shape", () => {
  // The Marketplace shape from the corpus smoke: the derived
  // initialize sets owner, but it first runs the base's initialize,
  // whose body requires the registry — the gate is real, one hop up.
  const findings = analyze(`
    pragma solidity ^0.4.24;
    contract Upgradeable {
      address registry;
      function initialize(address sender) public payable {
        require(msg.sender == address(registry));
      }
    }
    contract Marketplace is Upgradeable {
      address public owner;
      function initialize(address sender) public payable {
        super.initialize(sender);
        owner = sender;
      }
    }
  `);
  assert.equal(byDetector(findings, "pseudo-constructor").length, 0);
});

test("SWC-118: a super-call to an UNauthed base function does not disarm it", () => {
  const findings = analyze(`
    pragma solidity ^0.4.24;
    contract Base2 {
      function initialize(address sender) public payable { }
    }
    contract Shop is Base2 {
      address public owner;
      function initialize(address sender) public payable {
        super.initialize(sender);
        owner = sender;
      }
    }
  `);
  const hits = byDetector(findings, "pseudo-constructor");
  assert.equal(hits.length, 1);
  assert.equal(hits[0].severity, "medium");
});

test("SWC-118: a working constructor disarms containment — the Dust converters", () => {
  // Corpus FP from the Fix 59 smoke: contract Dust has a real
  // name-based constructor; convertEtherToDust merely CONTAINS the
  // contract name and its _transfer callee credits balances (a
  // mint-shaped effect). Not a pseudo-constructor.
  const findings = analyze(`
    pragma solidity ^0.4.21;
    contract Dust {
      address owner;
      mapping(address => uint256) balances;
      function Dust() public { owner = msg.sender; }
      function _transfer(address to, uint256 amount) internal {
        balances[to] += amount;
      }
      function convertEtherToDust() public payable {
        _transfer(msg.sender, msg.value);
      }
    }
  `);
  assert.equal(byDetector(findings, "pseudo-constructor").length, 0);
});

// ---------- Fix 60: SWC-124 source-level arbitrary write ----------

test("SWC-124: length grown to fit the key flags (mapping_write)", () => {
  const findings = analyze(`
    pragma solidity ^0.4.24;
    contract Map {
      uint256[] map;
      function set(uint256 key, uint256 value) public {
        if (map.length <= key) { map.length = key + 1; }
        map[key] = value;
      }
    }
  `);
  const hits = byDetector(findings, "arbitrary-storage-write");
  assert.equal(hits.length, 1);
  assert.equal(hits[0].swc, "SWC-124");
  assert.equal(hits[0].severity, "high");
});

test("SWC-124: bounded write + unauthed length decrement flags (arbitrary_location_write)", () => {
  const findings = analyze(`
    pragma solidity ^0.4.25;
    contract Wallet {
      uint[] bonusCodes;
      function PopBonusCode() public {
        require(bonusCodes.length > 0);
        bonusCodes.length--;
      }
      function UpdateBonusCodeAt(uint idx, uint c) public {
        require(idx < bonusCodes.length);
        bonusCodes[idx] = c;
      }
    }
  `);
  const hits = byDetector(findings, "arbitrary-storage-write");
  assert.equal(hits.length, 1);
  assert.equal(hits[0].locationFn, "UpdateBonusCodeAt");
});

test("SWC-124: length decrement in the writing function itself flags", () => {
  const findings = analyze(`
    pragma solidity ^0.4.24;
    contract E {
      uint[] a;
      function f(uint i, uint v) public {
        a.length--;
        a[i] = v;
      }
    }
  `);
  assert.equal(byDetector(findings, "arbitrary-storage-write").length, 1);
});

test("SWC-124: a bounded setter whose length nobody can move stays silent", () => {
  const findings = analyze(`
    pragma solidity ^0.4.24;
    contract A {
      uint[] arr;
      function pushIt(uint v) public { arr.push(v); }
      function set(uint i, uint v) public {
        require(i < arr.length);
        arr[i] = v;
      }
    }
  `);
  assert.equal(byDetector(findings, "arbitrary-storage-write").length, 0);
});

test("SWC-124: mapping writes stay silent even with a length decrement nearby", () => {
  const findings = analyze(`
    pragma solidity ^0.4.24;
    contract B {
      mapping(address => uint256) balances;
      uint[] log;
      function shrink() public { log.length--; }
      function set(address u, uint256 v) public { balances[u] = v; }
    }
  `);
  assert.equal(byDetector(findings, "arbitrary-storage-write").length, 0);
});

test("SWC-124: the authed version stays silent", () => {
  const findings = analyze(`
    pragma solidity ^0.4.24;
    contract Map2 {
      address owner;
      uint256[] map;
      modifier onlyOwner { require(msg.sender == owner); _; }
      function set(uint256 key, uint256 value) public onlyOwner {
        if (map.length <= key) { map.length = key + 1; }
        map[key] = value;
      }
    }
  `);
  assert.equal(byDetector(findings, "arbitrary-storage-write").length, 0);
});

test("SWC-124: a constant index stays silent even with length manipulation", () => {
  const findings = analyze(`
    pragma solidity ^0.4.24;
    contract C {
      uint[] arr;
      function poke() public { arr.length--; }
      function set(uint v) public { arr[0] = v; }
    }
  `);
  assert.equal(byDetector(findings, "arbitrary-storage-write").length, 0);
});

test("SWC-124: member-of-element writes stay silent", () => {
  const findings = analyze(`
    pragma solidity ^0.4.24;
    contract D {
      struct P { uint256 x; }
      P[] ps;
      function set(uint i, uint v) public {
        ps.length = i + 1;
        ps[i].x = v;
      }
    }
  `);
  assert.equal(byDetector(findings, "arbitrary-storage-write").length, 0);
});

test("SWC-124: a literal-0 length reset is not malleability", () => {
  const findings = analyze(`
    pragma solidity ^0.4.24;
    contract F {
      uint[] arr;
      function clear() public { arr.length = 0; }
      function set(uint i, uint v) public {
        require(i < arr.length);
        arr[i] = v;
      }
    }
  `);
  assert.equal(byDetector(findings, "arbitrary-storage-write").length, 0);
});
