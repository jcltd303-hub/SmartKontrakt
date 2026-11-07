import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { parseSource } from "./model.ts";
import { detectSource } from "./detect.ts";
import type { Finding } from "./types.ts";

/**
 * Regression fixtures for the 2026-11-06 ledger-driven detector
 * improvements (Fixes 39–44 in detect.ts, analyzer 2026-11-06.24).
 * Every change must prove BOTH directions: the adjudicated FP
 * archetype no longer flags (or demotes as specified) AND the real
 * archetype still flags.
 *
 * Ground truth: the 6,831-row adjudicated vet ledger
 * (full-vet/final-verdicts.csv, rounds 1–5) — confirmed-yield per
 * detector: tx-origin 239 rows / 0 confirmed, read-only-reentrancy
 * 453 / 0, delegatecall 679 / 0, unchecked-call 210 / 0,
 * erc20-unchecked 1,347 / 9 (the WBTCSwap class), unprotected-admin
 * 525 / 2 (ALIVA the one that mattered).
 *
 * The two fixture contracts are the real adjudicated sources:
 * fixtures/aliva.sol is ALIVA 0x640b43efe632409b0d41d4a00158c46024d862d6
 * (round 5, fork-confirmed pseudo-constructor) and fixtures/wbtcswap.sol
 * is WBTCSwap 0x8a92e4f744460cb42e346636c3db48a940327107 (round 5,
 * fork-confirmed drain through a false-returning token).
 */

function analyze(src: string): Finding[] {
  const model = parseSource(src);
  assert.equal(model.parseError, null);
  return detectSource(model, src);
}

function byDetector(findings: Finding[], detector: string): Finding[] {
  return findings.filter((f) => f.detector === detector);
}

function fromFile(rel: string): string {
  return readFileSync(new URL(rel, import.meta.url), "utf8");
}

// ---------------------------------------------------------------------------
// Fix 44: pseudo-constructor
// ---------------------------------------------------------------------------

const ALIVA = fromFile("./fixtures/aliva.sol");

test("pseudo-constructor: ALIVA's AlivaToken flags critical/high (real archetype)", () => {
  const hits = byDetector(analyze(ALIVA), "pseudo-constructor");
  assert.equal(hits.length, 1);
  assert.equal(hits[0].locationFn, "AlivaToken");
  assert.equal(hits[0].severity, "critical");
  assert.equal(hits[0].confidence, "high");
  assert.match(hits[0].summary, /ALIVA/);
});

test("pseudo-constructor: >=0.5 exact-name public function flags (Vault)", () => {
  const src = `
pragma solidity ^0.8.0;
contract Vault {
    address public owner;
    mapping (address => uint256) public balances;
    function Vault() public {
        owner = msg.sender;
        balances[msg.sender] += 1000;
    }
}`;
  const hits = byDetector(analyze(src), "pseudo-constructor");
  assert.equal(hits.length, 1);
  assert.equal(hits[0].severity, "critical");
});

test("pseudo-constructor: a real 0.4 exact-name constructor does NOT flag", () => {
  const src = `
pragma solidity ^0.4.24;
contract MyToken {
    address public owner;
    uint256 public totalSupply;
    function MyToken() public {
        owner = msg.sender;
        totalSupply = 1000;
    }
}`;
  assert.equal(byDetector(analyze(src), "pseudo-constructor").length, 0);
});

test("pseudo-constructor: access-controlled near-name function does NOT flag", () => {
  const src = `
pragma solidity ^0.4.24;
contract ALIVA2 {
    address public owner;
    mapping (address => uint256) balances;
    modifier onlyOwner() { require(msg.sender == owner); _; }
    function Aliva2Token() public onlyOwner {
        owner = msg.sender;
        balances[msg.sender] = balances[msg.sender] + 1000;
    }
}`;
  assert.equal(byDetector(analyze(src), "pseudo-constructor").length, 0);
});

test("pseudo-constructor: near-name function with no owner/mint effect does NOT flag", () => {
  const src = `
pragma solidity ^0.8.0;
contract AlivaInfo {
    uint256 public x;
    function AlivaInfoSupply() public view returns (uint256) {
        return x;
    }
}`;
  assert.equal(byDetector(analyze(src), "pseudo-constructor").length, 0);
});

// ---------------------------------------------------------------------------
// Fix 39: tx-origin split — EOA-gate is info, auth use stays high
// ---------------------------------------------------------------------------

test("tx-origin: revert-form onlyEOA gate (msg.sender != tx.origin) demotes to info (FP archetype)", () => {
  // TinfunReserve's onlyEOA shape, round-4 FP: the gate is written as
  // an if(!=) revert, which the ==-only stripper missed entirely, so
  // the modifier flagged as high-severity tx.origin authentication.
  const src = `
pragma solidity ^0.8.0;
contract OnlyEoa {
    uint256 public n;
    modifier onlyEOA() {
        if (msg.sender != tx.origin) revert("EOA only");
        _;
    }
    function play() external onlyEOA {
        n += 1;
    }
}`;
  const hits = byDetector(analyze(src), "tx-origin");
  assert.equal(hits.length, 1);
  assert.equal(hits[0].locationFn, "onlyEOA");
  assert.equal(hits[0].severity, "info");
});

test("tx-origin: require-form EOA-gate in a function demotes to info", () => {
  const src = `
pragma solidity ^0.8.0;
contract GateFn {
    uint256 public n;
    function play() external payable {
        require(msg.sender == tx.origin, "no contracts");
        n += 1;
    }
}`;
  const hits = byDetector(analyze(src), "tx-origin");
  assert.equal(hits.length, 1);
  assert.equal(hits[0].severity, "info");
});

test("tx-origin: tx.origin authorizing a value-moving function stays high (real archetype)", () => {
  const src = `
pragma solidity ^0.8.0;
contract OriginAuth {
    address public owner;
    constructor() { owner = msg.sender; }
    function withdraw() external {
        require(tx.origin == owner, "not owner");
        payable(msg.sender).transfer(address(this).balance);
    }
    receive() external payable {}
}`;
  const hits = byDetector(analyze(src), "tx-origin");
  assert.equal(hits.length, 1);
  assert.equal(hits[0].severity, "high");
  assert.match(hits[0].title, /authenticates with tx\.origin/);
});

// ---------------------------------------------------------------------------
// Fix 40: read-only-reentrancy — info unless the stale read feeds value
// ---------------------------------------------------------------------------

const BENIGN_RO = `
pragma solidity ^0.8.0;
contract BenignRO {
    uint256 public rate;
    uint256 public lastSeen;
    address public ext;
    constructor(address e) { ext = e; }
    function rebalance() external {
        (bool ok, ) = ext.call("");
        uint256 seen = rate;
        lastSeen = seen;
        rate = 0;
    }
}`;

test("read-only-reentrancy: bookkeeping consumer + fixed callee demotes to info (FP archetype)", () => {
  const hits = byDetector(analyze(BENIGN_RO), "read-only-reentrancy");
  assert.equal(hits.length, 1);
  assert.equal(hits[0].severity, "info");
  assert.match(hits[0].summary, /Calibrated: high → info/);
});

test("read-only-reentrancy: stale read feeding a payout stays high (real archetype)", () => {
  const src = `
pragma solidity ^0.8.0;
contract ValueRO {
    uint256 public rate;
    address public payee;
    address public ext;
    constructor(address p, address e) { payee = p; ext = e; rate = 3; }
    function rebalance() external {
        (bool ok, ) = ext.call("");
        uint256 payout = rate * 1 ether;
        payable(payee).transfer(payout);
        rate = 0;
    }
}`;
  const hits = byDetector(analyze(src), "read-only-reentrancy");
  assert.equal(hits.length, 1);
  assert.equal(hits[0].severity, "high");
});

test("read-only-reentrancy: caller-supplied callee keeps it high even with a bookkeeping consumer", () => {
  const src = BENIGN_RO.replace("address public ext;\n    constructor(address e) { ext = e; }\n    function rebalance() external {", "function rebalance(address ext) external {");
  const hits = byDetector(analyze(src), "read-only-reentrancy");
  assert.equal(hits.length, 1);
  assert.equal(hits[0].severity, "high");
});

// ---------------------------------------------------------------------------
// Fix 41: delegatecall — above info only when target or calldata is
// attacker-influenceable
// ---------------------------------------------------------------------------

test("delegatecall: caller-supplied target stays critical (real archetype)", () => {
  const src = `
pragma solidity ^0.8.0;
contract ParamExec {
    function exec(address target, bytes calldata data) external returns (bool) {
        (bool ok, ) = target.delegatecall(data);
        return ok;
    }
}`;
  const hits = byDetector(analyze(src), "delegatecall");
  assert.equal(hits.length, 1);
  assert.equal(hits[0].severity, "critical");
});

test("delegatecall: fixed target + fixed calldata demotes to info (FP archetype)", () => {
  const src = `
pragma solidity ^0.8.0;
contract FixedExec {
    address public implementation;
    constructor(address impl) { implementation = impl; }
    function exec() external returns (bool) {
        (bool ok, ) = implementation.delegatecall(abi.encodeWithSignature("ping()"));
        return ok;
    }
}`;
  const hits = byDetector(analyze(src), "delegatecall");
  assert.equal(hits.length, 1);
  assert.equal(hits[0].severity, "info");
});

test("delegatecall: fixed target + caller-supplied calldata stays high", () => {
  const src = `
pragma solidity ^0.8.0;
contract DataExec {
    address public implementation;
    constructor(address impl) { implementation = impl; }
    function exec(bytes calldata data) external returns (bool) {
        (bool ok, ) = implementation.delegatecall(data);
        return ok;
    }
}`;
  const hits = byDetector(analyze(src), "delegatecall");
  assert.equal(hits.length, 1);
  assert.equal(hits[0].severity, "high");
});

test("delegatecall: library utility with no contract call site stays silent (Fix 24 regression)", () => {
  const src = `
pragma solidity ^0.8.0;
library Fwd {
    function fwd(address t, bytes memory d) internal returns (bool) {
        (bool ok, ) = t.delegatecall(d);
        return ok;
    }
}
contract Bystander {
    function g() external pure returns (uint256) { return 1; }
}`;
  assert.equal(byDetector(analyze(src), "delegatecall").length, 0);
});

// ---------------------------------------------------------------------------
// Fix 42: unchecked-call — one notch down, note in summary
// ---------------------------------------------------------------------------

test("unchecked-call: call demotes high->medium, send medium->low, checked stays silent", () => {
  const src = `
pragma solidity ^0.8.0;
contract Payout {
    function pay(address target) external {
        target.call("");
    }
    function payChecked(address target) external {
        (bool ok, ) = target.call("");
        require(ok, "failed");
    }
    function paySend(address target) external {
        payable(target).send(1 ether);
    }
}`;
  const hits = byDetector(analyze(src), "unchecked-call");
  const pay = hits.find((f) => f.locationFn === "pay");
  const send = hits.find((f) => f.locationFn === "paySend");
  assert.ok(pay && send);
  assert.equal(pay.severity, "medium");
  assert.match(pay.summary, /Calibrated: severity lowered one notch/);
  assert.equal(send.severity, "low");
  assert.equal(hits.some((f) => f.locationFn === "payChecked"), false);
});

// ---------------------------------------------------------------------------
// Fix 43: erc20-unchecked — write-after-call raises confidence (WBTCSwap)
// ---------------------------------------------------------------------------

const WBTCSWAP = fromFile("./fixtures/wbtcswap.sol");

test("erc20-unchecked: WBTCSwap initiate/initiateWithFees raise to high confidence (real archetype)", () => {
  const hits = byDetector(analyze(WBTCSWAP), "erc20-unchecked");
  for (const fn of ["initiate", "initiateWithFees"]) {
    const hit = hits.find((f) => f.locationFn === fn);
    assert.ok(hit, `${fn} flagged`);
    assert.equal(hit.severity, "high");
    assert.equal(hit.confidence, "high");
    assert.match(hit.summary, /Confidence raised/);
  }
});

test("erc20-unchecked: WBTCSwap write-before-call functions keep medium confidence", () => {
  const hits = byDetector(analyze(WBTCSWAP), "erc20-unchecked");
  for (const fn of ["refund", "withdrawBrokerFees", "redeem"]) {
    const hit = hits.find((f) => f.locationFn === fn);
    assert.ok(hit, `${fn} flagged`);
    assert.equal(hit.confidence, "medium");
    assert.doesNotMatch(hit.summary, /Confidence raised/);
  }
});
