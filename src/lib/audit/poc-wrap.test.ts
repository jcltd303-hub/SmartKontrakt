// src/lib/audit/poc-wrap.test.ts
// Unit tests for wrapPocSnippet: pass-through, Reenter shape, no-arg
// constructor, null shapes, and no duplicated header lines.

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { wrapPocSnippet } from "./poc-wrap.ts";

const REENTER = `interface IVictim { function deposit() external payable; function withdraw() external; }
contract Reenter {
    IVictim victim;
    uint256 hits;
    constructor(address v) { victim = IVictim(v); }
    function attack() external payable {
        victim.deposit{value: msg.value}();
        victim.withdraw();
    }
    receive() external payable {
        if (hits++ < 5 && address(victim).balance >= 1 ether) { victim.withdraw(); }
    }
}`;

describe("wrapPocSnippet pass-through", () => {
  it("returns an already-runnable Test snippet unchanged", () => {
    const snippet = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
import "forge-std/Test.sol";
contract MyExploit is Test {
    function test_poc() public {
        assertTrue(true);
    }
}`;
    const wrapped = wrapPocSnippet(snippet);
    assert.ok(wrapped);
    assert.equal(wrapped.testFile, snippet);
    assert.equal(wrapped.attackContract, "<existing>");
    assert.equal(wrapped.entry, "<existing>");
  });
});

describe("wrapPocSnippet Reenter shape", () => {
  it("wraps interface + constructor(address) + payable attack() with deploy/call/assert", () => {
    const wrapped = wrapPocSnippet(REENTER);
    assert.ok(wrapped);
    assert.equal(wrapped.attackContract, "Reenter");
    assert.equal(wrapped.entry, "attack");
    // Snippet kept verbatim.
    assert.ok(wrapped.testFile.includes(REENTER));
    // Missing header lines added (snippet has none).
    assert.ok(wrapped.testFile.includes("// SPDX-License-Identifier: MIT"));
    assert.ok(wrapped.testFile.includes("pragma solidity ^0.8.0;"));
    assert.ok(wrapped.testFile.includes('import "forge-std/Test.sol";'));
    // Test contract: fork via backend env, target from env, deploy, fund, call, assert.
    assert.ok(wrapped.testFile.includes('vm.createSelectFork(vm.envString("POC_RPC_URL"))'));
    assert.ok(wrapped.testFile.includes('address target = vm.envAddress("POC_TARGET")'));
    assert.ok(wrapped.testFile.includes("Reenter attacker = new Reenter(target);"));
    assert.ok(wrapped.testFile.includes("attacker.attack{value: 1 ether}();"));
    assert.ok(wrapped.testFile.includes('assertTrue(address(attacker).balance > attackerBefore || target.balance < targetBefore, "no value moved")'));
    assert.ok(wrapped.testFile.includes("contract PocWrapTest is Test"));
  });
});

describe("wrapPocSnippet constructor shapes", () => {
  it("wraps a no-arg constructor with new X()", () => {
    const wrapped = wrapPocSnippet(`contract Hack {
    constructor() {}
    function exploit() external {}
}`);
    assert.ok(wrapped);
    assert.equal(wrapped.attackContract, "Hack");
    assert.equal(wrapped.entry, "exploit");
    assert.ok(wrapped.testFile.includes("Hack attacker = new Hack();"));
    // Non-payable entry: plain call, no {value:}.
    assert.ok(wrapped.testFile.includes("attacker.exploit();"));
    assert.ok(!wrapped.testFile.includes("exploit{value:"));
  });

  it("wraps a contract with no constructor with new X()", () => {
    const wrapped = wrapPocSnippet(`contract Hack {
    function poc() external {}
}`);
    assert.ok(wrapped);
    assert.ok(wrapped.testFile.includes("Hack attacker = new Hack();"));
    assert.ok(wrapped.testFile.includes("attacker.poc();"));
  });

  it("returns null for a multi-param constructor", () => {
    assert.equal(
      wrapPocSnippet(`contract Hack {
    constructor(address a, uint256 b) {}
    function attack() external {}
}`),
      null,
    );
  });

  it("returns null for a non-address single-param constructor", () => {
    assert.equal(
      wrapPocSnippet(`contract Hack {
    constructor(uint256 amount) {}
    function attack() external {}
}`),
      null,
    );
  });
});

describe("wrapPocSnippet null shapes", () => {
  it("returns null for a snippet with no attack contract", () => {
    assert.equal(
      wrapPocSnippet(`contract Helper {
    function foo() external {}
}`),
      null,
    );
  });

  it("returns null for a snippet with only interfaces", () => {
    assert.equal(
      wrapPocSnippet(`interface IVictim { function deposit() external payable; function withdraw() external; }`),
      null,
    );
  });

  it("returns null for a snippet with no contract definitions", () => {
    assert.equal(wrapPocSnippet(`// just a comment`), null);
    assert.equal(wrapPocSnippet(``), null);
  });

  it("returns null when the entry function takes params", () => {
    assert.equal(
      wrapPocSnippet(`contract Hack {
    function attack(uint256 amount) external {}
}`),
      null,
    );
  });
});

describe("wrapPocSnippet header dedup", () => {
  it("does not duplicate pragma/SPDX/import the snippet already has", () => {
    const snippet = `// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.19;
import "forge-std/Test.sol";
contract Hack {
    function attack() external {}
}`;
    const wrapped = wrapPocSnippet(snippet);
    assert.ok(wrapped);
    const count = (text: string, re: RegExp) => (text.match(re) ?? []).length;
    assert.equal(count(wrapped.testFile, /SPDX-License-Identifier/g), 1);
    assert.equal(count(wrapped.testFile, /pragma solidity/g), 1);
    assert.equal(count(wrapped.testFile, /forge-std\/Test\.sol/g), 1);
    // Original values preserved (not overwritten with the defaults).
    assert.ok(wrapped.testFile.includes("GPL-3.0"));
    assert.ok(wrapped.testFile.includes("pragma solidity ^0.8.19;"));
  });
});
