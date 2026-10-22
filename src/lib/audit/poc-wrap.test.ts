// src/lib/audit/poc-wrap.test.ts
// Unit tests for wrapPocSnippet: pass-through, Reenter shape, no-arg
// constructor, null shapes, and no duplicated header lines.

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { wrapPocSnippet, wrapPocSnippetWithReason } from "./poc-wrap.ts";

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
    assert.ok(wrapped.testFile.includes("contract PoC is Test"));
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

  it("fills a multi-param constructor (address, uint256) -> (target, 1 ether)", () => {
    const wrapped = wrapPocSnippet(`contract Hack {
    constructor(address a, uint256 b) {}
    function attack() external {}
}`);
    assert.ok(wrapped);
    assert.ok(wrapped.testFile.includes("Hack attacker = new Hack(target, 1 ether);"));
    assert.equal(wrapped.note, "Wrapped with defaults: constructor (address, uint256) -> (target, 1 ether)");
  });

  it("fills a non-address single-param constructor (uint256) -> (1 ether)", () => {
    const wrapped = wrapPocSnippet(`contract Hack {
    constructor(uint256 amount) {}
    function attack() external {}
}`);
    assert.ok(wrapped);
    assert.ok(wrapped.testFile.includes("Hack attacker = new Hack(1 ether);"));
    assert.ok(wrapped.note?.includes("constructor (uint256) -> (1 ether)"));
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

  it("fills an entry with params: attack(uint256) -> attack(1 ether)", () => {
    const wrapped = wrapPocSnippet(`contract Hack {
    function attack(uint256 amount) external {}
}`);
    assert.ok(wrapped);
    assert.ok(wrapped.testFile.includes("attacker.attack(1 ether);"));
    assert.equal(wrapped.note, "Wrapped with defaults: entry attack(uint256) -> attack(1 ether)");
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

describe("wrapPocSnippet name-aware address filling (Round 2)", () => {
  const DRAIN = `interface IVictim { function reclaimSurplusEth(address payable to) external; }
contract Drain {
    function go(address victim, address payable me) external {
        IVictim(victim).reclaimSurplusEth(me);
    }
}`;

  it("wraps Jer's Drain snippet to go(target, payable(address(attacker)))", () => {
    const wrapped = wrapPocSnippet(DRAIN);
    assert.ok(wrapped);
    assert.equal(wrapped.attackContract, "Drain");
    assert.equal(wrapped.entry, "go");
    assert.ok(wrapped.testFile.includes("attacker.go(target, payable(address(attacker)));"));
    assert.equal(
      wrapped.note,
      "Wrapped with defaults: entry go(address, address payable) -> go(target, payable(address(attacker)))",
    );
  });

  it("maps victim/target-named params to target", () => {
    for (const name of ["victim", "victimAddr", "target", "targetContract"]) {
      const wrapped = wrapPocSnippet(`contract Hack {
    function attack(address ${name}) external {}
}`);
      assert.ok(wrapped, name);
      assert.ok(wrapped.testFile.includes("attacker.attack(target);"), name);
    }
  });

  it("maps to/me/recipient/receiver/wallet/account/_to/_me-named params to the attacker", () => {
    const cases: Array<[string, string]> = [
      ["to", "attacker.attack(address(attacker));"],
      ["me", "attacker.attack(address(attacker));"],
      ["recipient", "attacker.attack(address(attacker));"],
      ["receiver", "attacker.attack(address(attacker));"],
      ["beneficiary", "attacker.attack(address(attacker));"],
      ["wallet", "attacker.attack(address(attacker));"],
      ["account", "attacker.attack(address(attacker));"],
      ["send_to", "attacker.attack(address(attacker));"],
      ["pay_to", "attacker.attack(address(attacker));"],
      ["payable_me", "attacker.attack(address(attacker));"],
    ];
    for (const [name, expected] of cases) {
      const wrapped = wrapPocSnippet(`contract Hack {
    function attack(address ${name}) external {}
}`);
      assert.ok(wrapped, name);
      assert.ok(wrapped.testFile.includes(expected), name);
    }
    // Payable recipient -> payable(address(attacker)).
    const payableMe = wrapPocSnippet(`contract Hack {
    function attack(address payable me) external {}
}`);
    assert.ok(payableMe);
    assert.ok(payableMe.testFile.includes("attacker.attack(payable(address(attacker)));"));
  });

  it("positional fallback: first address -> target, later addresses -> attacker", () => {
    const wrapped = wrapPocSnippet(`contract Hack {
    function attack(address a, address b) external {}
}`);
    assert.ok(wrapped);
    assert.ok(wrapped.testFile.includes("attacker.attack(target, address(attacker));"));
  });

  it("token-named param gets no victim hint (positional fallback applies)", () => {
    const alone = wrapPocSnippet(`contract Hack {
    function attack(address token) external {}
}`);
    assert.ok(alone);
    // Single address, first in its list -> target via fallback.
    assert.ok(alone.testFile.includes("attacker.attack(target);"));
    const withTo = wrapPocSnippet(`contract Hack {
    function attack(address token, address to) external {}
}`);
    assert.ok(withTo);
    assert.ok(withTo.testFile.includes("attacker.attack(target, address(attacker));"));
  });

  it("payable victim param -> payable(target); payable positional first -> payable(target)", () => {
    const victim = wrapPocSnippet(`contract Hack {
    function attack(address payable victim) external {}
}`);
    assert.ok(victim);
    assert.ok(victim.testFile.includes("attacker.attack(payable(target));"));
    const positional = wrapPocSnippet(`contract Hack {
    function attack(address payable a, address b) external {}
}`);
    assert.ok(positional);
    assert.ok(positional.testFile.includes("attacker.attack(payable(target), address(attacker));"));
  });

  it("go is lowest entry priority (attack beats go; go alone is detected)", () => {
    const both = wrapPocSnippet(`contract Hack {
    function attack() external {}
    function go() external {}
}`);
    assert.ok(both);
    assert.equal(both.entry, "attack");
    const onlyGo = wrapPocSnippet(`contract Hack {
    function go() external {}
}`);
    assert.ok(onlyGo);
    assert.equal(onlyGo.entry, "go");
    assert.ok(onlyGo.testFile.includes("attacker.go();"));
  });
});

describe("wrapPocSnippet param filling", () => {
  it("fills ctor (address, bool, string) -> (target, false, \"\")", () => {
    const wrapped = wrapPocSnippet(`contract Hack {
    constructor(address v, bool flag, string memory label) {}
    function attack() external {}
}`);
    assert.ok(wrapped);
    assert.ok(wrapped.testFile.includes('Hack attacker = new Hack(target, false, "");'));
    assert.equal(
      wrapped.note,
      "Wrapped with defaults: constructor (address, bool, string) -> (target, false, \"\")",
    );
  });

  it("fills both ctor and entry params and names both in the note", () => {
    const wrapped = wrapPocSnippet(`contract Hack {
    constructor(address v, uint256 seed) {}
    function attack(uint256 amount) external payable {}
}`);
    assert.ok(wrapped);
    assert.ok(wrapped.testFile.includes("Hack attacker = new Hack(target, 1 ether);"));
    assert.ok(wrapped.testFile.includes("attacker.attack{value: 1 ether}(1 ether);"));
    assert.equal(
      wrapped.note,
      "Wrapped with defaults: constructor (address, uint256) -> (target, 1 ether); entry attack(uint256) -> attack(1 ether)",
    );
  });

  it("fills fixed bytesN, dynamic arrays, int and bytes", () => {
    const wrapped = wrapPocSnippet(`contract Hack {
    constructor(bytes32 h, uint256[] ids, int128 delta, bytes data) {}
    function attack() external {}
}`);
    assert.ok(wrapped);
    assert.ok(
      wrapped.testFile.includes(
        "Hack attacker = new Hack(bytes32(0), new uint256[](0), 1 ether, \"\");",
      ),
    );
    assert.ok(wrapped.note?.includes("bytes32(0)"));
  });

  it("returns null for struct, fixed-array, nested-array and mapping params", () => {
    assert.equal(
      wrapPocSnippet(`contract Hack {
    struct S { uint256 x; }
    constructor(S memory s) {}
    function attack() external {}
}`),
      null,
    );
    assert.equal(
      wrapPocSnippet(`contract Hack {
    constructor(uint256[3] ids) {}
    function attack() external {}
}`),
      null,
    );
    assert.equal(
      wrapPocSnippet(`contract Hack {
    constructor(uint256[][] grid) {}
    function attack() external {}
}`),
      null,
    );
    assert.equal(
      wrapPocSnippet(`contract Hack {
    constructor(address v) {}
    function attack(mapping(address => uint256) m) external {}
}`),
      null,
    );
  });

  it("detects execute / drain / pwn entry names", () => {
    for (const name of ["execute", "drain", "pwn"]) {
      const wrapped = wrapPocSnippet(`contract Hack {
    function ${name}() external {}
}`);
      assert.ok(wrapped, name);
      assert.equal(wrapped.entry, name);
      assert.ok(wrapped.testFile.includes(`attacker.${name}();`));
    }
  });

  it("note is null for the plain 0-param shape, non-null when defaults are used", () => {
    const plain = wrapPocSnippet(`contract Hack {
    function attack() external {}
}`);
    assert.ok(plain);
    assert.equal(plain.note, null);
    const filled = wrapPocSnippet(`contract Hack {
    function attack(uint256 amount) external {}
}`);
    assert.ok(filled);
    assert.ok(filled.note);
    const passthrough = wrapPocSnippet(`contract MyExploit is Test {
    function test_poc() public { assertTrue(true); }
}`);
    assert.ok(passthrough);
    assert.equal(passthrough.note, null);
  });
});

describe("wrapPocSnippet test-contract name (Round 3)", () => {
  it("names the generated test contract PoC (backend runs --match-contract PoC)", () => {
    const wrapped = wrapPocSnippet(`contract Hack {
    function attack() external {}
}`);
    assert.ok(wrapped);
    assert.ok(wrapped.testFile.includes("contract PoC is Test"));
  });

  it("generated output contains no PocWrapTest string", () => {
    const wrapped = wrapPocSnippet(`contract Hack {
    function attack(uint256 amount) external {}
}`);
    assert.ok(wrapped);
    assert.ok(!wrapped.testFile.includes("PocWrapTest"));
  });

  it("renames a PoC-named attack contract to PoCAttack instead of returning null", () => {
    const wrapped = wrapPocSnippet(`contract PoC {
    function attack() external {}
}`);
    assert.ok(wrapped);
    assert.equal(wrapped.attackContract, "PoCAttack");
    assert.equal(wrapped.entry, "attack");
    // Renamed attack contract + exactly one `contract PoC` (the test contract).
    assert.ok(wrapped.testFile.includes("contract PoCAttack {"));
    assert.ok(wrapped.testFile.includes("contract PoC is Test"));
    assert.equal((wrapped.testFile.match(/contract PoC\b/g) ?? []).length, 1);
    assert.ok(wrapped.testFile.includes("PoCAttack attacker = new PoCAttack();"));
    assert.ok(wrapped.note?.includes("renamed attack contract PoC -> PoCAttack"));
  });

  it("renames PoC -> PoCAttack in Jer's Drain shape (go with victim/me params)", () => {
    const wrapped = wrapPocSnippet(`interface IVictim { function reclaimSurplusEth(address payable to) external; }
contract PoC {
    function go(address victim, address payable me) external {
        IVictim(victim).reclaimSurplusEth(me);
    }
}`);
    assert.ok(wrapped);
    assert.equal(wrapped.attackContract, "PoCAttack");
    assert.equal(wrapped.entry, "go");
    assert.ok(wrapped.testFile.includes("attacker.go(target, payable(address(attacker)));"));
    assert.ok(wrapped.note?.includes("renamed attack contract PoC -> PoCAttack"));
    assert.ok(wrapped.note?.includes("Wrapped with defaults:"));
  });

  it("does not rename PoC inside comments or string literals", () => {
    const wrapped = wrapPocSnippet(`contract Hack {
    // mentions PoC in a comment
    string public s = "PoC";
    function attack() external {}
}`);
    assert.ok(wrapped);
    assert.equal(wrapped.attackContract, "Hack");
    assert.ok(wrapped.testFile.includes("// mentions PoC in a comment"));
    assert.ok(wrapped.testFile.includes('"PoC"'));
    assert.ok(!wrapped.note?.includes("renamed"));
  });

  it("returns null with a reason when the snippet defines both PoC and PoCAttack", () => {
    const { wrapped, reason } = wrapPocSnippetWithReason(`contract PoC {
    function attack() external {}
}
contract PoCAttack {
    function foo() external {}
}`);
    assert.equal(wrapped, null);
    assert.ok(reason?.includes("both PoC and PoCAttack"));
  });
});

describe("wrapPocSnippetWithReason null reasons (Round 4)", () => {
  it("success yields reason null", () => {
    const { wrapped, reason } = wrapPocSnippetWithReason(`contract Hack {
    function attack() external {}
}`);
    assert.ok(wrapped);
    assert.equal(reason, null);
  });

  it("empty snippet -> empty-snippet reason", () => {
    for (const snippet of ["", "   "]) {
      const { wrapped, reason } = wrapPocSnippetWithReason(snippet);
      assert.equal(wrapped, null);
      assert.ok(reason?.includes("empty snippet"), snippet);
    }
  });

  it("no contract definitions -> reason names the cause", () => {
    const { wrapped, reason } = wrapPocSnippetWithReason(`// just a comment`);
    assert.equal(wrapped, null);
    assert.ok(reason?.includes("no contract definitions found"));
  });

  it("interfaces-only -> reason says interfaces only", () => {
    const { wrapped, reason } = wrapPocSnippetWithReason(
      `interface IVictim { function deposit() external payable; function withdraw() external; }`,
    );
    assert.equal(wrapped, null);
    assert.ok(reason?.includes("interfaces only"));
  });

  it("no entry function -> reason lists the entry names looked for", () => {
    const { wrapped, reason } = wrapPocSnippetWithReason(`contract Helper {
    function foo() external {}
}`);
    assert.equal(wrapped, null);
    assert.ok(reason?.includes("no entry function found"));
    // The looked-for list reflects the final entry search: the expanded
    // ENTRY_NAMES plus the prefix fallback.
    assert.ok(reason?.includes("attack/exploit/executeAttack/execute/seizeAndDrain/seize/poc/hack/run/drain/pwn/go"));
    assert.ok(reason?.includes("starting with attack/exploit/execute/drain/seize/pwn/take"));
  });

  it("unfillable constructor param -> constructor param type reason", () => {
    const { wrapped, reason } = wrapPocSnippetWithReason(`contract Hack {
    struct S { uint256 x; }
    constructor(S memory s) {}
    function attack() external {}
}`);
    assert.equal(wrapped, null);
    assert.ok(reason?.includes("constructor param type S is not fillable"));
  });

  it("unfillable fixed-array constructor param -> reason names the type", () => {
    const { wrapped, reason } = wrapPocSnippetWithReason(`contract Hack {
    constructor(uint256[3] ids) {}
    function attack() external {}
}`);
    assert.equal(wrapped, null);
    assert.ok(reason?.includes("constructor param type uint256[3] is not fillable"));
  });

  it("unfillable entry param -> entry param type reason (mapping parsed whole, balanced parens)", () => {
    const { wrapped, reason } = wrapPocSnippetWithReason(`contract Hack {
    constructor(address v) {}
    function attack(mapping(address => uint256) m) external {}
}`);
    assert.equal(wrapped, null);
    assert.ok(reason?.includes("entry param type mapping(address => uint256) is not fillable"));
  });

  it("unfillable constructor param with parens -> reason names the full type (balanced-paren parse)", () => {
    const { wrapped, reason } = wrapPocSnippetWithReason(`contract Hack {
    constructor(function(uint256) external cb) {}
    function attack() external {}
}`);
    assert.equal(wrapped, null);
    assert.ok(reason?.includes("constructor param type function(uint256) external is not fillable"));
  });

  it("wrapPocSnippet thin wrapper still returns null for null shapes", () => {
    assert.equal(wrapPocSnippet(``), null);
    assert.equal(
      wrapPocSnippet(`contract Helper {
    function foo() external {}
}`),
      null,
    );
  });
});
