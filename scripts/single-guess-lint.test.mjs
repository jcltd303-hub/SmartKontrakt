/**
 * Tests for the single-guess lint.
 *
 * A lint is only worth trusting if each rule provably fires. A rule with a
 * broken regex reports "clean" — false confidence in exactly the direction that
 * hides real findings — so every shape below has a synthetic POSITIVE (must be
 * flagged) and a NEGATIVE (must not be). The last test then runs the lint over
 * the 46 real templates.
 */
import test from "node:test";
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { SHAPE_IDS, callShapes, lintErrors, lintTemplate } from "./single-guess-lint.mjs";

const FALLBACKS = fileURLToPath(new URL("../foundry/poc-fallbacks/", import.meta.url));

/** A converted-style walk: several shapes, disclosed failure. */
const WALK = `
    function _attempt(address who, uint256 before, string memory label, bytes memory data)
        internal returns (string memory)
    {
        vm.prank(who);
        (bool ok,) = target.call(data);
        console.log("tried", label, ok ? "call returned" : "call reverted");
        if (ok && who.balance > before) return label;
        return "";
    }

    function test_exploit() public {
        string memory used = _attempt(a, 0, "withdraw()", abi.encodeWithSignature("withdraw()"));
        if (bytes(used).length == 0) {
            used = _attempt(a, 0, "claim()", abi.encodeWithSignature("claim()"));
        }
        assertTrue(bytes(used).length > 0, "no exit worked. Tried withdraw(), claim(). This does NOT establish safety.");
    }
`;

/** Each entry: [shape id, source that MUST be flagged, source that MUST NOT]. */
const CASES = [
  [
    "adapt-precondition",
    `function test_exploit() public {
        (bool upOk,) = target.call(abi.encodeWithSignature("upgradeTo(address)", impl));
        require(upOk, "upgradeTo failed -- upgrade is guarded or entry differs (adapt it)");
    }`,
    WALK,
  ],
  [
    "stub",
    `function test_exploit() public {
        revert("TEMPLATE_NOT_ADAPTED: target-specific exploit assertion required");
    }`,
    WALK,
  ],
  ["skipped", `function test_exploit() public { vm.skip(true); }`, WALK],
  [
    "call-success-assert",
    `function test_exploit() public {
        (bool secondOk,) = target.call(abi.encodeWithSignature("claim(bytes32[],uint256)", proof, AMOUNT));
        assertTrue(secondOk, "exploit did not reproduce: second claim was rejected");
    }`,
    WALK,
  ],
  [
    "call-success-assert",
    `function test_exploit() public {
        (bool ok,) = target.call(abi.encodeWithSignature("mint()"));
        assertTrue(ok, "exploit failed");
    }`,
    WALK,
  ],
  [
    "call-success-assert",
    `function test_exploit() public {
        assertEq(transferOk, true, "transfer did not go through");
    }`,
    WALK,
  ],
  [
    "vacuous-catch",
    `function test_exploit() public {
        try target.call(abi.encodeWithSignature("withdraw()")) {} catch {}
    }`,
    `function test_exploit() public {
        try target.call(abi.encodeWithSignature("withdraw()")) {} catch { console.log("reverted"); }
        assertGt(target.balance, 0, "still holds ETH. Tried withdraw(). This does NOT establish safety.");
    }`,
  ],
  ["always-pass", `function test_exploit() public { assertTrue(true, "ok"); }`, WALK],
  ["always-pass", `function test_exploit() public { uint256 x = 1; assertEq(x, x); }`, WALK],
  [
    "early-return-void",
    `function test_exploit() public {
        (bool ok,) = target.call(abi.encodeWithSignature("withdraw()"));
        if (!ok) return;
        assertGt(target.balance, 0, "held. Tried withdraw(). This does NOT establish safety.");
    }`,
    WALK,
  ],
  [
    "no-verdict-assert",
    `function test_exploit() public { console.log("nothing was checked"); }`,
    WALK,
  ],
  [
    "single-shape-guess",
    `function test_exploit() public {
        (bool ok,) = target.call(abi.encodeWithSignature("withdraw()"));
        ok;
    }`,
    WALK,
  ],
  [
    "undisclosed-failure",
    `function test_exploit() public {
        (bool ok,) = target.call(abi.encodeWithSignature("withdraw()"));
        ok;
        assertGt(target.balance, 0, "exploit did not reproduce: no per-iteration msg.value leak");
    }`,
    WALK,
  ],
  [
    "delegatecall-single",
    `function test_exploit() public {
        target.delegatecall(abi.encodeWithSignature("pwn()"));
        assertEq(owner(), a, "not taken over");
    }`,
    `function test_exploit() public {
        target.delegatecall(abi.encodeWithSignature("pwn()"));
        target.delegatecall(abi.encodeWithSignature("takeover()"));
        assertEq(owner(), a, "no takeover. Tried pwn(), takeover(). This does NOT establish safety.");
    }`,
  ],
  [
    "todo-in-verdict",
    `function test_exploit() public {
        // TODO: adapt the assertion to the target's real observable
        assertTrue(true);
    }`,
    WALK,
  ],
  [
    "bare-call-precondition",
    `function test_exploit() public {
        (bool ok,) = token.call(abi.encodeWithSignature("transferFrom(address,address,uint256)", v, a, n));
        require(ok, "transferFrom failed");
    }`,
    `function test_exploit() public {
        (bool ok,) = token.call(abi.encodeWithSignature("transferFrom(address,address,uint256)", v, a, n));
        require(ok, "no allowance path worked. Tried transferFrom(address,address,uint256). This does NOT establish safety.");
    }`,
  ],
];

test("every declared shape has a positive and a negative", () => {
  const covered = new Set(CASES.map((c) => c[0]));
  const missing = SHAPE_IDS.filter((id) => !covered.has(id));
  assert.deepEqual(missing, [], `shapes with no test case: ${missing.join(", ")}`);
});

for (const [shape, positive, negative] of CASES) {
  test(`flags ${shape}`, () => {
    const ids = lintTemplate(positive).map((f) => f.shape);
    assert.ok(ids.includes(shape), `expected ${shape}, got [${ids.join(", ")}]`);
  });

  test(`does not flag ${shape} on a converted harness`, () => {
    const ids = lintTemplate(negative).map((f) => f.shape);
    assert.ok(!ids.includes(shape), `${shape} false-positived on a converted harness`);
  });
}

test("callShapes counts typed and encoded shapes together", () => {
  const s = `IVault(target).deposit(1, a);
             target.call(abi.encodeWithSignature("withdraw()"));
             bytes4 sel = bytes4(keccak256("claim()"));`;
  const shapes = callShapes(s);
  for (const want of ["deposit", "withdraw()", "claim()"]) assert.ok(shapes.has(want), `missing ${want}`);
});

test("the 46 real templates have no single-guess errors", () => {
  const files = readdirSync(FALLBACKS).filter((f) => f.endsWith(".t.sol")).sort();
  assert.ok(files.length >= 46, `expected the full catalog, found ${files.length}`);

  const bad = [];
  for (const file of files) {
    const errs = lintErrors(readFileSync(join(FALLBACKS, file), "utf8"));
    if (errs.length > 0) bad.push(`${file}: ${errs.map((e) => e.shape).join(", ")}`);
  }
  assert.deepEqual(bad, [], `templates with an unearned verdict:\n${bad.join("\n")}`);
});
