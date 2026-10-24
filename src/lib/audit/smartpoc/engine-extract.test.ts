import { test } from "node:test";
import assert from "node:assert/strict";
import { extractCodeBlock } from "./engine.server.ts";

/**
 * extractCodeBlock picks the PoC source out of a model response. The
 * preference under test: with several fenced blocks, the first block
 * carrying executable test functions wins over a bare first block (the
 * hollow-pass draft shape); every other case matches the historical
 * first-block / trimmed-text behavior.
 */

const HELPER = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
contract AttackHelper {
    function poke(address target) external pure returns (address) { return target; }
}`;

const TEST_CONTRACT = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;
import {Test} from "forge-std/Test.sol";
contract PoC is Test {
    function test_exploit() public { assertTrue(true); }
}`;

test("multi-fence: a helper first block does not shadow the Test contract in the second block", () => {
  const response = ["Here is the helper, then the PoC:", "```solidity", HELPER, "```", "And the test:", "```solidity", TEST_CONTRACT, "```"].join("\n");
  assert.equal(extractCodeBlock(response), TEST_CONTRACT);
});

test("multi-fence: the FIRST test-bearing block wins when several carry tests", () => {
  const other = TEST_CONTRACT.replace("test_exploit", "test_other");
  const response = ["```solidity", TEST_CONTRACT, "```", "```solidity", other, "```"].join("\n");
  assert.equal(extractCodeBlock(response), TEST_CONTRACT);
});

test("multi-fence with no test-bearing block: first block wins (unchanged)", () => {
  const other = HELPER.replace("AttackHelper", "OtherHelper");
  const response = ["```solidity", HELPER, "```", "```solidity", other, "```"].join("\n");
  assert.equal(extractCodeBlock(response), HELPER);
});

test("single fence: returned verbatim even when it has no test function (unchanged)", () => {
  const response = ["Only one block:", "```solidity", HELPER, "```"].join("\n");
  assert.equal(extractCodeBlock(response), HELPER);
});

test("no fences: the trimmed text is returned (unchanged)", () => {
  assert.equal(extractCodeBlock(`  \n${HELPER}\n  `), HELPER);
});
