import test from "node:test";
import assert from "node:assert/strict";
import { parseTestCodeReply } from "./ai-review.server.ts";

const HEAD = '// SPDX-License-Identifier: MIT\npragma solidity ^0.8.24;\nimport "forge-std/Test.sol";\n';
const BODY = "contract PoC is Test { function test_x() public { assertTrue(true); } }\n";

test("real string concatenation is still rejected", () => {
  const code = HEAD + 'contract PoC is Test { function test_x() public { require(true, "a" + "b"); } }\n';
  assert.throws(() => parseTestCodeReply("```solidity\n" + code + "```", "stop"), /concatenat/);
});

test("a COMMENT mentioning the pattern is accepted", () => {
  const code = HEAD + '// never use "a" + "b" in Solidity\n' + BODY;
  assert.doesNotThrow(() => parseTestCodeReply("```solidity\n" + code + "```", "stop"));
});

test("string.concat is accepted", () => {
  const code = HEAD + 'contract PoC is Test { function test_x() public { require(true, string.concat("a", "b")); } }\n';
  assert.doesNotThrow(() => parseTestCodeReply("```solidity\n" + code + "```", "stop"));
});

test("arithmetic plus is accepted", () => {
  const code = HEAD + 'contract PoC is Test { function test_x() public { uint a = 1 + 2; require(a > 0, "ok"); } }\n';
  assert.doesNotThrow(() => parseTestCodeReply("```solidity\n" + code + "```", "stop"));
});

test("arithmetic followed by a string on the NEXT line is accepted", () => {
  const code = HEAD + 'contract PoC is Test { function test_x() public {\n  uint a = 1 + 2;\n  string memory s = "ok";\n  assertTrue(bytes(s).length > 0); } }\n';
  assert.doesNotThrow(() => parseTestCodeReply("```solidity\n" + code + "```", "stop"));
});
