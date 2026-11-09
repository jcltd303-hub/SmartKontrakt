import test from "node:test";
import assert from "node:assert/strict";
import { parseTestCodeReply } from "./ai-review.server.ts";

const HEAD = '// SPDX-License-Identifier: MIT\npragma solidity ^0.8.24;\nimport "forge-std/Test.sol";\n';
const BODY = "contract PoC is Test { function test_x() public { assertTrue(true); } }\n";
const wrap = (c: string) => "```solidity\n" + c + "```";

test("importing the target is rejected", () => {
  const code = HEAD + 'import "src/Vault.sol";\n' + BODY;
  assert.throws(() => parseTestCodeReply(wrap(code), "stop"), /Source not found|imports/);
});

test("a single-quoted target import is rejected too", () => {
  const code = HEAD + "import 'src/Token.sol';\n" + BODY;
  assert.throws(() => parseTestCodeReply(wrap(code), "stop"), /imports/);
});

test("forge-std alone is accepted", () => {
  assert.doesNotThrow(() => parseTestCodeReply(wrap(HEAD + BODY), "stop"));
});

test("an inline interface plus forge-std is accepted", () => {
  const code = HEAD + "interface IVault { function withdraw() external; }\n" + BODY;
  assert.doesNotThrow(() => parseTestCodeReply(wrap(code), "stop"));
});

test("a non-ASCII character in code is rejected", () => {
  const code = HEAD + 'contract PoC is Test { function test_x() public { require(true, "a—b"); } }\n';
  assert.throws(() => parseTestCodeReply(wrap(code), "stop"), /non-ASCII/);
});

test("a non-ASCII character in a COMMENT is accepted", () => {
  const code = HEAD + "// drains the pool — the classic case\n" + BODY;
  assert.doesNotThrow(() => parseTestCodeReply(wrap(code), "stop"));
});
