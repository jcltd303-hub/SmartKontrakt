import test from "node:test";
import assert from "node:assert/strict";
import { stripSolidityComments } from "./solidity-text.ts";

test("line comments are removed, newlines kept", () => {
  const src = "uint x = 1; // a comment\nuint y = 2;";
  const out = stripSolidityComments(src);
  assert.ok(!out.includes("comment"));
  assert.equal(out.split("\n").length, 2, "line structure survives");
});

test("block comments are removed", () => {
  const src = "uint x = 1; /* multi\nline\ncomment */ uint y = 2;";
  assert.ok(!stripSolidityComments(src).includes("multi"));
});

test("a URL inside a string is not treated as a comment", () => {
  const src = 'string memory u = "https://example.com/x";';
  assert.equal(stripSolidityComments(src), src);
});

test("a quote inside a comment does not open a string", () => {
  const src = '// it\'s fine\nuint x = 1;';
  assert.equal(stripSolidityComments(src).trim(), "uint x = 1;");
});

test("escaped quotes inside a string are preserved", () => {
  const src = 'string memory s = "a \\" b"; uint y = 2;';
  assert.equal(stripSolidityComments(src), src);
});

test("the comment that broke generation is stripped", () => {
  // The prompt says: never write `"a" + "b"`. A model echoing it in a comment
  // produced a file that was valid Solidity and was still rejected.
  const src = '// never use "a" + "b" in Solidity\ncontract PoC is Test {}';
  const out = stripSolidityComments(src);
  assert.ok(!out.includes('"a" + "b"'), "the pattern must be gone");
  assert.ok(out.includes("contract PoC is Test"), "code survives");
});
