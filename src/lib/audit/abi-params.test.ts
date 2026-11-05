import test from "node:test";
import assert from "node:assert/strict";
import { splitParamTypeAndName, splitParams } from "./abi.ts";

test("rendered params split into type and name", () => {
  assert.deepEqual(splitParamTypeAndName("address initialOwner", 0), { type: "address", name: "initialOwner" });
  assert.deepEqual(splitParamTypeAndName("uint160 sqrtPriceX96", 1), { type: "uint160", name: "sqrtPriceX96" });
  assert.deepEqual(splitParamTypeAndName("bytes data", 0), { type: "bytes", name: "data" });
});

test("a bare type keeps a positional name", () => {
  assert.deepEqual(splitParamTypeAndName("uint256", 2), { type: "uint256", name: "a2" });
  assert.deepEqual(splitParamTypeAndName("uint256[]", 0), { type: "uint256[]", name: "a0" });
});

test("a tuple with a name splits after the tuple, not inside it", () => {
  assert.deepEqual(splitParamTypeAndName("(uint256,address) pair", 0), { type: "(uint256,address)", name: "pair" });
});

test("an unterminated tuple does not split", () => {
  const r = splitParamTypeAndName("(uint256, address", 0);
  assert.equal(r.type, "(uint256, address");
});

test("splitParams still respects nesting", () => {
  assert.deepEqual(splitParams("(uint256,address) pair,uint256 x"), ["(uint256,address) pair", "uint256 x"]);
});
