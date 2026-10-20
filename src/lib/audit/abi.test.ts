import test from "node:test";
import assert from "node:assert/strict";
import { splitParams, heuristicAbiFromInventory, interfaceFromAbi, tailorTemplateToAbi, type AbiItem } from "./abi.ts";
import type { Inventory } from "./types.ts";

test("splitParams respects nested tuples and arrays", () => {
  assert.deepEqual(splitParams("address,uint256"), ["address", "uint256"]);
  assert.deepEqual(splitParams(""), []);
  assert.deepEqual(splitParams("address,uint256[],bytes32"), ["address", "uint256[]", "bytes32"]);
  assert.deepEqual(
    splitParams("(address,uint256),bytes[]"),
    ["(address,uint256)", "bytes[]"],
  );
});

test("heuristicAbiFromInventory rebuilds functions and events", () => {
  const inv = {
    functions: [
      { name: "withdraw", params: "uint256", mutability: "nonpayable", visibility: "external", modifiers: [], line: 1 },
      { name: "balanceOf", params: "address", mutability: "view", visibility: "external", modifiers: [], line: 2 },
      { name: "withdraw", params: "uint256", mutability: "nonpayable", visibility: "external", modifiers: [], line: 3 },
    ],
    events: ["Transfer(address,address,uint256)", "not a signature"],
  } as unknown as Inventory;

  const abi = heuristicAbiFromInventory(inv);
  const fns = abi.filter((i) => i.type === "function");
  const evs = abi.filter((i) => i.type === "event");
  assert.equal(fns.length, 2, "duplicate signatures are collapsed");
  assert.equal(evs.length, 1, "only well-formed event signatures are kept");
  assert.equal(fns.find((f) => f.name === "balanceOf")?.stateMutability, "view");
  assert.equal(fns.find((f) => f.name === "withdraw")?.inputs?.[0]?.type, "uint256");
});

test("heuristicAbiFromInventory is empty for a missing inventory", () => {
  assert.deepEqual(heuristicAbiFromInventory(null), []);
  assert.deepEqual(heuristicAbiFromInventory(undefined), []);
});

test("interfaceFromAbi renders real signatures, including tuples and returns", () => {
  const abi: AbiItem[] = [
    { type: "function", name: "withdraw", inputs: [{ name: "amount", type: "uint256" }], stateMutability: "nonpayable" },
    { type: "function", name: "balanceOf", inputs: [{ name: "who", type: "address" }], outputs: [{ type: "uint256" }], stateMutability: "view" },
    { type: "function", name: "setPair", inputs: [{ name: "p", type: "tuple", components: [{ type: "address" }, { type: "uint256" }] }], stateMutability: "nonpayable" },
    { type: "event", name: "Transfer", inputs: [{ type: "address" }] },
  ];
  const src = interfaceFromAbi(abi, "ITarget");
  assert.match(src, /interface ITarget \{/);
  assert.match(src, /function withdraw\(uint256 amount\) external;/);
  assert.match(src, /function balanceOf\(address who\) external view returns \(uint256\);/);
  assert.match(src, /\(address,uint256\) p/, "tuples render as an inline tuple type");
  assert.doesNotMatch(src, /Transfer/, "events are not part of the interface");
});

test("tailorTemplateToAbi prepends the surface without touching the template body", () => {
  const template = "contract PoC is Test {\n  function test_exploit() public {}\n}\n";
  const abi: AbiItem[] = [{ type: "function", name: "drain", inputs: [], stateMutability: "nonpayable" }];
  const out = tailorTemplateToAbi(template, abi, { source: "sourcify" });
  assert.ok(out.endsWith(template), "the template body must be preserved verbatim");
  assert.match(out, /TARGET SURFACE/);
  assert.match(out, /sourcify/);
  assert.match(out, /function drain\(\) external;/);
  assert.ok(out.indexOf("TARGET SURFACE") < out.indexOf("contract PoC"), "surface comes first");
});
