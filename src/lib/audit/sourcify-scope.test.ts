import { test } from "node:test";
import assert from "node:assert/strict";

import { importClosure, resolveImport, importSpecifiers } from "./address-fetcher.ts";

// Measured 2026-10-31: 0x0c0388e4 is an ERC1967Proxy — a few hundred bytes — but its
// Sourcify bundle is 91,621 characters, because the compilation unit also held
// @openzeppelin/upgrades-core's deliberately-unsafe TEST FIXTURES
// (HasSelfDestructNatspec1/2/3, explode, extremelyUnsafe, publicDelegateCall…).
// Concatenating the bundle and analysing all of it produced 29 criticals on a shell,
// every one a fixture. These tests exercise the REAL closure code, not a copy of it.

const PROXY = `pragma solidity ^0.8.9;
import "../Proxy.sol";
contract ERC1967Proxy is Proxy { }`;

const BASE_PROXY = `pragma solidity ^0.8.9;
abstract contract Proxy { }`;

const FIXTURE = `pragma solidity ^0.8.9;
contract HasSelfDestructNatspec1 {
  function d() public { selfdestruct(payable(msg.sender)); }
}`;

const BUNDLE = new Map<string, string>([
  ["@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol", PROXY],
  ["@openzeppelin/contracts/proxy/Proxy.sol", BASE_PROXY],
  ["@openzeppelin/upgrades-core/contracts/test/HasSelfDestruct.sol", FIXTURE],
]);

test("relative imports resolve, and `..` is collapsed", () => {
  const keys = new Set(BUNDLE.keys());
  assert.equal(
    resolveImport("@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol", "../Proxy.sol", keys),
    "@openzeppelin/contracts/proxy/Proxy.sol",
  );
});

test("bare imports resolve by suffix", () => {
  const keys = new Set(BUNDLE.keys());
  assert.equal(
    resolveImport("a/b/C.sol", "@openzeppelin/contracts/proxy/Proxy.sol", keys),
    "@openzeppelin/contracts/proxy/Proxy.sol",
  );
});

test("the closure of the proxy excludes the fixture file", () => {
  const closure = importClosure("@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol", BUNDLE);
  assert.deepEqual(closure, [
    "@openzeppelin/contracts/proxy/Proxy.sol",
    "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol",
  ]);
  assert.ok(!closure.some((f) => f.includes("HasSelfDestruct")), "the fixture is not imported");
});

test("the fixture's selfdestruct is what produced the phantom criticals", () => {
  const body = importClosure("@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol", BUNDLE)
    .map((n) => BUNDLE.get(n))
    .join("\n\n");
  assert.ok(!/selfdestruct\s*\(/.test(body), "scoped body has no selfdestruct");
  // And the unscoped bundle did — which is the bug.
  assert.ok(/selfdestruct\s*\(/.test([...BUNDLE.values()].join("\n")));
});

test("importSpecifiers handles both forms and ignores comments", () => {
  const src = `import "../A.sol";\nimport {B} from "./B.sol";\n// import "./C.sol";\n`;
  const got = importSpecifiers(src);
  assert.deepEqual(got, ["../A.sol", "./B.sol"]);
});

test("an unresolvable import is skipped rather than throwing", () => {
  const closure = importClosure("@x/Y.sol", new Map([["@x/Y.sol", `import "./missing.sol"; contract Y {}`]]));
  assert.deepEqual(closure, ["@x/Y.sol"]);
});
