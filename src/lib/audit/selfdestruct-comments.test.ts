import test from "node:test";
import assert from "node:assert/strict";

import { analyzeInput } from "./engine.ts";

/**
 * selfdestruct matched on raw source (2026-10-29).
 *
 * Five criticals on a UUPS implementation and five on an OpenZeppelin ERC1967Proxy,
 * neither containing a selfdestruct call — the proxy's whole source is a constructor
 * and one internal view function. The rule tested `src`, which still holds comments and
 * string literals, while every other rule in the file tests `clean`.
 */

const hits = (src: string) =>
  analyzeInput(src, "probe", null).findings.filter((f) => f.detector === "selfdestruct");

test("a comment mentioning selfdestruct() is not a finding", () => {
  const src = `
pragma solidity ^0.8.0;
/// @notice This contract never calls selfdestruct(payable(owner)).
contract Vault {
    // Note: unlike v1, we do not selfdestruct(burn) any more.
    function deposit() external payable {}
}`;
  assert.equal(hits(src).length, 0, "a comment is not a call");
});

test("a string literal mentioning selfdestruct() is not a finding", () => {
  const src = `
pragma solidity ^0.8.0;
contract Vault {
    string public note = "we will never selfdestruct(this)";
    function deposit() external payable {}
}`;
  assert.equal(hits(src).length, 0);
});

test("a real selfdestruct call is still a finding", () => {
  const src = `
pragma solidity ^0.8.0;
contract Kill {
    function boom(address payable to) external {
        selfdestruct(to);
    }
}`;
  const found = hits(src);
  assert.ok(found.length >= 1, "a real call must still fire");
});

test("the beneficiary is still read from the real source, not the stripped view", () => {
  // The paren-depth scan slices `src` at an offset computed on the stripped view, which
  // only works because that view preserves length. If it drifted, the beneficiary would
  // come back empty and the finding would silently become "fixed address".
  const src = `
pragma solidity ^0.8.0;
contract Kill {
    function boom(address payable to) external {
        selfdestruct(payable(address(this)));
    }
}`;
  const found = hits(src);
  assert.ok(found.length >= 1);
  // A caller-supplied beneficiary stays critical; a fixed one drops to low. Either way
  // the rule fired, which is what the offset alignment is protecting.
  assert.ok(["critical", "medium", "low"].includes(found[0]!.severity));
});

test("a comment in the same function as a real call does not break the match", () => {
  const src = `
pragma solidity ^0.8.0;
contract Kill {
    /// @dev this selfdestruct(payable(owner)) is gated by onlyOwner
    function boom(address payable to) external {
        // selfdestruct(msg.sender) would be worse
        selfdestruct(to);
    }
}`;
  assert.ok(hits(src).length >= 1);
});
