import { test } from "node:test";
import assert from "node:assert/strict";

import { analyzeInput } from "./engine.ts";

// Encodes the soda-2020 INVARIANT ("collateral seized exceeds amount authorized by an
// independent position-health model"), not its mechanism — the source material marks that
// mechanism provisional and asks for primary-code verification.

const UNCHECKED = `
pragma solidity ^0.8.0;
contract Lender {
    mapping(address => uint256) public collateral;
    IERC20 public asset;
    function liquidate(address user, uint256 amount) external {
        collateral[user] -= amount;
        asset.transfer(msg.sender, amount);
    }
}`;

const CHECKED = `
pragma solidity ^0.8.0;
contract Lender {
    mapping(address => uint256) public collateral;
    IERC20 public asset;
    function healthOf(address user) public view returns (uint256) { return collateral[user]; }
    function liquidate(address user, uint256 amount) external {
        require(healthOf(user) < MIN_HEALTH, "position healthy");
        collateral[user] -= amount;
        asset.transfer(msg.sender, amount);
    }
}`;

const MODIFIER_GATED = `
pragma solidity ^0.8.0;
contract Lender {
    IERC20 public asset;
    modifier onlyUnderwater(address user) { require(isUnderwater(user), "healthy"); _; }
    function isUnderwater(address user) public view returns (bool) { return false; }
    function liquidate(address user, uint256 amount) external onlyUnderwater(user) {
        asset.transfer(msg.sender, amount);
    }
}`;

const hits = (src: string) =>
  analyzeInput(src, "c").findings.filter((f) => f.detector === "liquidation-without-health-check");

test("a liquidation that seizes collateral with no health model is flagged", () => {
  const found = hits(UNCHECKED);
  assert.equal(found.length, 1);
  assert.equal(found[0]!.severity, "medium", "source-only evidence, so medium");
});

test("a health check in the function body suppresses it", () => {
  assert.equal(hits(CHECKED).length, 0);
});

test("a health check in a modifier or a contract helper suppresses it", () => {
  assert.equal(hits(MODIFIER_GATED).length, 0);
});

test("a non-liquidation function is never flagged, however unguarded", () => {
  const src = UNCHECKED.replace(/liquidate/g, "deposit");
  assert.equal(hits(src).length, 0, "the rule is keyed on the seizure path");
});
