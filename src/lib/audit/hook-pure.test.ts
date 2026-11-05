import test from "node:test";
import assert from "node:assert/strict";
import { analyzeInput } from "./engine.ts";

// SatoHook's actual shape, 2026-11-06: value-moving callbacks gated, the rest pure.
const SATO = `
pragma solidity ^0.8.26;
contract SatoHook {
    error NotPoolManager();
    address public immutable POOL_MANAGER;
    constructor(address pm) { POOL_MANAGER = pm; }
    modifier onlyPoolManager() {
        if (msg.sender != address(POOL_MANAGER)) revert NotPoolManager();
        _;
    }
    function beforeSwap(address, bytes calldata) external onlyPoolManager returns (bytes4) {
        return 0;
    }
    function afterSwap(address, bytes calldata) external pure returns (bytes4) {
        return 0;
    }
    function beforeDonate(address, uint256) external pure returns (bytes4) {
        return 0;
    }
}`;

// The control: an unguarded callback that is NOT pure — it can move value.
const BAD = `
pragma solidity ^0.8.26;
contract BadHook {
    mapping(address => uint256) public owed;
    function beforeSwap(address who, bytes calldata) external returns (bytes4) {
        owed[who] += 1;
        return 0;
    }
}`;

test("pure hook callbacks are not reported", () => {
  const f = analyzeInput(SATO, "satohook").findings.filter((x) => x.detector === "hook-callback-auth");
  assert.equal(f.length, 0, "a pure callback returns a selector and moves nothing");
});

test("a non-pure unguarded callback still fires", () => {
  const f = analyzeInput(BAD, "badhook").findings.filter((x) => x.detector === "hook-callback-auth");
  assert.ok(f.length >= 1, "state-writing callbacks must still be reported");
});
