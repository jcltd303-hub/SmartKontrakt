import test from "node:test";
import assert from "node:assert/strict";
import { analyzeInput } from "./engine.ts";

// SurtHook's shape: identity decoded from caller-supplied hookData, then used as the
// key for a per-block cap and a cooldown.
const SURT_LIKE = `
pragma solidity ^0.8.24;
contract Hook {
    error NotPoolManager();
    address public immutable POOL_MANAGER;
    uint8 public constant MAX_SWAPS_PER_BLOCK = 3;
    mapping(uint256 => mapping(address => uint8)) private _swapsInBlock;
    mapping(address => uint256) public lastBuyBlock;
    constructor(address pm) { POOL_MANAGER = pm; }
    modifier onlyPoolManager() { if (msg.sender != POOL_MANAGER) revert NotPoolManager(); _; }

    function beforeSwap(address, bytes calldata, bytes calldata hookData)
        external onlyPoolManager returns (bytes4)
    {
        address swapper = abi.decode(hookData, (address));
        uint8 c = _swapsInBlock[block.number][swapper];
        if (c >= MAX_SWAPS_PER_BLOCK) revert TooMany();
        _swapsInBlock[block.number][swapper] = c + 1;
        lastBuyBlock[swapper] = block.number;
        return 0;
    }
}`;

// Control: decodes an address but only emits it — nothing is keyed on it.
const BENIGN = `
pragma solidity ^0.8.24;
contract Fine {
    event Seen(address who);
    function peek(bytes calldata blob) external {
        address who = abi.decode(blob, (address));
        emit Seen(who);
    }
}`;

test("a guard keyed on a caller-supplied address is reported", () => {
  const f = analyzeInput(SURT_LIKE, "hook").findings.filter((x) => x.detector === "caller-supplied-identity");
  assert.ok(f.length >= 1, "the SurtHook shape must fire");
});

test("decoding an address without keying state on it does not fire", () => {
  const f = analyzeInput(BENIGN, "fine").findings.filter((x) => x.detector === "caller-supplied-identity");
  assert.equal(f.length, 0);
});
