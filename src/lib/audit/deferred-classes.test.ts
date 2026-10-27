import test from "node:test";
import assert from "node:assert/strict";

import { analyzeInput } from "./engine.ts";
import type { Finding } from "./types.ts";

/**
 * The four deferred classes (2026-10-27, second pass).
 *
 * docs/recent-exploits-2026.md listed these as deliberately NOT implemented,
 * because a pattern match on each fires on correct code. That was right about
 * the naive version and wrong about the alternative: each class has an
 * INVARIANT a correct implementation must satisfy, and these fixtures pin the
 * invariant on both sides — a violating contract fires, a correct one does not.
 */

const has = (src: string, detector: string): boolean =>
  analyzeInput(src, "deferred").findings.some((f: Finding) => f.detector === detector);

// ---------------------------------------------------------------- 1. shares

test("share-accounting-double-debit: two debit paths, neither clears the position", () => {
  const src = `pragma solidity ^0.8.0;
contract Vesting {
    struct Pos { uint256 shares; }
    mapping(uint256 => Pos) public positions;
    uint256 public totalShares;
    function release(uint256 id) external {
        require(positions[id].shares > 0, "none");
        totalShares -= positions[id].shares;
        payable(msg.sender).transfer(positions[id].shares);
    }
    function cancel(uint256 id) external {
        require(positions[id].shares > 0, "none");
        totalShares -= positions[id].shares;
        payable(msg.sender).transfer(positions[id].shares);
    }
}`;
  assert.equal(has(src, "share-accounting-double-debit"), true);
});

test("share-accounting-double-debit: clearing the position is the fix and does not fire", () => {
  const src = `pragma solidity ^0.8.0;
contract VestingOK {
    struct Pos { uint256 shares; }
    mapping(uint256 => Pos) public positions;
    uint256 public totalShares;
    function release(uint256 id) external {
        uint256 s = positions[id].shares;
        require(s > 0, "none");
        positions[id].shares = 0;
        totalShares -= s;
        payable(msg.sender).transfer(s);
    }
    function cancel(uint256 id) external {
        uint256 s = positions[id].shares;
        require(s > 0, "none");
        positions[id].shares = 0;
        totalShares -= s;
        payable(msg.sender).transfer(s);
    }
}`;
  assert.equal(has(src, "share-accounting-double-debit"), false);
});

// ------------------------------------------------------------- 2. netting

test("shared-unlock-delta-netting: a callback that takes and settles with no delta check", () => {
  const src = `pragma solidity ^0.8.0;
interface IPoolManager {
    function take(address, address, uint256) external;
    function settle() external payable returns (uint256);
}
contract Hook {
    IPoolManager public poolManager;
    function lockAcquired(bytes calldata data) external returns (bytes memory) {
        poolManager.take(address(this), address(this), 1 ether);
        poolManager.settle();
        return data;
    }
}`;
  assert.equal(has(src, "shared-unlock-delta-netting"), true);
});

test("shared-unlock-delta-netting: requiring the delta settled is the fix and does not fire", () => {
  const src = `pragma solidity ^0.8.0;
interface IPoolManager {
    function take(address, address, uint256) external;
    function settle() external payable returns (uint256);
}
contract HookOK {
    IPoolManager public poolManager;
    uint256 public outstandingDelta;
    function lockAcquired(bytes calldata data) external returns (bytes memory) {
        require(outstandingDelta == 0, "delta unsettled");
        poolManager.take(address(this), address(this), 1 ether);
        poolManager.settle();
        return data;
    }
}`;
  assert.equal(has(src, "shared-unlock-delta-netting"), false);
});

// ------------------------------------------------------------ 3. interest

test("idle-gap-interest-accrual: the checkpoint is advanced only inside an if", () => {
  const src = `pragma solidity ^0.8.0;
contract Market {
    uint256 public lastBlock;
    uint256 public interestIndex;
    uint256 public rate;
    function accrue() external {
        uint256 elapsed = block.number - lastBlock;
        interestIndex += elapsed * rate;
        if (interestIndex == 0) { lastBlock = block.number; }
    }
}`;
  assert.equal(has(src, "idle-gap-interest-accrual"), true);
});

test("idle-gap-interest-accrual: advancing the checkpoint on every path does not fire", () => {
  const src = `pragma solidity ^0.8.0;
contract MarketOK {
    uint256 public lastBlock;
    uint256 public interestIndex;
    uint256 public rate;
    function accrue() external {
        uint256 elapsed = block.number - lastBlock;
        lastBlock = block.number;
        interestIndex += elapsed * rate;
    }
}`;
  assert.equal(has(src, "idle-gap-interest-accrual"), false);
});

// ----------------------------------------------------------- 4. signature

test("signature-field-omission: the digest omits a parameter that steers value", () => {
  const src = `pragma solidity ^0.8.0;
contract Claims {
    address public trusted;
    mapping(address => bool) public used;
    function claim(address to, uint256 amount, uint8 v, bytes32 r, bytes32 s) external {
        bytes32 digest = keccak256(abi.encode(to));
        require(ecrecover(digest, v, r, s) == trusted, "sig");
        require(!used[to], "used");
        used[to] = true;
        payable(to).transfer(amount);
    }
}`;
  assert.equal(has(src, "signature-field-omission"), true);
});

test("signature-field-omission: a digest that covers the amount does not fire", () => {
  const src = `pragma solidity ^0.8.0;
contract ClaimsOK {
    address public trusted;
    mapping(address => bool) public used;
    function claim(address to, uint256 amount, uint8 v, bytes32 r, bytes32 s) external {
        bytes32 digest = keccak256(abi.encode(address(this), block.chainid, to, amount));
        require(ecrecover(digest, v, r, s) == trusted, "sig");
        require(!used[to], "used");
        used[to] = true;
        payable(to).transfer(amount);
    }
}`;
  assert.equal(has(src, "signature-field-omission"), false);
});

test("an ECDSA claim is no longer reported as an unverified bridge handler", () => {
  // The bridge rule used to fire here because it looked for the word
  // "signature" and the parameters were v/r/s. A recovered signer IS
  // verification of the message; the real defect is the omitted field above.
  const src = `pragma solidity ^0.8.0;
contract Claims2 {
    address public trusted;
    function claim(address to, uint256 amount, uint8 v, bytes32 r, bytes32 s) external {
        bytes32 digest = keccak256(abi.encode(to, amount));
        require(ecrecover(digest, v, r, s) == trusted, "sig");
        payable(to).transfer(amount);
    }
}`;
  assert.equal(has(src, "bridge-message-auth"), false);
});
