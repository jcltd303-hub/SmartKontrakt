import test from "node:test";
import assert from "node:assert/strict";

import { analyzeInput } from "./engine.ts";

/**
 * signature-replay on view functions (2026-10-29).
 *
 * 79 findings in the archive — the most common detector by far — on a cohort of audited
 * protocols. Tested against realistic shapes, the first thing it fired on was a plain
 * `isValidSignature(hash,v,r,s) external view returns (bool)`: a helper that answers
 * whether a signature belongs to the owner. It changes no state, so there is nothing to
 * replay. That is the shape of every EIP-1271 helper in existence.
 */

const hits = (src: string) =>
  analyzeInput(src, "probe", null).findings.filter((f) => f.detector === "signature-replay");

test("a view signature-check helper is not a replay risk", () => {
  const src = `
pragma solidity ^0.8.0;
contract Wallet {
    address public owner;
    function isValidSignature(bytes32 hash, uint8 v, bytes32 r, bytes32 s) external view returns (bool) {
        return ecrecover(hash, v, r, s) == owner;
    }
}`;
  assert.equal(hits(src).length, 0, "a view function cannot be replayed");
});

test("a pure signature-check helper is not a replay risk", () => {
  const src = `
pragma solidity ^0.8.0;
contract Lib {
    function check(bytes32 hash, uint8 v, bytes32 r, bytes32 s) external pure returns (address) {
        return ecrecover(hash, v, r, s);
    }
}`;
  assert.equal(hits(src).length, 0);
});

test("a state-changing claim with no nonce still fires", () => {
  const src = `
pragma solidity ^0.8.0;
contract Airdrop {
    address public signer;
    mapping(address => uint256) public claimed;
    function claim(address to, uint256 amount, uint8 v, bytes32 r, bytes32 s) external {
        bytes32 h = keccak256(abi.encode(to, amount));
        require(ecrecover(h, v, r, s) == signer, "bad sig");
        claimed[to] += amount;
        payable(to).transfer(amount);
    }
}`;
  const found = hits(src);
  assert.equal(found.length, 1, "the real class must still fire");
  assert.equal(found[0]!.severity, "medium");
});

test("a state-changing claim with a nonce is exempt", () => {
  const src = `
pragma solidity ^0.8.0;
contract Airdrop {
    address public signer;
    mapping(address => uint256) public nonces;
    function claim(address to, uint256 amount, uint8 v, bytes32 r, bytes32 s) external {
        bytes32 h = keccak256(abi.encode(to, amount, nonces[to]++));
        require(ecrecover(h, v, r, s) == signer, "bad sig");
        payable(to).transfer(amount);
    }
}`;
  assert.equal(hits(src).length, 0);
});
