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

/**
 * Recovery primitives (2026-10-29), from the archive's own 79 findings.
 *
 * Nearly every one was a function that RECEIVES a digest and returns a signer:
 * recoverAddressFromSignature, tryRecover, ecrecovery, safer_ecrecover, getSignerOfHash,
 * isValidSignature, checkNSignatures, recoverAddress, _ecmulVerify,
 * _verifyLinearCombinationWithGenerator. The digest is built by the caller, so whether it
 * contains a nonce is the digest-builder's business in a different function. Flagging the
 * primitive is like flagging keccak256 for having no nonce.
 */

test("recoverAddressFromSignature(hash, v, r, s) is a primitive, not a replay surface", () => {
  const src = `
pragma solidity ^0.8.0;
contract Signatures {
    function recoverAddressFromSignature(bytes32 hash, uint8 v, bytes32 r, bytes32 s) public pure returns (address) {
        return ecrecover(hash, v, r, s);
    }
}`;
  assert.equal(hits(src).length, 0);
});

test("Gnosis Safe's checkNSignatures(dataHash, ...) is not flagged", () => {
  const src = `
pragma solidity ^0.8.0;
contract Safe {
    function signatureSplit(bytes memory s, uint256 p) internal pure returns (uint8, bytes32, bytes32) { return (0,0,0); }
    function checkNSignatures(bytes32 dataHash, bytes memory data, bytes memory signatures, uint256 requiredSignatures) public view {
        address currentOwner = address(0);
        for (uint256 i = 0; i < requiredSignatures; i++) {
            (uint8 v, bytes32 r, bytes32 s) = signatureSplit(signatures, i);
            currentOwner = ecrecover(dataHash, v, r, s);
        }
        data; currentOwner;
    }
}`;
  assert.equal(hits(src).length, 0, "the digest came from the caller");
});

test("an OZ-style tryRecover(hash, ...) is not flagged", () => {
  const src = `
pragma solidity ^0.8.0;
library ECDSA {
    function tryRecover(bytes32 hash, uint8 v, bytes32 r, bytes32 s) internal pure returns (address, bool) {
        address signer = ecrecover(hash, v, r, s);
        if (signer == address(0)) return (address(0), false);
        return (signer, true);
    }
}`;
  assert.equal(hits(src).length, 0);
});

test("a function that BUILDS its own digest and consumes it still fires", () => {
  // The distinction that matters: this one constructs the digest from its own
  // parameters, so it is where a nonce belongs — and there is none.
  const src = `
pragma solidity ^0.8.0;
contract Airdrop {
    address public signer;
    function claim(address to, uint256 amount, uint8 v, bytes32 r, bytes32 s) external {
        bytes32 h = keccak256(abi.encode(to, amount));
        require(ecrecover(h, v, r, s) == signer, "bad sig");
        payable(to).transfer(amount);
    }
}`;
  const found = hits(src);
  assert.equal(found.length, 1, "the digest-builder is the real class");
});
