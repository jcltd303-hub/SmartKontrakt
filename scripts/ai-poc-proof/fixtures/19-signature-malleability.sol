// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// Fixture for fallback type 19 (signature malleability).
/// VULNERABLE BY DESIGN: claim() DOES track used signatures (keyed by
/// the signature bytes) but never enforces low-S (EIP-2). The high-S
/// twin of a consumed signature is a DIFFERENT byte string that
/// ecrecover accepts for the same signer -- it sails past the
/// used-check and pays again. Signer / message hash as in fixture 18.
contract MalleableVault {
    address public constant SIGNER = 0xe05fcC23807536bEe418f142D19fa0d21BB0cfF7;
    bytes32 public constant CLAIM_HASH =
        0x93bf105a0b8cb9db852cb7c9a9374207b28a4db9de085b158e3f5afc48e9d8ca;
    mapping(bytes32 => bool) public usedSig;

    function claim(bytes calldata sig) external {
        require(sig.length == 65, "bad sig length");
        bytes32 sigId = keccak256(sig);
        require(!usedSig[sigId], "signature already used");
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := calldataload(sig.offset)
            s := calldataload(add(sig.offset, 32))
            v := byte(0, calldataload(add(sig.offset, 64)))
        }
        // BUG: no s <= n/2 check -- the malleable twin verifies too.
        require(ecrecover(CLAIM_HASH, v, r, s) == SIGNER, "bad signer");
        usedSig[sigId] = true;
        (bool ok, ) = msg.sender.call{value: 1 ether}("");
        require(ok, "payout failed");
    }

    receive() external payable {}
}
