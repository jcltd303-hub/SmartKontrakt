// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// Fixture for fallback type 18 (signature replay).
/// VULNERABLE BY DESIGN: claim() verifies a signature over a FIXED
/// message hash with no nonce, deadline, or per-signature usage
/// record -- the same signature pays out again and again.
/// The trusted signer is the address for the template's SIGNER_KEY
/// (0xA11CE), and MESSAGE_HASH is keccak256("SmartKontrakt proof:
/// claim 1 ETH"); both are baked into the suite manifest's adaptations.
contract ReplayVault {
    address public constant SIGNER = 0xe05fcC23807536bEe418f142D19fa0d21BB0cfF7;
    bytes32 public constant CLAIM_HASH =
        0x93bf105a0b8cb9db852cb7c9a9374207b28a4db9de085b158e3f5afc48e9d8ca;

    function claim(bytes calldata sig) external {
        require(sig.length == 65, "bad sig length");
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := calldataload(sig.offset)
            s := calldataload(add(sig.offset, 32))
            v := byte(0, calldataload(add(sig.offset, 64)))
        }
        // BUG: no nonce / usage tracking -- replayable forever.
        require(ecrecover(CLAIM_HASH, v, r, s) == SIGNER, "bad signer");
        (bool ok, ) = msg.sender.call{value: 1 ether}("");
        require(ok, "payout failed");
    }

    receive() external payable {}
}
