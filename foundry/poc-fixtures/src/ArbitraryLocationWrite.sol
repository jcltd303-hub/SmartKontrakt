// SPDX-License-Identifier: MIT
/*
 * PROVENANCE
 *   Dataset repo     : smartbugs/smartbugs-curated
 *   Dataset path     : dataset/access_control/arbitrary_location_write_simple.sol
 *   @source          : https://smartcontractsecurity.github.io/SWC-registry/docs/SWC-124#arbitrary-location-write-simplesol
 *   Original pragma  : pragma solidity ^0.4.25;
 *   Vulnerable line  : 27   ( require(0 <= bonusCodes.length);  then  bonusCodes.length--; )
 *
 *   Port: Solidity ^0.8.24.
 *     - uint256[] / uint256 (explicit types)
 *     - function () public payable -> fallback() external payable
 *     - selfdestruct(msg.sender) -> selfdestruct(payable(msg.sender))
 *     - NON-MECHANICAL, REQUIRED: `bonusCodes.length--` when length == 0 UNDERFLOWED and
 *       wrapped in 0.4 (giving an attacker an array that spans all of storage). Solidity
 *       0.8 inserts checked arithmetic and would REVERT, masking the bug. The decrement
 *       is therefore wrapped in `unchecked { ... }` to restore the original 0.4 wrapping
 *       semantics. This is the only behaviour-affecting migration edit.
 *   The vulnerable ordering is preserved verbatim (always-true bound check followed by
 *   an unguarded length decrement; SWC-124 write to arbitrary storage location).
 */
pragma solidity ^0.8.24;

contract ArbitraryLocationWrite {
    uint256[] private bonusCodes;
    address private owner;

    constructor() {
        bonusCodes = new uint256[](0);
        owner = msg.sender;
    }

    fallback() external payable {
    }

    function PushBonusCode(uint256 c) public {
        bonusCodes.push(c);
    }

    function PopBonusCode() public {
        // <yes> <report> ACCESS_CONTROL   (vulnerable line 27)
        require(0 <= bonusCodes.length); // this condition is always true since array lengths are unsigned
        // Solidity 0.8 makes a storage array's `.length` read-only and uses checked
        // arithmetic; the resize is done in assembly, whose SUB wraps on underflow --
        // restoring the exact 0.4 behaviour (0 -> 2**256-1) that this bug relies on.
        assembly {
            sstore(bonusCodes.slot, sub(sload(bonusCodes.slot), 1))
        }
    }

    function UpdateBonusCodeAt(uint256 idx, uint256 c) public {
        require(idx < bonusCodes.length);
        bonusCodes[idx] = c; // write to any index less than bonusCodes.length
    }

    function Destroy() public {
        require(msg.sender == owner);
        selfdestruct(payable(msg.sender));
    }
}
