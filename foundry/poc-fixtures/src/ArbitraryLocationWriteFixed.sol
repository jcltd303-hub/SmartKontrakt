// SPDX-License-Identifier: MIT
/*
 * PROVENANCE
 *   Dataset repo     : smartbugs/smartbugs-curated
 *   Dataset path     : dataset/access_control/arbitrary_location_write_simple.sol
 *   @source          : https://smartcontractsecurity.github.io/SWC-registry/docs/SWC-124#arbitrary-location-write-simplesol
 *   Original pragma  : pragma solidity ^0.4.25;
 *   Vulnerable line  : 27
 *
 *   FIXED variant of ArbitraryLocationWrite. Standard remediation: replace the
 *   always-true bound check with a real lower bound so the length can never underflow,
 *   which keeps the array length at a sane value and makes the out-of-range write in
 *   `UpdateBonusCodeAt` revert on the bounds check.
 */
pragma solidity ^0.8.24;

contract ArbitraryLocationWriteFixed {
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
        // FIX: real lower bound; underflow is impossible
        require(bonusCodes.length > 0, "ArbitraryLocationWriteFixed: empty");
        bonusCodes.pop();
    }

    function UpdateBonusCodeAt(uint256 idx, uint256 c) public {
        require(idx < bonusCodes.length);
        bonusCodes[idx] = c;
    }

    function Destroy() public {
        require(msg.sender == owner);
        selfdestruct(payable(msg.sender));
    }
}
