// SPDX-License-Identifier: MIT
/*
 * PROVENANCE
 *   Dataset repo     : smartbugs/smartbugs-curated
 *   Dataset path     : dataset/access_control/incorrect_constructor_name1.sol
 *   @source          : https://github.com/trailofbits/not-so-smart-contracts/blob/master/wrong_constructor_name/incorrect_constructor.sol
 *   Original pragma  : pragma solidity ^0.4.24;
 *   Vulnerable line  : 20
 *
 *   FIXED variant of IncorrectConstructorName. Standard remediation: replace the
 *   mis-named `IamMissing()` function with a real `constructor()` so ownership is
 *   set exactly once, at deployment, by the deployer. The attacker-callable
 *   ownership setter no longer exists.
 */
pragma solidity ^0.8.24;

contract IncorrectConstructorNameFixed {
    address private owner;

    modifier onlyowner {
        require(msg.sender == owner);
        _;
    }

    // FIX: real constructor, runs once at deployment
    constructor() {
        owner = msg.sender;
    }

    fallback() external payable {}

    function withdraw()
        public
        onlyowner
    {
       payable(owner).transfer(address(this).balance);
    }
}
