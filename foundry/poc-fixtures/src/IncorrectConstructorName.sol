// SPDX-License-Identifier: MIT
/*
 * PROVENANCE
 *   Dataset repo     : smartbugs/smartbugs-curated
 *   Dataset path     : dataset/access_control/incorrect_constructor_name1.sol
 *   @source          : https://github.com/trailofbits/not-so-smart-contracts/blob/master/wrong_constructor_name/incorrect_constructor.sol
 *   Original pragma  : pragma solidity ^0.4.24;
 *   Vulnerable line  : 20   ( function IamMissing() public { owner = msg.sender; } )
 *
 *   Port: Solidity ^0.8.24. Mechanical 0.4 -> 0.8 migration only:
 *     - owner.transfer(this.balance) -> payable(owner).transfer(address(this).balance)
 *     - function () payable {} -> fallback() external payable {}
 *   The bug is preserved verbatim: the contract is named `Missing` but the would-be
 *   constructor is called `IamMissing`, so it is an ordinary PUBLIC function that
 *   anyone can call to seize ownership (SWC-118 incorrect constructor name).
 */
pragma solidity ^0.8.24;

contract IncorrectConstructorName {
    address private owner;

    modifier onlyowner {
        require(msg.sender == owner);
        _;
    }

    // The name of the constructor should be Missing
    // Anyone can call the IamMissing once the contract is deployed
    // <yes> <report> ACCESS_CONTROL   (vulnerable line 20)
    function IamMissing()
        public
    {
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
