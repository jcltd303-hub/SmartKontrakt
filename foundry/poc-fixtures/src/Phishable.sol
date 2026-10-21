// SPDX-License-Identifier: MIT
/*
 * PROVENANCE
 *   Dataset repo     : smartbugs/smartbugs-curated
 *   Dataset path     : dataset/access_control/phishable.sol
 *   @source          : https://github.com/sigp/solidity-security-blog
 *   Original pragma  : pragma solidity ^0.4.22;
 *   Vulnerable line  : 20   ( require(tx.origin == owner); )
 *
 *   Port: Solidity ^0.8.24. Mechanical 0.4 -> 0.8 migration only:
 *     - _recipient.transfer(this.balance) -> payable(_recipient).transfer(address(this).balance)
 *     - function () public payable {} -> fallback() external payable {}
 *   The bug is preserved verbatim: `withdrawAll` authorises with `tx.origin == owner`
 *   instead of `msg.sender == owner`, so a phishing contract can induce the owner to
 *   call it and drain the balance (SWC-115 tx.origin authentication).
 */
pragma solidity ^0.8.24;

contract Phishable {
    address public owner;

    constructor (address _owner) {
        owner = _owner;
    }

    fallback() external payable {} // collect ether

    function withdrawAll(address _recipient) public {
        // <yes> <report> ACCESS_CONTROL   (vulnerable line 20)
        require(tx.origin == owner);
        payable(_recipient).transfer(address(this).balance);
    }
}
