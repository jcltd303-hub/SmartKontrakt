// SPDX-License-Identifier: MIT
/*
 * PROVENANCE
 *   Dataset repo     : smartbugs/smartbugs-curated
 *   Dataset path     : dataset/access_control/phishable.sol
 *   @source          : https://github.com/sigp/solidity-security-blog
 *   Original pragma  : pragma solidity ^0.4.22;
 *   Vulnerable line  : 20
 *
 *   FIXED variant of Phishable. Standard remediation: authorise on `msg.sender`
 *   instead of `tx.origin`, so a phishing intermediary contract cannot borrow the
 *   owner's origin (owner/role check).
 */
pragma solidity ^0.8.24;

contract PhishableFixed {
    address public owner;

    constructor (address _owner) {
        owner = _owner;
    }

    fallback() external payable {} // collect ether

    function withdrawAll(address _recipient) public {
        // FIX: msg.sender, not tx.origin
        require(msg.sender == owner, "PhishableFixed: not owner");
        payable(_recipient).transfer(address(this).balance);
    }
}
