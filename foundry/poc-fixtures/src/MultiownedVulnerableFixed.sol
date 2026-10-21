// SPDX-License-Identifier: MIT
/*
 * PROVENANCE
 *   Dataset repo     : smartbugs/smartbugs-curated
 *   Dataset path     : dataset/access_control/multiowned_vulnerable.sol
 *   @source          : https://github.com/SmartContractSecurity/SWC-registry/blob/master/test_cases/solidity/unprotected_critical_functions/multiowned_vulnerable/multiowned_vulnerable.sol
 *   Original pragma  : pragma solidity ^0.4.23;
 *   Vulnerable line  : 38
 *
 *   FIXED variant of MultiownedVulnerable. Standard remediation: add the missing
 *   `onlyOwner` modifier to `newOwner` (owner/role check) so that only an existing
 *   owner can add new owners.
 */
pragma solidity ^0.8.24;

contract MultiownedVulnerableFixed {
  address public root;
  mapping (address => address) public owners; // owner => parent of owner

  constructor() {
    root = msg.sender;
    owners[root] = root;
  }

  modifier onlyOwner() {
    require(owners[msg.sender] != address(0));
    _;
  }

  // FIX: onlyOwner added
  function newOwner(address _owner) onlyOwner external returns (bool) {
    require(_owner != address(0));
    owners[_owner] = msg.sender;
    return true;
  }

  function deleteOwner(address _owner) onlyOwner external returns (bool) {
    require(owners[_owner] == msg.sender || (owners[_owner] != address(0) && msg.sender == root));
    owners[_owner] = address(0);
    return true;
  }
}

contract MultiownedVulnerableFixedTestContract is MultiownedVulnerableFixed {

  function withdrawAll() onlyOwner public {
    payable(msg.sender).transfer(address(this).balance);
  }

  fallback() external payable {
  }

}
