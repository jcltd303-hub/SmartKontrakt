// SPDX-License-Identifier: MIT
/*
 * PROVENANCE
 *   Dataset repo     : smartbugs/smartbugs-curated
 *   Dataset path     : dataset/access_control/multiowned_vulnerable.sol
 *   @source          : https://github.com/SmartContractSecurity/SWC-registry/blob/master/test_cases/solidity/unprotected_critical_functions/multiowned_vulnerable/multiowned_vulnerable.sol
 *   Original pragma  : pragma solidity ^0.4.23;
 *   Vulnerable line  : 38   ( function newOwner(address _owner) external returns (bool)  -- missing onlyOwner )
 *
 *   Port: Solidity ^0.8.24. Mechanical 0.4 -> 0.8 migration only:
 *     - constructor() public -> constructor()
 *     - owners[x] != 0 -> owners[x] != address(0)   (address literal comparison)
 *     - msg.sender.transfer(this.balance) -> payable(msg.sender).transfer(address(this).balance)
 *     - function() payable -> fallback() external payable
 *   The vulnerable ordering is preserved verbatim: `newOwner` is external and
 *   carries NO onlyOwner modifier (SWC-105 / unprotected critical function).
 */
pragma solidity ^0.8.24;

/**
 * @title MultiOwnable
 */
contract MultiownedVulnerable {
  address public root;
  mapping (address => address) public owners; // owner => parent of owner

  /**
  * @dev The Ownable constructor sets the original `owner` of the contract to the sender
  * account.
  */
  constructor() {
    root = msg.sender;
    owners[root] = root;
  }

  /**
  * @dev Throws if called by any account other than the owner.
  */
  modifier onlyOwner() {
    require(owners[msg.sender] != address(0));
    _;
  }

  /**
  * @dev Adding new owners
  * Note that the "onlyOwner" modifier is missing here.
  */
  // <yes> <report> ACCESS_CONTROL   (vulnerable line 38)
  function newOwner(address _owner) external returns (bool) {
    require(_owner != address(0));
    owners[_owner] = msg.sender;
    return true;
  }

  /**
    * @dev Deleting owners
    */
  function deleteOwner(address _owner) onlyOwner external returns (bool) {
    require(owners[_owner] == msg.sender || (owners[_owner] != address(0) && msg.sender == root));
    owners[_owner] = address(0);
    return true;
  }
}

contract MultiownedVulnerableTestContract is MultiownedVulnerable {

  function withdrawAll() onlyOwner public {
    payable(msg.sender).transfer(address(this).balance);
  }

  fallback() external payable {
  }

}
