// SPDX-License-Identifier: MIT
/*
 * PROVENANCE
 *   Dataset repo     : smartbugs/smartbugs-curated
 *   Dataset path     : dataset/access_control/proxy.sol
 *   @source          : https://smartcontractsecurity.github.io/SWC-registry/docs/SWC-112#proxysol
 *   Original pragma  : pragma solidity ^0.4.24;
 *   Vulnerable line  : 19
 *
 *   FIXED variant of AccessControlProxy. Standard remediation: restrict who may drive
 *   the delegatecall. `forward` now requires the caller to be the owner (owner/role
 *   check), so an unauthorised caller can no longer make the proxy delegatecall
 *   arbitrary code in its own storage context.
 */
pragma solidity ^0.8.24;

contract AccessControlProxyFixed {

  address owner;

  constructor() {
    owner = msg.sender;
  }

  // FIX: only the owner may forward
  function forward(address callee, bytes memory _data) public {
    require(msg.sender == owner, "AccessControlProxyFixed: not owner");
    (bool ok, ) = callee.delegatecall(_data);
    require(ok);
  }

}
