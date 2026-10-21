// SPDX-License-Identifier: MIT
/*
 * PROVENANCE
 *   Dataset repo     : smartbugs/smartbugs-curated
 *   Dataset path     : dataset/access_control/proxy.sol
 *   @source          : https://smartcontractsecurity.github.io/SWC-registry/docs/SWC-112#proxysol
 *   Original pragma  : pragma solidity ^0.4.24;
 *   Vulnerable line  : 19   ( require(callee.delegatecall(_data)); )
 *
 *   Port: Solidity ^0.8.24.
 *     - `bytes _data` -> `bytes memory _data`
 *     - NON-MECHANICAL (forced by 0.8): in 0.4 `callee.delegatecall(_data)` returned a
 *       single `bool`; in 0.8 it returns `(bool, bytes)`. The return value is therefore
 *       destructured and the success flag is required, preserving the original
 *       semantics (`require(delegatecall success)`). Behaviour is unchanged.
 *   The vulnerable ordering is preserved verbatim: `forward` is PUBLIC with no access
 *   control, so any caller can make the proxy `delegatecall` into an arbitrary address
 *   with arbitrary calldata, executing code in the proxy's own storage context
 *   (SWC-112 delegatecall to untrusted callee).
 */
pragma solidity ^0.8.24;

contract AccessControlProxy {

  address owner;

  constructor() {
    owner = msg.sender;
  }

  function forward(address callee, bytes memory _data) public {
    // <yes> <report> ACCESS_CONTROL   (vulnerable line 19)
    (bool ok, ) = callee.delegatecall(_data);
    require(ok); //Use delegatecall with caution and make sure to never call into untrusted contracts
  }

}
