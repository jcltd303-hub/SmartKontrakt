// SPDX-License-Identifier: MIT
/*
 * PROVENANCE
 *   Dataset repo     : smartbugs/smartbugs-curated
 *   Dataset path     : dataset/access_control/mapping_write.sol
 *   @source          : https://smartcontractsecurity.github.io/SWC-registry/docs/SWC-124#mapping-writesol
 *   Original pragma  : pragma solidity ^0.4.24;
 *   Vulnerable line  : 20
 *
 *   FIXED variant of MappingWrite. Standard remediation for the missing access
 *   control on `set`: the dataset contract never assigns `owner` (it is always
 *   address(0)); the fix introduces a real owner and restricts the arbitrary
 *   storage write to that owner (owner/role check).
 */
pragma solidity ^0.8.24;

contract MappingWriteFixed {
    address public owner;
    uint256[] map;

    modifier onlyOwner() {
        require(msg.sender == owner, "MappingWriteFixed: not owner");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    function set(uint256 key, uint256 value) public onlyOwner {
        if (map.length <= key) {
            // Solidity 0.8 makes a storage array's `.length` read-only; resize it with
            // inline assembly (sstore to the array length slot). Semantics are identical
            // to 0.4's `map.length = key + 1`.
            assembly {
                sstore(map.slot, add(key, 1))
            }
        }
        map[key] = value;
    }

    function get(uint256 key) public view returns (uint256) {
        return map[key];
    }

    function withdraw() public {
        require(msg.sender == owner);
        payable(msg.sender).transfer(address(this).balance);
    }
}
