// SPDX-License-Identifier: MIT
/*
 * PROVENANCE
 *   Dataset repo     : smartbugs/smartbugs-curated
 *   Dataset path     : dataset/access_control/mapping_write.sol
 *   @source          : https://smartcontractsecurity.github.io/SWC-registry/docs/SWC-124#mapping-writesol
 *   Original pragma  : pragma solidity ^0.4.24;
 *   Vulnerable line  : 20   ( map[key] = value; )
 *
 *   Port: Solidity ^0.8.24.
 *     - uint256[] map (explicit type)
 *     - function get(...) public view   (constant -> view)
 *     - msg.sender.transfer(x) -> payable(msg.sender).transfer(x)
 *     - NON-MECHANICAL, REQUIRED: Solidity 0.8 makes a storage array's `.length`
 *       read-only, so the original `map.length = key + 1;` does not compile. It is
 *       reproduced with inline assembly (`sstore(map.slot, add(key, 1))`), which has
 *       exactly the same effect: it resizes the array so the out-of-range index below
 *       can reach storage slot 0. This is the only non-mechanical edit.
 *   The vulnerable ordering is preserved verbatim: `set` is publicly callable and
 *   writes map[key] for any caller-supplied key with no access control (SWC-124).
 */
pragma solidity ^0.8.24;

//This code is derived from the Capture the Ether https://capturetheether.com/challenges/math/mapping/

contract MappingWrite {
    address public owner;
    uint256[] map;

    function set(uint256 key, uint256 value) public {
        if (map.length <= key) {
            // Solidity 0.8 makes a storage array's `.length` read-only; resize it with
            // inline assembly (sstore to the array length slot). Semantics are identical
            // to 0.4's `map.length = key + 1`.
            assembly {
                sstore(map.slot, add(key, 1))
            }
        }
        // <yes> <report> ACCESS_CONTROL   (vulnerable line 20)
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
