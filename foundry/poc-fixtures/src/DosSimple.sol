/*
 * PROVENANCE
 * -------------------------------------------------------------------
 * Dataset repo : smartbugs/smartbugs-curated
 * Dataset path : dataset/denial_of_service/dos_simple.sol
 * Upstream @source: https://github.com/SmartContractSecurity/SWC-registry/blob/master/test_cases/dos_gas_limit/dos_simple.sol
 * Original pragma: ^0.4.25
 * Original vulnerable line(s): 17,18  (DENIAL_OF_SERVICE / SWC-128 block gas limit)
 * Port pragma  : ^0.8.24
 *
 * Migration edits (mechanical 0.4 -> 0.8 only):
 *   - uint  -> uint256
 *   - explicit `public` visibility on ifillArray
 * No semantics changed: the unbounded 350-iteration push loop is preserved verbatim.
 *
 * VULNERABILITY (why it is a DoS): a single external call performs 350 storage
 * writes (each a 0->non-zero SSTORE of ~20k gas) with no bound on how large the
 * list may become before the loop runs. One participant can therefore consume a
 * very large slice of a block's gas (SWC-128) and bloat storage without limit.
 * The `else` branch additionally wipes every recorded participant once the list
 * passes 1500 entries, so a griefer can also destroy other users' records.
 */
pragma solidity ^0.8.24;

contract DosSimple {

    address[] listAddresses;

    function ifillArray() public returns (bool){
        if(listAddresses.length<1500) {
            // <yes> <report> DENIAL_OF_SERVICE
            for(uint256 i=0;i<350;i++) {
                listAddresses.push(msg.sender);
            }
            return true;

        } else {
            listAddresses = new address[](0);
            return false;
        }
    }
}
