/*
 * PROVENANCE
 * -------------------------------------------------------------------
 * Dataset repo : smartbugs/smartbugs-curated
 * Dataset path : dataset/denial_of_service/dos_simple.sol
 * Upstream @source: https://github.com/SmartContractSecurity/SWC-registry/blob/master/test_cases/dos_gas_limit/dos_simple.sol
 * Original pragma: ^0.4.25
 * Original vulnerable line(s): 17,18
 * Fixed variant: DosSimpleFixed
 *
 * REMEDIATION (DoS / SWC-128): bound the per-call work so no single transaction
 * can exhaust the block gas limit, cap the array so it cannot grow without limit,
 * and never wipe the existing records. One call now writes at most one entry.
 */
pragma solidity ^0.8.24;

contract DosSimpleFixed {

    address[] listAddresses;
    uint256 private constant MAX_ENTRIES = 1500;

    function ifillArray() public returns (bool){
        // FIX: bounded per-call work (one entry) -> a single call can never blow the gas limit.
        if(listAddresses.length < MAX_ENTRIES) {
            listAddresses.push(msg.sender);
            return true;
        }
        // FIX: do not wipe the records of other participants.
        return false;
    }
}
