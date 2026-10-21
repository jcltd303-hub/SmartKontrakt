/*
 * PROVENANCE
 * -------------------------------------------------------------------
 * Dataset repo : smartbugs/smartbugs-curated
 * Dataset path : dataset/denial_of_service/send_loop.sol
 * Upstream @source: https://consensys.github.io/smart-contract-best-practices/known_attacks/#dos-with-unexpected-revert
 * Original pragma: 0.4.24
 * Original vulnerable line(s): 24  (DENIAL_OF_SERVICE / SWC-113 DoS with failed call)
 * Port pragma  : ^0.8.24
 *
 * Migration edits (mechanical 0.4 -> 0.8 only):
 *   - uint -> uint256; explicit visibility.
 *   - `address[]` -> `address payable[]` (0.8 requires a payable type to call
 *     the low-level `.send`); the push sites use `payable(...)`.
 * The vulnerable ordering is preserved verbatim: a single failing `.send`
 * inside the loop is wrapped in `require(...)`, so it reverts the whole refund.
 */
pragma solidity ^0.8.24;

contract SendLoop {

    address payable[] private refundAddresses;
    mapping (address => uint256) public refunds;

    constructor() {
        refundAddresses.push(payable(0x79B483371E87d664cd39491b5F06250165e4b184));
        refundAddresses.push(payable(0x79B483371E87d664cd39491b5f06250165e4b185));
    }

    // bad
    function refundAll() public {
        for(uint256 x; x < refundAddresses.length; x++) { // arbitrary length iteration based on how many addresses participated
        // <yes> <report> DENIAL_OF_SERVICE
            require(refundAddresses[x].send(refunds[refundAddresses[x]])); // doubly bad, now a single failure on send will hold up all funds
        }
    }

}
