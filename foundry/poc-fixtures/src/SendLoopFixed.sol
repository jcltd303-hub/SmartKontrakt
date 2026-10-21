/*
 * PROVENANCE
 * -------------------------------------------------------------------
 * Dataset repo : smartbugs/smartbugs-curated
 * Dataset path : dataset/denial_of_service/send_loop.sol
 * Upstream @source: https://consensys.github.io/smart-contract-best-practices/known_attacks/#dos-with-unexpected-revert
 * Original pragma: 0.4.24
 * Original vulnerable line(s): 24
 * Fixed variant: SendLoopFixed
 *
 * REMEDIATION (DoS with failed call): skip-on-failure (and pull-payment style
 * crediting). A single recipient whose send fails can no longer revert the whole
 * batch, so every other participant is still paid.
 */
pragma solidity ^0.8.24;

contract SendLoopFixed {

    address payable[] private refundAddresses;
    mapping (address => uint256) public refunds;

    constructor() {
        refundAddresses.push(payable(0x79B483371E87d664cd39491b5F06250165e4b184));
        refundAddresses.push(payable(0x79B483371E87d664cd39491b5f06250165e4b185));
    }

    function refundAll() public {
        for(uint256 x; x < refundAddresses.length; x++) {
            address payable recipient = refundAddresses[x];
            uint256 amount = refunds[recipient];
            refunds[recipient] = 0;
            // FIX: skip on failure instead of `require`-ing success. One bad
            // recipient can no longer block the others.
            (bool ok, ) = recipient.call{value: amount}("");
            ok; // failure is intentionally ignored
        }
    }
}
