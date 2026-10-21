/*
 * PROVENANCE
 * -------------------------------------------------------------------
 * Dataset repo : smartbugs/smartbugs-curated
 * Dataset path : dataset/time_manipulation/timed_crowdsale.sol
 * Upstream @source: https://github.com/SmartContractSecurity/SWC-registry/blob/master/test_cases/timestamp_dependence/timed_crowdsale.sol
 * Original pragma: ^0.4.25
 * Original vulnerable line(s): 13
 * Fixed variant: TimedCrowdsaleFixed
 *
 * REMEDIATION (time manipulation): the gate uses a block-number clock instead of
 * a manipulable `block.timestamp`, so warping the timestamp cannot flip it.
 */
pragma solidity ^0.8.24;

contract TimedCrowdsaleFixed {
  // FIX: block-number deadline (not directly manipulable by the block producer).
  uint256 public constant SALE_END_BLOCK = 10_000_000;

  function isSaleFinished() public view returns (bool) {
    return block.number >= SALE_END_BLOCK;
  }
}
