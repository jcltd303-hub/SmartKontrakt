/*
 * PROVENANCE
 * -------------------------------------------------------------------
 * Dataset repo : smartbugs/smartbugs-curated
 * Dataset path : dataset/time_manipulation/timed_crowdsale.sol
 * Upstream @source: https://github.com/SmartContractSecurity/SWC-registry/blob/master/test_cases/timestamp_dependence/timed_crowdsale.sol
 * Original pragma: ^0.4.25
 * Original vulnerable line(s): 13  (TIME_MANIPULATION / SWC-116)
 * Port pragma  : ^0.8.24
 *
 * Migration edits (mechanical 0.4 -> 0.8 only):
 *   - explicit visibility / modifier order (`view public` -> `public view`).
 * No semantics changed: the sale-finish gate is a bare `block.timestamp` check.
 *
 * VULNERABILITY: the sale's end condition depends solely on `block.timestamp`,
 * which a block producer can nudge, so the observable gate can be flipped by the
 * clock alone.
 */
pragma solidity ^0.8.24;

contract TimedCrowdsale {
  // Sale should finish exactly at January 1, 2019
  function isSaleFinished() public view returns (bool) {
    // <yes> <report> TIME_MANIPULATION
    return block.timestamp >= 1546300800;
  }
}
