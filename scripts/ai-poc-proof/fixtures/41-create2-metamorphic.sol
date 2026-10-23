// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// Fixture for fallback type 41 (CREATE2 metamorphic redeploy).
/// The template is SELF-CONTAINED: it deploys its own factory and
/// impls on the fork and proves same-address code replacement. The
/// fixture is just a deployed placeholder so POC_TARGET points at a
/// live contract with code (the template's fork-sanity check).
contract Placeholder41 {
    uint256 public marker = 41;
}
