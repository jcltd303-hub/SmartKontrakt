import test from "node:test";
import assert from "node:assert/strict";

import {
  CALIBRATION_NOTE_PROXY_GUARD,
  CALIBRATION_NOTE_PROXY_MECHANISM,
  calibrateProxyShell,
  looksLikeProxyShell,
} from "./severity-calibration.ts";
import { analyzeInput } from "./engine.ts";
import type { Finding } from "./types.ts";

/**
 * Gate 4 (2026-10-28). Measured on 0xDD9BC35aE942eF0cFa76930954a156B3fF30a4E1, a
 * verified 27-line OpenZeppelin ERC1967Proxy whose entire source is a constructor
 * and an internal `_implementation()` view: the archive recorded 29 criticals
 * against it, 17 of them `delegatecall`. A proxy delegates every call by design, and
 * its upgrade guard lives in the implementation at another address. Five such rows
 * carried 145 of 171 criticals in a 24-contract sample.
 */

const OZ_PROXY = `
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
abstract contract Proxy {
    function _delegate(address implementation) internal virtual {
        assembly {
            calldatacopy(0, 0, calldatasize())
            let result := delegatecall(gas(), implementation, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            switch result
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }
    function _implementation() internal view virtual returns (address);
    function _fallback() internal virtual { _delegate(_implementation()); }
    fallback () external payable virtual { _fallback(); }
    receive () external payable virtual { _fallback(); }
}
abstract contract ERC1967Upgrade {
    bytes32 private constant _IMPLEMENTATION_SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
    function _getImplementation() internal view returns (address) {
        return StorageSlot.getAddressSlot(_IMPLEMENTATION_SLOT).value;
    }
    function _upgradeToAndCall(address newImplementation, bytes memory data, bool forceCall) internal {
        StorageSlot.getAddressSlot(_IMPLEMENTATION_SLOT).value = newImplementation;
        if (data.length > 0 || forceCall) { Address.functionDelegateCall(newImplementation, data); }
    }
}
library StorageSlot {
    struct AddressSlot { address value; }
    function getAddressSlot(bytes32 slot) internal pure returns (AddressSlot storage r) { assembly { r.slot := slot } }
}
library Address {
    function functionDelegateCall(address target, bytes memory data) internal returns (bytes memory) {
        (bool success, bytes memory returndata) = target.delegatecall(data);
        require(success, "Address: low-level delegate call failed");
        return returndata;
    }
}
contract ERC1967Proxy is Proxy, ERC1967Upgrade {
    constructor(address _logic, bytes memory _data) payable { _upgradeToAndCall(_logic, _data, false); }
    function _implementation() internal view virtual override returns (address impl) { return ERC1967Upgrade._getImplementation(); }
}
`;

const finding = (over: Partial<Finding>): Finding => ({
  id: "x", severity: "critical", confidence: "high", title: "t", detector: "delegatecall",
  summary: "s", walkthrough: "w", exploitSolidity: "e", remediationSolidity: "r",
  locationFn: "fallback", locationLine: 1, snippet: "delegatecall(...)", swc: null, ...over,
});

test("a proxy shell is recognised, and a normal delegatecall contract is not", () => {
  assert.equal(looksLikeProxyShell(OZ_PROXY), true);
  const ordinary = `
    pragma solidity ^0.8.0;
    contract Router {
      function forward(address target, bytes calldata data) external {
        (bool ok, ) = target.delegatecall(data);
        require(ok);
      }
    }`;
  assert.equal(looksLikeProxyShell(ordinary), false, "delegatecall alone is not a proxy shell");
  const proxyWithKill = OZ_PROXY.replace("contract ERC1967Proxy", "contract ERC1967Proxy { function kill() external { selfdestruct(payable(msg.sender)); } }\ncontract X");
  assert.equal(looksLikeProxyShell(proxyWithKill), false, "a shell with selfdestruct is not a shell");
});

test("the shell's own delegation is informational, and the guard is capped at medium", () => {
  const out = calibrateProxyShell(
    [
      finding({ detector: "delegatecall", severity: "critical" }),
      finding({ detector: "arbitrary-dispatch-call", severity: "critical" }),
      finding({ detector: "unprotected-admin", severity: "critical" }),
      finding({ detector: "unchecked-return", severity: "critical" }),
    ],
    OZ_PROXY,
  );
  assert.equal(out[0]!.severity, "info");
  assert.match(out[0]!.summary, /proxy's own delegation mechanism/);
  assert.equal(out[1]!.severity, "info");
  assert.equal(out[2]!.severity, "medium");
  assert.ok(out[2]!.summary.includes(CALIBRATION_NOTE_PROXY_GUARD.trim()));
  assert.equal(out[3]!.severity, "critical", "unrelated detectors are untouched");
});

test("an ordinary delegatecall contract keeps its critical", () => {
  const ordinary = `
    pragma solidity ^0.8.0;
    contract Router {
      function forward(address target, bytes calldata data) external {
        (bool ok, ) = target.delegatecall(data);
        require(ok);
      }
    }`;
  const out = calibrateProxyShell([finding({ detector: "delegatecall", severity: "critical" })], ordinary);
  assert.equal(out[0]!.severity, "critical");
});

test("the real OZ proxy source produces no criticals end to end", () => {
  const report = analyzeInput(OZ_PROXY, "ERC1967Proxy", null);
  const criticals = report.findings.filter((f) => f.severity === "critical");
  assert.deepEqual(criticals.map((f) => f.detector), [], "a 27-line proxy shell has no criticals");
  const deleg = report.findings.find((f) => f.detector === "delegatecall");
  assert.ok(deleg, "the delegatecall is still reported");
  assert.equal(deleg!.severity, "info");
  assert.match(deleg!.summary, /proxy's own delegation mechanism/);
});
