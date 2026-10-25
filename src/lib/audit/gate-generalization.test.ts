import test from "node:test";
import assert from "node:assert/strict";

import { analyzeInput } from "./engine.ts";
import type { Finding } from "./types.ts";

/**
 * Fix 38 regression fixtures — the gate generalized to delegatecall,
 * reentrancy and selfdestruct. Every FP shape is drawn from the
 * 2026-10-25 fork-proof sweep #2 corpus (critical-sweep/RESULTS.md;
 * verified sources under critical-sweep/artifacts/), minimized to the
 * decisive structure. The sweep executed all 37 stored criticals in
 * these classes against a mainnet fork: 37/37 were false positives.
 * The positive controls are the sweep harness rigs' shapes and MUST
 * keep flagging at full severity — a gate that eats real findings is
 * worse than the FP rate it fixes.
 */

function findingsFor(source: string, detector: string): Finding[] {
  const report = analyzeInput(source, "fix38-fixture");
  return report.findings.filter((f) => f.detector === detector);
}

function oneFor(source: string, detector: string): Finding {
  const hits = findingsFor(source, detector);
  assert.equal(hits.length, 1, `expected exactly one ${detector} finding, got ${hits.length}`);
  return hits[0] as Finding;
}

// ------------------------------------------------------------------
// delegatecall
// ------------------------------------------------------------------

test("delegatecall: OZ Address utility with no contract call site is not a finding (Fix 24 shape)", () => {
  const src = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
library Address {
    function functionDelegateCall(address target, bytes memory data) internal returns (bytes memory) {
        (bool success, bytes memory returndata) = target.delegatecall(data);
        require(success, "delegatecall failed");
        return returndata;
    }
}
contract Wallet {
    uint256 public balance;
    function deposit() public payable { balance += msg.value; }
}`;
  assert.equal(findingsFor(src, "delegatecall").length, 0);
});

test("delegatecall: library utility reached with a caller-supplied target still flags critical", () => {
  const src = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
library Address {
    function functionDelegateCall(address target, bytes memory data) internal returns (bytes memory) {
        (bool success, bytes memory returndata) = target.delegatecall(data);
        require(success, "delegatecall failed");
        return returndata;
    }
}
contract Exec {
    function go(address target, bytes memory data) public returns (bytes memory) {
        return Address.functionDelegateCall(target, data);
    }
}`;
  const f = oneFor(src, "delegatecall");
  assert.equal(f.severity, "critical");
});

test("delegatecall: EIP-173 internal _setImplementation behind onlyOwner upgrade entries is info", () => {
  // Sweep artifact 0x6f7a14bd931554683ed15dc92e25d046ed68ea68: the
  // delegatecall site is the internal setter; the guards on the
  // upgradeTo entries executed and held on the fork (NOT_AUTHORIZED).
  const src = `// SPDX-License-Identifier: MIT
pragma solidity ^0.7.0;
contract EIP173Proxy {
    address public implementation;
    address public owner;
    modifier onlyOwner() {
        require(msg.sender == owner, "NOT_AUTHORIZED");
        _;
    }
    function upgradeTo(address newImplementation) external onlyOwner {
        _setImplementation(newImplementation, "");
    }
    function upgradeToAndCall(address newImplementation, bytes calldata data) external payable onlyOwner {
        _setImplementation(newImplementation, data);
    }
    function _setImplementation(address newImplementation, bytes memory data) internal {
        implementation = newImplementation;
        if (data.length > 0) {
            (bool ok, ) = newImplementation.delegatecall(data);
            require(ok, "upgrade call failed");
        }
    }
}`;
  const hits = findingsFor(src, "delegatecall");
  assert.ok(hits.length >= 1, "expected the upgrade path finding");
  for (const f of hits) {
    assert.equal(f.severity, "info", `expected info, got ${f.severity} (${f.title})`);
  }
});

test("delegatecall: fixed stored implementation through a public entry reclassifies low", () => {
  // Sweep artifact 0x0feccb11c5b61b3922c511d0f002c0b72d770dce
  // (MarketingMiningDelegator): delegateToImplementation passes the
  // STORED implementation — the caller supplies data, never the
  // target. The fork confirmed nothing was redirectable.
  const src = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract Delegator {
    address public implementation;
    function delegateToImplementation(bytes memory data) public returns (bytes memory) {
        return delegateTo(implementation, data);
    }
    function become(bytes memory data) public {
        delegateToImplementation(data);
    }
    function delegateTo(address callee, bytes memory data) internal returns (bytes memory) {
        (bool success, bytes memory returnData) = callee.delegatecall(data);
        require(success, "delegate failed");
        return returnData;
    }
}`;
  const f = oneFor(src, "delegatecall");
  assert.equal(f.severity, "low");
  assert.ok(f.title.includes("stored address"), f.title);
  assert.ok(f.summary.includes("stored"), f.summary);
});

test("delegatecall: fixed-caller gateway gate (if (msg.sender != X) revert) caps at high", () => {
  // Sweep gateway shape: invoke() delegatecalls a caller-supplied
  // target, but a fixed stored caller is the only accepted sender —
  // the fork call from a fresh address reverted Unauthorized().
  const src = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract Gateway {
    error Unauthorized();
    address public constant GATEWAY = 0x1111111111111111111111111111111111111111;
    function invoke(address target, bytes memory data) external returns (bytes memory) {
        if (msg.sender != GATEWAY) revert Unauthorized();
        (bool ok, bytes memory ret) = target.delegatecall(data);
        require(ok, "invoke failed");
        return ret;
    }
}`;
  const f = oneFor(src, "delegatecall");
  assert.equal(f.severity, "high");
  assert.ok(f.summary.includes("access-controlled"), f.summary);
});

test("delegatecall: helper behind an unverifiable-modifier entry caps at high and names the modifier", () => {
  // The Cub _applyFix shape: the helper is reached only through an
  // entry carrying a custom modifier defined outside the file
  // (onlyBeacon). Unverifiable means possible guard: cap + note,
  // never critical, never dropped.
  const src = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract Cub {
    function applyFix(address impl, bytes memory data) external onlyBeacon {
        _applyFix(impl, data);
    }
    function _applyFix(address impl, bytes memory data) internal {
        (bool ok, ) = impl.delegatecall(data);
        require(ok, "fix failed");
    }
}`;
  const f = oneFor(src, "delegatecall");
  assert.equal(f.severity, "high");
  assert.ok(f.summary.includes("onlyBeacon"), f.summary);
});

test("delegatecall: reachable only through the initializer entry caps at high with the deferral note", () => {
  // The Aave pair's shape: the delegatecall lives behind initialize.
  // Whether it can still run is the initializer gate's live question
  // (Fix 37) — source alone does not earn the critical.
  const src = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract Vault {
    bool private initialized;
    function initialize(address logic, bytes memory data) external {
        require(!initialized, "already initialized");
        initialized = true;
        (bool ok, ) = logic.delegatecall(data);
        require(ok, "init delegatecall failed");
    }
}`;
  const f = oneFor(src, "delegatecall");
  assert.equal(f.severity, "high");
  assert.ok(f.summary.includes("initializer"), f.summary);
});

test("delegatecall: open box with a caller-supplied target flags critical (positive control)", () => {
  const src = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract OpenBox {
    function exec(address target, bytes memory data) external {
        (bool ok, ) = target.delegatecall(data);
        require(ok, "exec failed");
    }
}`;
  const f = oneFor(src, "delegatecall");
  assert.equal(f.severity, "critical");
});

test("delegatecall: caller-supplied target through an internal helper flags critical and names the entry (positive control)", () => {
  const src = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract Box {
    function exec(address target, bytes memory data) external {
        _run(target, data);
    }
    function _run(address t, bytes memory d) internal {
        (bool ok, ) = t.delegatecall(d);
        require(ok, "run failed");
    }
}`;
  const f = oneFor(src, "delegatecall");
  assert.equal(f.severity, "critical");
  assert.equal(f.locationFn, "exec");
});

// ------------------------------------------------------------------
// reentrancy
// ------------------------------------------------------------------

test("reentrancy: dividend failure-rollback write is low — CEI holds (sweep 0x18d5 shape)", () => {
  // Real body from 0x18d5beb2b1271724b53cf59a3dff55f31ae8facd
  // DividendTracker: the credit is added BEFORE the call and the
  // post-call write is the .sub rollback inside if(!success).
  const src = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract DividendTracker {
    mapping(address => uint256) public withdrawnDividends;
    mapping(address => uint256) public balances;
    function withdrawDividend() public {
        _withdrawDividendOfUser(msg.sender);
    }
    function _withdrawDividendOfUser(address user) internal returns (uint256) {
        uint256 _withdrawableDividend = balances[user];
        if (_withdrawableDividend > 0) {
            withdrawnDividends[user] = withdrawnDividends[user] + _withdrawableDividend;
            (bool success, ) = user.call{value: _withdrawableDividend}("");
            if (!success) {
                withdrawnDividends[user] = withdrawnDividends[user] - _withdrawableDividend;
                return 0;
            }
            return _withdrawableDividend;
        }
        return 0;
    }
}`;
  const f = oneFor(src, "reentrancy");
  assert.equal(f.severity, "low");
  assert.ok(f.summary.includes("rollback"), f.summary);
  assert.equal(f.locationFn, "withdrawDividend");
});

test("reentrancy: gas:3000 dividend payout is info — the cap cannot carry a reentry (sweep 0x198d shape)", () => {
  const src = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract GasDivs {
    mapping(address => uint256) public withdrawnDividends;
    mapping(address => uint256) public balances;
    uint256 public totalDividendsWithdrawn;
    function withdrawDividend() public {
        _pay(msg.sender);
    }
    function _pay(address account) internal returns (uint256) {
        uint256 _withdrawableDividend = balances[account];
        withdrawnDividends[account] += _withdrawableDividend;
        (bool success, ) = account.call{value: _withdrawableDividend, gas: 3000}("");
        if (!success) {
            withdrawnDividends[account] -= _withdrawableDividend;
            totalDividendsWithdrawn -= _withdrawableDividend;
            return 0;
        }
        return _withdrawableDividend;
    }
}`;
  const hits = findingsFor(src, "reentrancy");
  assert.ok(hits.length >= 1, "expected a reentrancy finding");
  for (const f of hits) {
    assert.equal(f.severity, "info", `expected info, got ${f.severity} (${f.title})`);
  }
});

test("reentrancy: router-swap payout leg through a fixed stored router is low", () => {
  // The sweep's router shape: the credit settles before the call,
  // the payout leg runs through the FIXED stored router (the payee's
  // code never runs inside the flagged call), and a non-credit
  // bookkeeping write lands after.
  const src = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
interface IRouter {
    function swap(address to) external payable returns (uint256);
}
contract ClaimRouter {
    mapping(address => uint256) public balances;
    mapping(address => uint256) public claimed;
    IRouter public router;
    function claim(uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient");
        balances[msg.sender] -= amount;
        uint256 out = router.swap{value: amount}(msg.sender);
        claimed[msg.sender] = out;
    }
}`;
  const f = oneFor(src, "reentrancy");
  assert.equal(f.severity, "low");
  assert.ok(f.title.includes("fixed stored contract"), f.title);
});

test("reentrancy: internal _settle behind nonReentrant/onlyOwner entries is low and names an entry (Noper shape)", () => {
  // Sweep artifact 0xe375ac202b34d6dd3450ad90851828a42543d8eb: the
  // flagged helper is internal; every public caller is guarded.
  const src = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract Tourney {
    mapping(address => uint256) public prizes;
    address public owner;
    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }
    modifier nonReentrant() {
        _;
    }
    function settle() external nonReentrant {
        _settle(msg.sender);
    }
    function distribute() external onlyOwner nonReentrant {
        _settle(msg.sender);
    }
    function _settle(address s) internal {
        uint256 amt = prizes[s];
        (bool ok, ) = s.call{value: amt}("");
        require(ok, "pay failed");
        prizes[s] = 0;
    }
}`;
  const f = oneFor(src, "reentrancy");
  assert.equal(f.severity, "low");
  assert.notEqual(f.locationFn, "_settle");
});

test("reentrancy: KatWalkerz hand-rolled withdrawing mutex is low (real CEI break, neutralized)", () => {
  // Real body from 0xb2b140f098d2a1e71ac5f70cb896bb32f80e97f2: the
  // balance IS zeroed after the call (a genuine CEI violation), but
  // the hand-rolled flag makes the reentry revert — the fork proved
  // it unexploitable.
  const src = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract KatWalkerzRoyalties {
    mapping(address => uint256) public balances;
    uint256 public winnerFunds;
    bool private withdrawing;
    function withdraw(address addr) public {
        require(!withdrawing, "withdrawing in process");
        require(balances[msg.sender] > 0, "no balance");
        uint256 amount = balances[msg.sender];
        withdrawing = true;
        (bool success, ) = payable(addr).call{value: amount}("");
        require(success, "failed");
        balances[msg.sender] = 0;
        winnerFunds -= amount;
        withdrawing = false;
    }
}`;
  const f = oneFor(src, "reentrancy");
  assert.equal(f.severity, "low");
  assert.ok(f.summary.includes("withdrawing"), f.summary);
});

test("reentrancy: balance zeroed after the call with no guard flags critical (positive control)", () => {
  // The KatWalkerz shape MINUS the mutex — the sweep harness rig:
  // this one must stay critical.
  const src = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract Vault {
    mapping(address => uint256) public balances;
    function withdraw() external {
        uint256 amount = balances[msg.sender];
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "call failed");
        balances[msg.sender] = 0;
    }
}`;
  const f = oneFor(src, "reentrancy");
  assert.equal(f.severity, "critical");
});

test("reentrancy: helper behind an OPEN public entry flags critical and names the entry (positive control)", () => {
  const src = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract ClaimBox {
    mapping(address => uint256) public balances;
    function claim() external {
        _pay();
    }
    function _pay() internal {
        uint256 amount = balances[msg.sender];
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "call failed");
        balances[msg.sender] = 0;
    }
}`;
  const f = oneFor(src, "reentrancy");
  assert.equal(f.severity, "critical");
  assert.equal(f.locationFn, "claim");
});

// ------------------------------------------------------------------
// selfdestruct
// ------------------------------------------------------------------

test("selfdestruct: Wallet.sol onlymanyowners kill is medium — the modifier IS the access check", () => {
  // Sweep artifacts (all 7 selfdestruct criticals): kill carries
  // onlymanyowners(sha3(msg.data)), which delegates the caller check
  // to confirmAndCheck → m_ownerIndex[uint(msg.sender)]. A non-owner
  // call on the fork was a silent no-op; 202 ETH sat behind one.
  const src = `// SPDX-License-Identifier: MIT
pragma solidity ^0.4.24;
contract Wallet {
    uint[256] public m_owners;
    uint[256] public m_ownerIndex;
    modifier onlymanyowners(bytes32 _operation) {
        if (confirmAndCheck(_operation))
            _;
    }
    function confirmAndCheck(bytes32 _operation) internal returns (bool) {
        uint ownerIndex = m_ownerIndex[uint(msg.sender)];
        if (ownerIndex == 0) return false;
        return true;
    }
    function kill(address _to) onlymanyowners(sha3(msg.data)) external {
        suicide(_to);
    }
}`;
  const f = oneFor(src, "selfdestruct");
  assert.equal(f.severity, "medium");
});

test("selfdestruct: unverifiable custom modifier caps at high and names it", () => {
  const src = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract Curated {
    function kill(address payable to) external onlyCurator {
        selfdestruct(to);
    }
}`;
  const f = oneFor(src, "selfdestruct");
  assert.equal(f.severity, "high");
  assert.ok(f.summary.includes("onlyCurator"), f.summary);
});

test("selfdestruct: unguarded kill flags critical (positive control)", () => {
  const src = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract OpenKill {
    function kill(address payable to) external {
        selfdestruct(to);
    }
}`;
  const f = oneFor(src, "selfdestruct");
  assert.equal(f.severity, "critical");
});

test("selfdestruct: internal-only helper with no public path is not flagged", () => {
  const src = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract Hidden {
    uint256 public x;
    function deposit() public payable {
        x += msg.value;
    }
    function _kill(address payable to) internal {
        selfdestruct(to);
    }
}`;
  assert.equal(findingsFor(src, "selfdestruct").length, 0);
});
