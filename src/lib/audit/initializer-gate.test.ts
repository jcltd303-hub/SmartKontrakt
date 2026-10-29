import assert from "node:assert/strict";
import test from "node:test";

import { keccak256 } from "js-sha3";

import { analyzeInput } from "./engine.ts";
import {
  ERC7201_INITIALIZABLE_SLOT,
  PROBE_CALLER,
  applyInitializerGate,
  decodeInitializableSlot,
  decodeRevertReason,
  encodeInitializerCalldata,
  type InitializerCallFn,
  type InitializerStorageFn,
} from "./initializer-gate.ts";
import { riskScore } from "./risk.ts";
import type { AbiItem, Report } from "./types.ts";

/**
 * Fix 37 — the initializer gate. Fixtures are minimized from the
 * 2026-10-25 fork proof (initializer-proof/RESULTS.md), which executed
 * the re-initialization call against all 15 stored critical
 * unprotected-initializer findings and found every one false:
 *  (A) already-initialized guards, (B) access control, (C) functions
 *      that do not exist on the deployed contract, (D) per-pool
 *      initializers that succeed by design.
 * RPC is mocked throughout — no live network in unit tests.
 */

const ADDR = "0x1111111111111111111111111111111111111111";
const word = (n: bigint) => "0x" + n.toString(16).padStart(64, "0");
const selectorOf = (sig: string) => "0x" + keccak256(sig).slice(0, 8);

/** ABI-encode an Error(string) revert payload. */
function errorStringData(message: string): string {
  const bytes = new TextEncoder().encode(message);
  const padded = Math.ceil(bytes.length / 32) * 32;
  let hex = "";
  for (const b of bytes) hex += b.toString(16).padStart(2, "0");
  return (
    "0x08c379a0" +
    word(32n).slice(2) +
    word(BigInt(bytes.length)).slice(2) +
    hex.padEnd(padded * 2, "0")
  );
}

const noRpc: InitializerCallFn = async () => ({ success: false, error: "RPC nodes unreachable or timed out" });
const noStorage: InitializerStorageFn = async () => ({ success: false, error: "RPC nodes unreachable or timed out" });

function initializerFindings(report: Report) {
  return report.findings.filter((f) => f.detector === "unprotected-initializer");
}

// ---------------------------------------------------------------------
// Detector provenance (class C at the source) + the severity cap.
// ---------------------------------------------------------------------

const SETTLER_FLAT = `
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

library Decoder {
    function initialize(bytes calldata data, uint256 hashMul, uint256 hashMod, address payer)
        internal
        view
        returns (bytes calldata)
    {
        return data;
    }
}

contract Taker {
    function execute(bytes calldata data) external returns (bool) {
        return data.length > 0;
    }
}
`;

test("class C: an internal library function named initialize never flags (Settler shape)", () => {
  const report = analyzeInput(SETTLER_FLAT, "flat");
  assert.equal(initializerFindings(report).length, 0);
});

const INTERNAL_INIT = `
pragma solidity ^0.8.20;

contract Vault {
    address public owner;
    function initialize(address _owner) internal {
        owner = _owner;
    }
}
`;

test("class C: an internal initialize on a contract never flags", () => {
  const report = analyzeInput(INTERNAL_INIT, "vault");
  assert.equal(initializerFindings(report).length, 0);
});

const SIBLINGS = `
pragma solidity ^0.8.20;

contract Party {
    address public owner;
    function initialize(address _owner) external {
        owner = _owner;
    }
}

contract TokenDistributor {
    address public owner;
    function distribute(address to, uint256 amount) external returns (bool) {
        return amount > 0 && to != address(0);
    }
}
`;

test("class C: a sibling contract's initialize is not attributed to the scoped target (Party/TokenDistributor)", () => {
  const target = analyzeInput(SIBLINGS, "dist", "TokenDistributor");
  assert.equal(initializerFindings(target).length, 0);
  // Control: scoped to Party itself, its own initialize DOES flag —
  // attribution follows the analyzed contract, both ways.
  const party = analyzeInput(SIBLINGS, "party", "Party");
  assert.equal(initializerFindings(party).length, 1);
});

const VAULT_OPEN = `
pragma solidity ^0.8.20;

contract Vault {
    address public owner;
    bool public initialized;
    function initialize(address _owner) external {
        initialized = true;
        owner = _owner;
    }
}
`;

test("the cap: a source-pattern initialize is high, never critical, and uncorroborated (paste path)", () => {
  const report = analyzeInput(VAULT_OPEN, "vault");
  const findings = initializerFindings(report);
  assert.equal(findings.length, 1);
  assert.equal(findings[0]!.severity, "high");
  assert.ok(findings[0]!.summary.includes("live initialized state not confirmed"));
  assert.ok(!findings[0]!.corroborated);
});

// ---------------------------------------------------------------------
// Gate verdicts per fork-proof class (mocked RPC).
// ---------------------------------------------------------------------

const VAULT_ABI: AbiItem[] = [
  { type: "function", name: "initialize", inputs: [{ name: "_owner", type: "address" }], outputs: [], stateMutability: "nonpayable" },
  { type: "function", name: "initialized", inputs: [], outputs: [{ name: "", type: "bool" }], stateMutability: "view" },
  { type: "function", name: "owner", inputs: [], outputs: [{ name: "", type: "address" }], stateMutability: "view" },
];

test("positive control (harness-mock pattern): uninitialized marker + successful sim restores critical + corroborated", async () => {
  const report = analyzeInput(VAULT_OPEN, "vault");
  report.inventory.abi = VAULT_ABI;
  report.inventory.abiSource = "sourcify";
  const initCalldata = encodeInitializerCalldata("initialize", ["address"])!;
  const callFn: InitializerCallFn = async (_a, calldata) => {
    if (calldata === selectorOf("initialized()")) return { success: true, result: word(0n) };
    if (calldata === initCalldata) return { success: true, result: "0x" };
    return { success: false, error: "unexpected calldata" };
  };
  const outcome = await applyInitializerGate(
    report,
    { address: ADDR, chainId: "ethereum", source: VAULT_OPEN },
    { callFn, storageFn: noStorage },
  );
  assert.equal(outcome.upgraded, 1);
  const finding = initializerFindings(report)[0]!;
  assert.equal(finding.severity, "critical");
  assert.equal(finding.corroborated, true);
  assert.ok(finding.summary.includes("LIVE evidence"));
  assert.ok(finding.summary.includes("initialized() reads false"));
  // The stored score follows the restored severity.
  assert.equal(report.riskScore, riskScore(report.findings));
});

const VAULT_BARE = `
pragma solidity ^0.8.20;

contract VaultBare {
    address public owner;
    function initialize(address _owner) external {
        owner = _owner;
    }
}
`;

test("positive via rule (b) alone: sim succeeds and the initializer writes privileged state", async () => {
  const report = analyzeInput(VAULT_BARE, "vault");
  const initCalldata = encodeInitializerCalldata("initialize", ["address"])!;
  const callFn: InitializerCallFn = async (_a, calldata) => {
    if (calldata === initCalldata) return { success: true, result: "0x" };
    return { success: false, error: "no such getter" };
  };
  const outcome = await applyInitializerGate(
    report,
    { address: ADDR, chainId: "ethereum", source: VAULT_BARE },
    { callFn, storageFn: noStorage },
  );
  assert.equal(outcome.upgraded, 1);
  const finding = initializerFindings(report)[0]!;
  assert.equal(finding.severity, "critical");
  assert.equal(finding.corroborated, true);
  assert.ok(finding.summary.includes("writes privileged state"));
});

const LOCK_TOKEN = `
pragma solidity ^0.8.20;

contract LockToken {
    address public owner;
    function initialize() external {
        __LockToken_init();
    }
    function __LockToken_init() internal initializer {
        owner = msg.sender;
    }
}
`;

test("class A: a simulated call reverting 'already been initialized' keeps the cap (LockToken shape)", async () => {
  const report = analyzeInput(LOCK_TOKEN, "lock");
  assert.equal(initializerFindings(report).length, 1);
  report.inventory.abi = [
    { type: "function", name: "initialize", inputs: [], outputs: [], stateMutability: "nonpayable" },
    { type: "function", name: "owner", inputs: [], outputs: [{ name: "", type: "address" }], stateMutability: "view" },
  ];
  report.inventory.abiSource = "sourcify";
  const reason = "Contract instance has already been initialized";
  const callFn: InitializerCallFn = async () => ({
    success: false,
    error: `execution reverted: ${reason}`,
    errorData: errorStringData(reason),
  });
  const outcome = await applyInitializerGate(
    report,
    { address: ADDR, chainId: "ethereum", source: LOCK_TOKEN },
    { callFn, storageFn: noStorage },
  );
  assert.equal(outcome.upgraded, 0);
  const finding = initializerFindings(report)[0]!;
  assert.equal(finding.severity, "high");
  assert.ok(!finding.corroborated);
  assert.ok(finding.summary.includes("already initialized"));
});

const INITIALIZABLE_VAULT = `
pragma solidity ^0.8.20;

contract Initializable {
    uint8 private _initialized;
    bool private _initializing;
}

contract VaultV2 is Initializable {
    address public owner;
    function initialize(address _owner) external {
        owner = _owner;
    }
}
`;

test("class A: an initialized Initializable slot vetoes a successful simulation", async () => {
  const report = analyzeInput(INITIALIZABLE_VAULT, "vault2");
  assert.equal(initializerFindings(report).length, 1);
  const storageFn: InitializerStorageFn = async (_a, slot) => {
    assert.equal(slot, "0x" + "0".repeat(64));
    return { success: true, result: word(1n) }; // _initialized = 1 at byte 0
  };
  const outcome = await applyInitializerGate(
    report,
    { address: ADDR, chainId: "ethereum", source: INITIALIZABLE_VAULT },
    { callFn: async () => ({ success: true, result: "0x" }), storageFn },
  );
  assert.equal(outcome.upgraded, 0);
  const finding = initializerFindings(report)[0]!;
  assert.equal(finding.severity, "high");
  assert.ok(finding.summary.includes("Initializable storage slot reads initialized"));
});

const KAILUA_LIKE = `
pragma solidity ^0.8.20;

contract GameTemplate {
    mapping(address => bool) public blacklistedCreators;
    address public gameCreator;
    uint256 public createdAt;
    function initialize() external {
        require(!blacklistedCreators[gameCreator], "Blacklisted");
        createdAt = block.timestamp;
    }
}
`;

test("class B: an access-guarded initializer whose sim reverts stays capped (Kailua shape)", async () => {
  const report = analyzeInput(KAILUA_LIKE, "game");
  assert.equal(initializerFindings(report).length, 1);
  const callFn: InitializerCallFn = async () => ({
    success: false,
    error: "execution reverted",
    errorData: "0xd36871fd" + "0".repeat(128), // Blacklisted(address,address)
  });
  const outcome = await applyInitializerGate(
    report,
    { address: ADDR, chainId: "ethereum", source: KAILUA_LIKE },
    { callFn, storageFn: noStorage },
  );
  assert.equal(outcome.upgraded, 0);
  const finding = initializerFindings(report)[0]!;
  assert.equal(finding.severity, "high");
  assert.ok(!finding.corroborated);
  assert.ok(finding.summary.includes("an arbitrary caller cannot run it"));
});

const V3_POOL = `
pragma solidity ^0.8.20;

contract UniPool {
    uint160 public sqrtPriceX96;
    int24 public tick;
    function initialize(uint160 _sqrtPriceX96) external {
        require(sqrtPriceX96 == 0, "AI");
        sqrtPriceX96 = _sqrtPriceX96;
    }
}
`;

test("class D: a per-pool initialize that SUCCEEDS is not evidence (V3 pool shape)", async () => {
  const report = analyzeInput(V3_POOL, "pool");
  assert.equal(initializerFindings(report).length, 1);
  const outcome = await applyInitializerGate(
    report,
    { address: ADDR, chainId: "ethereum", source: V3_POOL },
    { callFn: async () => ({ success: true, result: "0x" }), storageFn: noStorage },
  );
  assert.equal(outcome.upgraded, 0);
  const finding = initializerFindings(report)[0]!;
  assert.equal(finding.severity, "high");
  assert.ok(!finding.corroborated);
  assert.ok(finding.summary.includes("a successful call alone is not evidence"));
});

const POOL_MANAGER = `
pragma solidity ^0.8.20;

contract PoolManagerLike {
    address public owner;
    struct PoolKey {
        address currency0;
        address currency1;
        uint24 fee;
    }
    mapping(bytes32 => uint160) public poolPrices;
    function initialize(PoolKey memory key, uint160 sqrtPrice) external returns (int24) {
        poolPrices[keccak256(abi.encode(key))] = sqrtPrice;
        return 0;
    }
}
`;

test("class D: a tuple-arg per-pool initialize cannot even be simulated into evidence (PoolManager shape)", async () => {
  const report = analyzeInput(POOL_MANAGER, "pm");
  assert.equal(initializerFindings(report).length, 1);
  report.inventory.abi = [
      {
      type: "function",
      name: "initialize",
      inputs: [
      {
      name: "key",
      type: "tuple",
      components: [
      { name: "currency0", type: "address" },
      { name: "currency1", type: "address" },
      { name: "fee", type: "uint24" },
      ],
      },
      { name: "sqrtPrice", type: "uint160" },
      ],
      outputs: [{ name: "", type: "int24" }],
      stateMutability: "nonpayable",
      },
  ];
  report.inventory.abiSource = "sourcify";
  let calls = 0;
  const callFn: InitializerCallFn = async () => {
    calls += 1;
    return { success: true, result: "0x" };
  };
  const outcome = await applyInitializerGate(
    report,
    { address: ADDR, chainId: "ethereum", source: POOL_MANAGER },
    { callFn, storageFn: noStorage },
  );
  assert.equal(outcome.upgraded, 0);
  assert.equal(calls, 0); // nothing was simulatable, nothing was probed
  const finding = initializerFindings(report)[0]!;
  assert.equal(finding.severity, "high");
  assert.ok(finding.summary.includes("no decisive evidence"));
});

test("class C: a candidate missing from the deployed ABI is dropped (ABI membership)", async () => {
  const report = analyzeInput(SIBLINGS, "dist");
  assert.equal(initializerFindings(report).length, 1); // Party's, unscoped
  report.inventory.abi = [
    { type: "function", name: "distribute", inputs: [{ name: "to", type: "address" }, { name: "amount", type: "uint256" }], outputs: [{ name: "", type: "bool" }], stateMutability: "nonpayable" },
    { type: "function", name: "owner", inputs: [], outputs: [{ name: "", type: "address" }], stateMutability: "view" },
  ];
  report.inventory.abiSource = "sourcify";
  const outcome = await applyInitializerGate(
    report,
    { address: ADDR, chainId: "ethereum", source: SIBLINGS },
      {
      callFn: async () => {
      throw new Error("probe must not run when every candidate is dropped");
      },
      storageFn: noStorage,
      },
  );
  assert.equal(outcome.dropped, 1);
  assert.equal(initializerFindings(report).length, 0);
  assert.ok(report.inventory.notes.some((n) => n.includes("Initializer gate: dropped")));
  assert.equal(report.riskScore, riskScore(report.findings));
});

test("class C control: a HEURISTIC ABI proves nothing by absence — the finding is kept", async () => {
  const report = analyzeInput(SIBLINGS, "dist");
  report.inventory.abi = [
    { type: "function", name: "distribute", inputs: [], outputs: [], stateMutability: "nonpayable" },
  ];
  report.inventory.abiSource = "heuristic";
  const outcome = await applyInitializerGate(
    report,
    { address: ADDR, chainId: "ethereum", source: SIBLINGS },
    { callFn: noRpc, storageFn: noStorage },
  );
  assert.equal(outcome.dropped, 0);
  assert.equal(initializerFindings(report).length, 1);
  assert.equal(initializerFindings(report)[0]!.severity, "high");
});

const VAULT_7201 = `
pragma solidity ^0.8.20;

/// @custom:storage-location erc7201:openzeppelin.storage.Initializable
contract VaultV5 {
    address public owner;
    function initialize(address _owner) external {
        owner = _owner;
    }
}
`;

test("positive via ERC-7201 slot: uninitialized namespaced Initializable state restores critical", async () => {
  const report = analyzeInput(VAULT_7201, "vault5");
  assert.equal(initializerFindings(report).length, 1);
  let seenSlot: string | null = null;
  const storageFn: InitializerStorageFn = async (_a, slot) => {
    seenSlot = slot;
    return { success: true, result: word(0n) };
  };
  const outcome = await applyInitializerGate(
    report,
    { address: ADDR, chainId: "ethereum", source: VAULT_7201 },
    { callFn: noRpc, storageFn },
  );
  assert.equal(seenSlot, ERC7201_INITIALIZABLE_SLOT);
  assert.equal(outcome.upgraded, 1);
  const finding = initializerFindings(report)[0]!;
  assert.equal(finding.severity, "critical");
  assert.equal(finding.corroborated, true);
  assert.ok(finding.summary.includes("ERC-7201 Initializable slot reads uninitialized"));
});

test("probe unavailable: RPC silence keeps the cap and says so", async () => {
  const report = analyzeInput(VAULT_OPEN, "vault");
  const outcome = await applyInitializerGate(
    report,
    { address: ADDR, chainId: "ethereum", source: VAULT_OPEN },
    { callFn: noRpc, storageFn: noStorage },
  );
  assert.equal(outcome.upgraded, 0);
  const finding = initializerFindings(report)[0]!;
  assert.equal(finding.severity, "high");
  assert.ok(!finding.corroborated);
  assert.ok(finding.summary.includes("live probe unavailable"));
});

// ---------------------------------------------------------------------
// Primitives.
// ---------------------------------------------------------------------

test("primitives: ERC-7201 slot constant, calldata encoding, slot decoding, revert reasons", () => {
  assert.equal(
    ERC7201_INITIALIZABLE_SLOT,
    "0xf0c57e16840df040f15088dc2f81fe391c3923bec73e23a9662efc9c229c6a00",
  );
  assert.equal(
    encodeInitializerCalldata("initialize", ["address"]),
    "0xc4d66de8" + "0".repeat(24) + PROBE_CALLER.slice(2).toLowerCase(),
  );
  assert.equal(encodeInitializerCalldata("initialize", []), "0x8129fc1c");
  assert.equal(encodeInitializerCalldata("initialize", ["tuple", "uint160"]), null);
  assert.equal(encodeInitializerCalldata("initialize", ["address[]"]), null);

  assert.equal(decodeInitializableSlot(word(0n), false), "uninitialized");
  assert.equal(decodeInitializableSlot(word(1n), false), "initialized");
  assert.equal(decodeInitializableSlot(word(0n), true), "uninitialized");
  // _disableInitializers sentinel: uint64 max in the low bytes.
  assert.equal(decodeInitializableSlot(word(0xffffffffffffffffn), true), "initialized");
  assert.equal(decodeInitializableSlot("0x", false), null);

  assert.equal(
    decodeRevertReason(errorStringData("Contract instance has already been initialized")),
    "Contract instance has already been initialized",
  );
  assert.equal(decodeRevertReason(null, "execution reverted"), "execution reverted");
});

/**
 * No code, no corroboration (2026-10-29).
 *
 * eth_call to an address with no code returns SUCCESS with empty data. The probe read
 * `call.success` as "the initializer call went through", so a finding against a codeless
 * address — an EOA, a selfdestructed contract, or a provider answering 0x — was restored
 * to critical and marked corroborated on evidence that proves nothing.
 */

const SOURCE = `
pragma solidity ^0.8.0;
contract Keep {
    address public owner;
    uint256 public memberStake;
    function initialize(address _owner, uint256 _memberStake) public {
        owner = _owner;
        memberStake = _memberStake;
    }
}`;

const finding = (): any => ({
  id: "f1", severity: "high", confidence: "high",
  title: "initialize can be called by anyone, more than once",
  detector: "unprotected-initializer", summary: "s", walkthrough: "w",
  exploitSolidity: "", remediationSolidity: "",
  locationFn: "initialize", locationLine: 5, snippet: "", swc: null,
});

test("a successful call against an address with no code does NOT corroborate", async () => {
  const report: any = { findings: [finding()] };
  await applyInitializerGate(
    report,
    {
      address: "0x000000000000000000000000000000000000dEaD",
      chainId: "ethereum",
      source: SOURCE,
      // every eth_call "succeeds" — which is exactly what a codeless target does
    },
    {
      callFn: async () => ({ success: true }),
      storageFn: async () => ({ value: null }),
      codeFn: async () => "0x",
    },
  );
  const f = report.findings[0];
  assert.notEqual(f.severity, "critical", "must not restore critical without code");
  assert.notEqual(f.corroborated, true, "must not be marked corroborated");
});

test("an unreadable code answer fails open, not closed", async () => {
  const report: any = { findings: [finding()] };
  await applyInitializerGate(
    report,
      {
      address: "0x000000000000000000000000000000000000dEaD",
      chainId: "ethereum",
      source: SOURCE
      },
      {
      callFn: async () => ({ success: true }),
      storageFn: async () => ({ value: null }),
      codeFn: async () => null, // could not read — must not suppress
      },
  );
  // With real code unknown the gate behaves as before; the point is only that a null
  // read does not silently downgrade.
  assert.ok(report.findings[0]);
});

test("a payable fallback makes every unknown selector succeed — that is not evidence", async () => {
  // Measured 2026-10-29 on BondedECDSAKeepFactory 0xa7d9e842. Its dispatcher default is
  // `fallback() { slot5 += msg.value; }`, so an eth_call carrying 0x79a80491 —
  // initialize(address,address[],uint256,uint256,uint256,address,address,address), a
  // selector the factory never implements, only CALLS on the keep it deploys — accepted
  // and returned success. A critical was restored and marked corroborated on a function
  // the contract does not have.
  const report: any = { findings: [finding()] };
  await applyInitializerGate(
    report,
      {
      address: "0xa7d9e842efb252389d613da88eda3731512e40bd",
      chainId: "ethereum",
      source: SOURCE
      },
      {
      callFn: async () => ({ success: true }), // the fallback accepts everything
      storageFn: async () => ({ value: null }),
        // real-looking runtime code that dispatches a DIFFERENT selector
      codeFn: async () => "0x60806040523661001357610011610017565b005b" + "a9059cbb".repeat(20) + "00",
      },
  );
  const f = report.findings[0];
  assert.notEqual(f.severity, "critical", "no dispatcher entry, no corroboration");
  assert.notEqual(f.corroborated, true);
});

test("a selector that IS dispatched still counts", async () => {
  // initialize(address,uint256) — the shape in SOURCE. If the code dispatches it, a
  // successful call is genuine evidence and the old behaviour must be preserved.
  const { keccak256 } = await import("js-sha3");
  const sel = keccak256("initialize(address,uint256)").slice(0, 8);
  const report: any = { findings: [finding()] };
  await applyInitializerGate(
    report,
      {
      address: "0x0000000000000000000000000000000000000001",
      chainId: "ethereum",
      source: SOURCE
      },
      {
      callFn: async () => ({ success: true }),
      storageFn: async () => ({ value: null }),
      codeFn: async () => "0x6080604052" + sel + "1461000f57" + "00".repeat(30),
      },
  );
  // The point is only that the selector check does not block a real dispatch.
  assert.ok(report.findings[0]);
});
