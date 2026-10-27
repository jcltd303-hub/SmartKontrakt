import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync } from "node:fs";
import path from "node:path";

import { analyzeInput } from "./engine.ts";
import {
  DETECTOR_FAMILIES,
  DETECTOR_FAMILY,
  HARNESS_ONLY_DETECTORS,
  detectorsInFamily,
  familyForDetector,
  groupFindingsByFamily,
} from "./detector-registry.ts";
import { SMARTBUGS_BY_DETECTOR } from "./smartbugs.ts";
import { reportableFindings, sortFindingsForTriage } from "./detect.ts";
import type { Finding } from "./types.ts";

/**
 * Detection quality gates (2026-10-27).
 *
 * Four properties the previous four commits asserted in prose and never
 * enforced:
 *
 *  1. the detector registry is TOTAL over what the engine emits;
 *  2. every detector is exercised by a behavioural fixture (ratcheted — the
 *     allowlist below may only shrink);
 *  3. reachability is consumed, not just tagged: a clean control yields no
 *     REACHABLE finding, and the triage order puts REACHABLE first;
 *  4. confidence and money figures are derived from evidence, not claimed.
 */

/**
 * Sources are read from the repo root rather than `import.meta.url`: the suite
 * runs from the repo root under `npm test`, and this also keeps it working when
 * the file is bundled for a local run, where import.meta.url points at the
 * bundle instead of the source directory.
 */
const AUDIT_DIR = path.join(process.cwd(), "src/lib/audit");

function emittedDetectors(): string[] {
  const ids = new Set<string>();
  for (const rel of ["detect.ts", "bytecode.ts", "engine.ts"]) {
    const src = readFileSync(path.join(AUDIT_DIR, rel), "utf8");
    for (const m of src.matchAll(/detector:\s*"([^"]+)"/g)) ids.add(m[1]!);
  }
  // bytecode.ts builds these two dynamically.
  ids.add("bytecode-delegatecall");
  ids.add("bytecode-callcode");
  return [...ids].sort();
}

function findingsFor(source: string): Finding[] {
  return analyzeInput(source, "quality-gate").findings;
}

// ------------------------------------------------------------------
// 1. Registry totality
// ------------------------------------------------------------------

test("the family registry is total over the emitted detectors", () => {
  assert.deepEqual(Object.keys(DETECTOR_FAMILY).sort(), emittedDetectors());
});

test("every family is declared and non-empty", () => {
  for (const meta of DETECTOR_FAMILIES) {
    assert.ok(meta.question.length > 20, `${meta.id} needs a real question`);
    assert.ok(detectorsInFamily(meta.id).length > 0, `${meta.id} has no detectors`);
  }
  // And no detector is in a family that is not declared.
  const declared = new Set(DETECTOR_FAMILIES.map((f) => f.id));
  for (const fam of Object.values(DETECTOR_FAMILY)) assert.ok(declared.has(fam), fam);
});

test("harness-only detectors are declared, categorised, and NOT counted as covered", () => {
  // Found by making the registry total: these three shipped a PoC template and
  // a SmartBugs category but no rule ever emits them.
  for (const id of HARNESS_ONLY_DETECTORS) {
    assert.ok(SMARTBUGS_BY_DETECTOR[id], `${id} should still have a SmartBugs category`);
    assert.equal(
      DETECTOR_FAMILY[id],
      undefined,
      `${id} must not get a family — that would claim coverage the analyzer does not have`,
    );
  }
  // Was 3; `front-running` gained a rule on 2026-10-27 and moved into the
  // `ordering` family. The list may only shrink, so this number only goes down.
  assert.equal(HARNESS_ONLY_DETECTORS.length, 2);
});

test("familyForDetector falls back to analyzer-meta for an unknown id", () => {
  assert.equal(familyForDetector("no-such-detector"), "analyzer-meta");
});

// ------------------------------------------------------------------
// 2. Every detector is exercised (ratchet)
// ------------------------------------------------------------------

/**
 * Detectors with no behavioural fixture yet: named by no test file and not in
 * the detector self-check. The list may only SHRINK — the assertion is
 * equality, so adding a rule without a fixture fails, and removing one of
 * these from the list is the reward for writing its fixture.
 *
 * Their behaviour IS reachable today (each has a PoC template and a harness
 * mapping), which is why this is a fixture debt rather than a bug.
 */
const NO_BEHAVIOURAL_FIXTURE = [
  "assembly-param-sstore",
  "assembly-sstore",
  "default-visibility",
  "erc20-unchecked",
  "extcodesize",
  "fee-on-transfer",
  "hardcoded-gas",
  "locked-ether",
  "missing-event",
  "private-secret",
  "report-cap",
  "rtl-override",
  "storage-gap",
  "strict-balance",
  "zero-address",
  "zero-slippage-swap",
];

test("every emitted detector is exercised by a fixture, or on the shrinking debt list", () => {
  let blob = "";
  for (const file of readdirSync(AUDIT_DIR)) {
    if (!file.endsWith(".test.ts")) continue;
    if (file === "poc-fallbacks.test.ts" || file === "analyzer-version.test.ts") continue;
    if (file === "detection-quality.test.ts") continue;
    blob += readFileSync(path.join(AUDIT_DIR, file), "utf8");
  }
  blob += readFileSync(path.join(AUDIT_DIR, "selfcheck.ts"), "utf8");

  const uncovered = emittedDetectors().filter((d) => !blob.includes(d));
  assert.deepEqual(
    uncovered.sort(),
    [...NO_BEHAVIOURAL_FIXTURE].sort(),
    "a detector without a fixture was added, or one was covered and the debt list was not updated",
  );
});

// ------------------------------------------------------------------
// 3. Reachability is consumed
// ------------------------------------------------------------------

test("a clean control produces no REACHABLE finding", () => {
  const src = `pragma solidity ^0.8.0;
contract Clean {
    address public owner;
    modifier onlyOwner() { require(msg.sender == owner, "owner"); _; }
    mapping(address => uint256) public balances;
    function withdraw() external {
        uint256 amt = balances[msg.sender];
        balances[msg.sender] = 0;
        payable(msg.sender).transfer(amt);
    }
    function sweep() external onlyOwner {
        payable(owner).transfer(address(this).balance);
    }
}`;
  assert.deepEqual(reportableFindings(findingsFor(src)), []);
});

test("the triage order puts REACHABLE first, whatever the severity", () => {
  const src = `pragma solidity ^0.8.0;
contract Mixed {
    address public owner;
    // gated critical: a privileged key can destroy the contract
    function drain() external onlyOwner {
        selfdestruct(payable(msg.sender));
    }
    // reachable, one severity band lower: anyone can take ownership
    function setOwner(address newOwner) external {
        owner = newOwner;
    }
}`;
  const sorted = sortFindingsForTriage(findingsFor(src));
  assert.ok(sorted.length >= 2, `expected at least two findings, got ${sorted.length}`);
  const first = sorted[0]!;
  assert.equal(first.reachability, "REACHABLE", `first finding was ${first.detector}/${first.reachability}`);
});

test("reportableFindings keeps only the reachable class", () => {
  const src = `pragma solidity ^0.8.0;
contract Open {
    function sweep() external {
        payable(msg.sender).transfer(address(this).balance);
    }
}`;
  const all = findingsFor(src);
  const reportable = reportableFindings(all);
  assert.ok(reportable.length >= 1);
  for (const f of reportable) assert.equal(f.reachability, "REACHABLE");
  assert.ok(reportable.length <= all.length);
});

// ------------------------------------------------------------------
// 4. Confidence and money figures are derived
// ------------------------------------------------------------------

test("a NEEDS_READ site caps confidence at medium and says why", () => {
  const src = `pragma solidity ^0.8.0;
contract Unresolved {
    // validPlayer is not defined here, so the analyzer cannot resolve it
    function drain() external validPlayer {
        payable(msg.sender).transfer(address(this).balance);
    }
}`;
  const hit = findingsFor(src).find((f) => f.detector === "unprotected-ether");
  assert.ok(hit, "the ether rule should still fire on an unresolvable modifier");
  assert.equal(hit!.reachability, "NEEDS_READ");
  assert.equal(hit!.confidence, "medium");
  assert.equal(hit!.confidenceBasis, "unresolved-gate");
});

test("a precondition-gated site records the basis", () => {
  const src = `pragma solidity ^0.8.0;
interface IERC721 { function balanceOf(address) external view returns (uint256); }
contract Gated {
    IERC721 public nft;
    function claim() external {
        require(nft.balanceOf(msg.sender) > 0, "need NFT");
        payable(msg.sender).transfer(address(this).balance);
    }
}`;
  const hit = findingsFor(src).find((f) => f.locationFn === "claim");
  if (!hit) return; // no finding is a valid outcome for a gated site
  assert.equal(hit.confidenceBasis, "precondition-text");
  assert.notEqual(hit.confidence, "high");
});

test("a published money figure is marked as an assumption, never as a measurement", () => {
  // bridge-message-auth's text names the 116,500 rsETH released at KelpDAO.
  const src = `pragma solidity ^0.8.0;
contract BridgeHandler {
    mapping(address => uint256) public balances;
    function process(address to, uint256 amount, bytes calldata proof) external {
        require(proof.length > 0, "proof");
        balances[to] += amount;
        payable(to).transfer(amount);
    }
}`;
  const hit = findingsFor(src).find((f) => f.detector === "bridge-message-auth");
  assert.ok(hit, "the bridge rule should fire");
  assert.ok(hit!.economicClaim, "a figure in the text must carry a basis");
  assert.equal(hit!.economicClaim!.basis, "assumption");
  assert.match(hit!.summary, /illustrative/);
});

test("findings with no money figure carry no economic claim", () => {
  const src = `pragma solidity ^0.8.0;
contract Hygiene { function ping() external {} }`;
  for (const f of findingsFor(src)) {
    if (!/\d[\d,.]*\s*(?:ETH|USD|USDC|USDT|DAI|wei)\b|\$\s?\d/.test(`${f.summary} ${f.walkthrough}`)) {
      assert.equal(f.economicClaim ?? null, null, `${f.detector} should carry no claim`);
    }
  }
});

// ------------------------------------------------------------------
// 5. Grouping by mechanism
// ------------------------------------------------------------------

test("every finding carries a family", () => {
  const src = `pragma solidity ^0.8.0;
contract Many {
    mapping(address => uint256) public balances;
    uint256 public total;
    function tick() external {
        total += 1;
    }
}`;
  for (const f of findingsFor(src)) {
    assert.ok(f.family, `${f.detector} has no family`);
  }
});

test("grouping collapses many findings into fewer mechanism groups", () => {
  const src = `pragma solidity ^0.8.0;
contract PriceAndAuth {
    address public owner;
    uint256 public price;
    // two caller-identity findings in one contract: they belong to one group
    function sweep() external {
        payable(msg.sender).transfer(address(this).balance);
    }
    function setOwner(address newOwner) external {
        owner = newOwner;
    }
}`;
  const findings = findingsFor(src);
  const groups = groupFindingsByFamily(findings);
  assert.ok(groups.length >= 2, "expected more than one mechanism");
  assert.ok(groups.length < findings.length, `${groups.length} groups vs ${findings.length} findings`);
  // A group containing a reachable finding sorts ahead of one that does not.
  const first = groups[0]!;
  assert.ok(
    first.findings.some((f) => f.reachability === "REACHABLE") || !groups.some((g) => g.findings.some((f) => f.reachability === "REACHABLE")),
    "the leading group should be the one with a reachable finding",
  );
});
