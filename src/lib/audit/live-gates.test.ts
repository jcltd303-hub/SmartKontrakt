// src/lib/audit/live-gates.test.ts
import assert from "node:assert/strict";
import test from "node:test";
import { applyLiveGates, applyLiveStateAnnotations, applyValueExposure } from "./live-gates.ts";
import type { Finding, Report } from "./types.ts";
import type { AddressValue } from "./value.ts";

function finding(partial: Partial<Finding>): Finding {
  return {
    severity: "high",
    swc: null,
    title: "t",
    confidence: "high",
    detector: "unprotected-ether",
    summary: "s",
    walkthrough: "w",
    exploitSolidity: "",
    remediationSolidity: "",
    locationFn: "f",
    locationLine: 1,
    snippet: "",
    ...partial,
  } as Finding;
}

function report(partial: Partial<Report>): Report {
  return {
    label: "L",
    inputKind: "address",
    riskScore: 0,
    summary: "s",
    inventory: { notes: [] },
    findings: [],
    aiNarrative: null,
    aiStatus: "unavailable",
    ...partial,
  } as unknown as Report;
}

function value(partial: Partial<AddressValue>): AddressValue {
  return {
    address: "0xA",
    chainId: 1,
    symbol: "ETH",
    nativeWei: "0",
    nativeUsd: 0,
    totalUsd: 0,
    holdings: [],
    priced: 0,
    unpriced: 0,
    sources: [],
    complete: true,
    notes: [],
    valuedAt: "2026-11-01T00:00:00Z",
    ...partial,
  };
}

test("value exposure stamps the live figure on value-bound detectors only", () => {
  const r = report({
    findings: [
      finding({ detector: "unprotected-ether" }),
      finding({ detector: "reentrancy" }),
      finding({ detector: "token-drain", economicClaim: { figure: "$5 in the text", basis: "assumption" } }),
    ],
  });
  r.inventory.value = value({ totalUsd: 2500, priced: 2 });
  assert.equal(applyValueExposure(r), 2);
  assert.equal(r.findings[0]!.economicClaim?.basis, "live");
  assert.match(r.findings[0]!.economicClaim?.figure ?? "", /\$2\.50k live value/);
  assert.equal(r.findings[1]!.economicClaim, undefined);
  // The detector's text-figure assumption is replaced by the live read.
  assert.equal(r.findings[2]!.economicClaim?.basis, "live");
});

test("a complete $0 read is stated; an incomplete $0 is not", () => {
  const empty = report({ findings: [finding({})] });
  empty.inventory.value = value({ totalUsd: 0, complete: true });
  assert.equal(applyValueExposure(empty), 1);
  assert.match(empty.findings[0]!.economicClaim?.figure ?? "", /nothing to extract/);

  const unknown = report({ findings: [finding({})] });
  unknown.inventory.value = value({ totalUsd: 0, complete: false });
  assert.equal(applyValueExposure(unknown), 0);
  assert.equal(unknown.findings[0]!.economicClaim, undefined);
});

test("live-state annotations attach owner and paused reads to the findings they bear on", () => {
  const r = report({
    findings: [
      finding({ detector: "unprotected-admin", severity: "critical" }),
      finding({ detector: "unprotected-ether", severity: "critical" }),
      finding({ detector: "unprotected-ether", severity: "low" }),
    ],
  });
  r.inventory.liveState = {
    address: "0xA",
    chainId: "ethereum",
    blockNumber: 123,
    reads: [
      { name: "owner", kind: "address", value: "0x000000000000000000000000000000000000dEaD", raw: "0x" },
      { name: "paused", kind: "bool", value: "true", raw: "0x1" },
    ],
    failures: [],
  };
  assert.equal(applyLiveStateAnnotations(r), 2);
  assert.match(r.findings[0]!.confidenceBasis ?? "", /live owner\(\) = 0x000000000000000000000000000000000000dEaD at block 123/);
  assert.match(r.findings[1]!.confidenceBasis ?? "", /live paused\(\) = true at block 123/);
  // Low severity is not annotated for paused — the note is triage signal, not noise.
  assert.equal(r.findings[2]!.confidenceBasis, undefined);
  // Combined pass is safe with no data at all.
  applyLiveGates(report({ findings: [finding({})] }));
});
