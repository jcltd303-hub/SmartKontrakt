// src/lib/audit/poc-audit-llm.test.ts
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  createRepairBodyResolver,
  externalTokenCandidate,
  fourbyteForStoredReport,
  pocAuditReviewPayload,
} from "./poc-audit-llm.ts";
import { fourbyteResultsFromReport } from "./fourbyte.ts";
import type { Finding, Inventory, Report } from "./types.ts";

function inventoryWith(
  selectors: Inventory["selectors"],
  topics?: Inventory["topics"],
): Inventory {
  return {
    inputKind: "source",
    contractNames: ["Target"],
    kindNote: "",
    pragma: "^0.8.24",
    compiler: "0.8.24",
    functions: [],
    stateVars: [],
    events: [],
    inheritance: [],
    selectors,
    reconstructed: "",
    topics,
    opcodes: [],
    signals: [],
    bytecodeBytes: null,
    basicBlocks: null,
    proxy: null,
    notes: [],
    disassembly: "",
  };
}

function reportWith(inventory: Inventory): Report {
  return {
    label: "Target",
    inputKind: "source",
    riskScore: 50,
    summary: "",
    inventory,
    findings: [],
    aiNarrative: null,
    aiStatus: "ok",
  };
}

const FINDING: Finding = {
  id: "scan-1:0",
  severity: "critical",
  swc: "SWC-112",
  title: "delegatecall to a caller-supplied address",
  confidence: "high",
  detector: "delegatecall",
  summary: "",
  walkthrough: "",
  exploitSolidity: "contract Attack {}",
  remediationSolidity: "",
  locationFn: "poke",
  locationLine: 12,
  snippet: "target.delegatecall(data);",
};

const RESOLVED_REPORT = reportWith(
  inventoryWith(
    [
      { selector: "0xa9059cbb", signature: "transfer(address,uint256)" },
      {
        selector: "0x23b872dd",
        signature: "transferFrom(address,address,uint256)",
        signatures: ["transferFrom(address,address,uint256)", "transferFrom(address,address,uint256,bytes)"],
      },
      { selector: "0xdeadbeef", signature: null },
    ],
    [
      {
        topic: "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef",
        signature: "Transfer(address,address,uint256)",
      },
      { topic: "0x0000000000000000000000000000000000000000000000000000000000000000", signature: null },
    ],
  ),
);

describe("pocAuditReviewPayload — fourbyte parity with the workbench", () => {
  it("carries the same fourbyte payload the workbench sends when the stored report yields results", () => {
    const payload = pocAuditReviewPayload({
      contractName: "Target",
      body: "contract Target {}",
      findings: [FINDING],
      storedReport: RESOLVED_REPORT,
    });
    assert.deepEqual(payload.fourbyte, fourbyteResultsFromReport(RESOLVED_REPORT));
    // The resolved names actually reach the payload — the field is not
    // a decorative empty object.
    assert.deepEqual(payload.fourbyte?.selectors["0xa9059cbb"], ["transfer(address,uint256)"]);
    assert.deepEqual(payload.fourbyte?.selectors["0x23b872dd"], [
      "transferFrom(address,address,uint256)",
      "transferFrom(address,address,uint256,bytes)",
    ]);
    assert.equal(payload.fourbyte?.selectors["0xdeadbeef"], undefined);
    assert.deepEqual(
      payload.fourbyte?.topics["0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"],
      ["Transfer(address,address,uint256)"],
    );
    // The rest of the payload passes through untouched.
    assert.equal(payload.contractName, "Target");
    assert.equal(payload.body, "contract Target {}");
    assert.deepEqual(payload.findings, [FINDING]);
  });

  it("passes the helper's empty-maps object (not undefined) when a well-formed report resolved nothing — the workbench sends the same shape and the server fn normalizes it", () => {
    const bare = reportWith(inventoryWith([{ selector: "0xdeadbeef", signature: null }]));
    const payload = pocAuditReviewPayload({
      contractName: "Target",
      body: "contract Target {}",
      findings: [],
      storedReport: bare,
    });
    assert.deepEqual(payload.fourbyte, { selectors: {}, topics: {} });
  });

  it("sends undefined when the stored record cannot yield fourbyte results", () => {
    for (const storedReport of [null, undefined]) {
      const payload = pocAuditReviewPayload({
        contractName: "Target",
        body: "contract Target {}",
        findings: [],
        storedReport,
      });
      assert.equal(payload.fourbyte, undefined);
    }
    // A record predating the current Report shape: inventory without a
    // selectors array must not throw and must not fabricate context.
    const legacy = { label: "Old", inventory: {} } as unknown as Report;
    assert.equal(fourbyteForStoredReport(legacy), undefined);
  });
});

describe("createRepairBodyResolver — full stored body for the direct path", () => {
  it("returns the parent scan's full stored body", async () => {
    const resolver = createRepairBodyResolver(async () => "contract Target { /* full source */ }");
    const resolved = await resolver.resolve("scan-1", "snippet fallback");
    assert.equal(resolved.source, "stored");
    assert.equal(resolved.body, "contract Target { /* full source */ }");
    assert.equal(resolved.note, undefined);
  });

  it("fetches a scan's body once across many findings of that scan (AUDIT ALL cache)", async () => {
    let loads = 0;
    const resolver = createRepairBodyResolver(async (scanId) => {
      loads += 1;
      return `body of ${scanId}`;
    });
    const first = await resolver.resolve("scan-1", "snippet A");
    const second = await resolver.resolve("scan-1", "snippet B");
    const other = await resolver.resolve("scan-2", "snippet C");
    assert.equal(loads, 2); // scan-1 loaded once, scan-2 loaded once
    assert.equal(resolver.cachedScanCount(), 2);
    assert.equal(first.body, "body of scan-1");
    assert.equal(second.body, "body of scan-1"); // cache wins over the second finding's own snippet
    assert.equal(other.body, "body of scan-2");
  });

  it("falls back to the finding snippet — with the reason on the record — only when the load fails", async () => {
    let loads = 0;
    const resolver = createRepairBodyResolver(async () => {
      loads += 1;
      throw new Error("scan payload missing");
    });
    const resolved = await resolver.resolve("scan-9", "target.delegatecall(data);");
    assert.equal(resolved.source, "snippet");
    assert.equal(resolved.body, "target.delegatecall(data);");
    assert.match(resolved.note ?? "", /could not be loaded \(scan payload missing\)/);
    // The failure is cached too: a second finding of the same scan does
    // not re-hammer a broken load, and still gets the annotated fallback.
    const again = await resolver.resolve("scan-9", "other snippet");
    assert.equal(loads, 1);
    assert.equal(again.source, "snippet");
    assert.equal(again.body, "other snippet");
  });

  it("falls back with a missing/empty note when the loader returns no usable body", async () => {
    for (const empty of [null, "", "   \n  "]) {
      const resolver = createRepairBodyResolver(async () => empty);
      const resolved = await resolver.resolve("scan-1", "snippet");
      assert.equal(resolved.source, "snippet");
      assert.equal(resolved.body, "snippet");
      assert.match(resolved.note ?? "", /No stored contract body/);
    }
  });
});

describe("externalTokenCandidate — POC_TOKEN source (audit class E1)", () => {
  const TARGET = "0x1111111111111111111111111111111111111111";
  const TOK_A = "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
  const TOK_B = "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
  const holding = (partial: Record<string, unknown>) => ({
    kind: "erc20",
    address: TOK_A,
    symbol: "T",
    name: null,
    decimals: 18,
    raw: "1000",
    amount: 1,
    priceUsd: 1,
    valueUsd: 10,
    priceSource: null,
    ...partial,
  }) as never;
  const reportWith = (holdings: unknown) =>
    ({ inventory: { value: { holdings } } }) as unknown as Pick<Report, "inventory">;

  it("picks the most valuable external ERC-20 holding", () => {
    const report = reportWith([
      holding({ address: TOK_A, valueUsd: 10 }),
      holding({ address: TOK_B, valueUsd: 250 }),
    ]);
    assert.equal(externalTokenCandidate(report, TARGET), TOK_B);
  });

  it("skips the target itself, native holdings, and zero balances", () => {
    const report = reportWith([
      holding({ address: TARGET, valueUsd: 9999 }),
      holding({ address: null, kind: "native", valueUsd: 8888 }),
      holding({ address: TOK_A, raw: "0", valueUsd: 7777 }),
      holding({ address: TOK_B, valueUsd: 5 }),
    ]);
    assert.equal(externalTokenCandidate(report, TARGET), TOK_B);
  });

  it("an unpriced holding (valueUsd null) still counts, ranked last", () => {
    const report = reportWith([
      holding({ address: TOK_A, valueUsd: null }),
      holding({ address: TOK_B, valueUsd: 1 }),
    ]);
    assert.equal(externalTokenCandidate(report, TARGET), TOK_B);
    assert.equal(externalTokenCandidate(reportWith([holding({ valueUsd: null })]), TARGET), TOK_A);
  });

  it("returns null without a valuation or qualifying holdings", () => {
    assert.equal(externalTokenCandidate(null, TARGET), null);
    assert.equal(externalTokenCandidate(reportWith([]), TARGET), null);
    assert.equal(externalTokenCandidate(reportWith([holding({ address: TARGET })]), TARGET), null);
    assert.equal(
      externalTokenCandidate({ inventory: {} } as unknown as Pick<Report, "inventory">, TARGET),
      null,
    );
  });
});
