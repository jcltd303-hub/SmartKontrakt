import test from "node:test";
import assert from "node:assert/strict";

import { analyzeAddress } from "./address-fetcher.ts";

/**
 * Sourcify v2 (2026-10-27).
 *
 * The fetcher called `https://sourcify.dev/server/files/any/...`, which is the v1
 * path — turned off on 2026-07-07. For four months every Sourcify lookup failed
 * and every verified contract silently fell through to Blockscout or to
 * bytecode-only analysis. v2 answers `{ sources: { "<path>": { content } } }`
 * (verified live against 0x000000000000541e251335090ac5b47176af4f7e, which is
 * dexBlue).
 */

const REAL_V2_SHAPE = {
  sources: {
    "contracts/Token.sol": {
      content:
        "// SPDX-License-Identifier: MIT\npragma solidity 0.8.24;\nimport {IThing} from \"./IThing.sol\";\ncontract Token is IThing {\n  mapping(address => uint256) public balanceOf;\n  function sweep(address payable to) external { to.transfer(address(this).balance); }\n}\n",
    },
    "contracts/IThing.sol": {
      content: "// SPDX-License-Identifier: MIT\npragma solidity 0.8.24;\ninterface IThing { function balanceOf(address) external view returns (uint256); }\n",
    },
  },
};

const V1_SHAPE = {
  files: [{ name: "Old.sol", content: "pragma solidity 0.8.0;\ncontract Old { function f() external {} }\n" }],
};

const ADDRESS = "0x1111111111111111111111111111111111111111";

function stubFetch(responses: Record<string, unknown>) {
  const asked: string[] = [];
  const original = globalThis.fetch;
  globalThis.fetch = (async (url: string | URL | Request) => {
    const href = typeof url === "string" ? url : url instanceof URL ? url.href : url.url;
    asked.push(href);
    for (const [fragment, body] of Object.entries(responses)) {
      if (href.includes(fragment)) {
        return new Response(JSON.stringify(body), { status: 200, headers: { "content-type": "application/json" } });
      }
    }
    return new Response("{}", { status: 404 });
  }) as typeof fetch;
  return { asked, restore: () => { globalThis.fetch = original; } };
}

test("the v2 sources map is fetched, joined, and analysed", async () => {
  const stub = stubFetch({
    "/v2/contract/1/": REAL_V2_SHAPE,
    // RPC and Blockscout are not stubbed: they 404, which is the bytecode path.
  });
  try {
    const { report, inputKind } = await analyzeAddress(ADDRESS, "ethereum");
    assert.equal(inputKind, "source", "v2 source was found and used");
    assert.ok(
      report.findings.length > 0 || report.inventory.selectors.length > 0,
      "the joined multi-file source actually parsed",
    );
    assert.ok(
      stub.asked.some((u) => u.includes("/server/v2/contract/1/")),
      "the v2 endpoint is the one called",
    );
    assert.ok(
      !stub.asked.some((u) => u.includes("/server/files/any/")),
      "the retired v1 path is never called",
    );
  } finally {
    stub.restore();
  }
});

test("a v1-shaped response still parses, so a cached mirror does not break", async () => {
  const stub = stubFetch({ "/v2/contract/1/": V1_SHAPE });
  try {
    const { inputKind } = await analyzeAddress(ADDRESS, "ethereum");
    assert.equal(inputKind, "source");
  } finally {
    stub.restore();
  }
});
