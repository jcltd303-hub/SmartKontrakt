import test from "node:test";
import assert from "node:assert/strict";
import { runDeepAgentRound, repairPocCode } from "./deep-agent.server.ts";
import type { Finding } from "./types.ts";

/**
 * Deep Agent proposal parsing — the 2026-10-25 live failure: a
 * free-tier model answered Round 1 with prose instead of a bare JSON
 * object and the whole search died with "Model reply did not contain
 * a JSON object". These tests pin the tolerant path: extraction
 * recovers wrapped JSON without a retry, an unrecoverable reply gets
 * ONE corrective retry, and a second failure throws with the
 * offending reply IN the message. Validation strictness after
 * extraction is unchanged (a hypothesis without a PoC is dropped).
 */

const FINDING: Finding = {
  id: "f1",
  severity: "high",
  swc: null,
  title: "Caller-supplied delegatecall target",
  confidence: "high",
  detector: "delegatecall",
  summary: "upgradeTo delegatecalls a caller-supplied implementation.",
  walkthrough: "",
  exploitSolidity: "",
  remediationSolidity: "",
  locationFn: "upgradeTo",
  locationLine: 329,
  snippet: "",
};

const BODY = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract Proxy {
    function upgradeTo(address impl) public { impl.delegatecall(""); }
}
`;

const VALID_REPLY = JSON.stringify({
  hypotheses: [
    {
      title: "Unprivileged upgradeTo hijack",
      detector: "delegatecall",
      severity: "critical",
      hypothesis: "upgradeTo has no access check, so anyone can delegatecall attacker code.",
      foundryTestCode:
        "// SPDX-License-Identifier: MIT\npragma solidity ^0.8.20;\ncontract PoC is Test { function test_hijack() public {} }",
    },
  ],
  stopReason: null,
});

/** Script OpenRouter replies by call order; returns the request log. */
function installOpenRouter(replies: string[]) {
  const original = globalThis.fetch;
  const requests: Array<{ body: string }> = [];
  globalThis.fetch = (async (input: unknown, init?: { body?: unknown }) => {
    const url = String(input);
    if (!url.includes("openrouter.ai")) {
      throw new Error(`unexpected fetch in deep-agent test: ${url}`);
    }
    const body = String(init?.body ?? "");
    requests.push({ body });
    const content = replies[Math.min(requests.length - 1, replies.length - 1)];
    return new Response(
      JSON.stringify({ choices: [{ message: { content } }] }),
      { status: 200, headers: { "Content-Type": "application/json" } },
    );
  }) as typeof fetch;
  return { requests, restore: () => { globalThis.fetch = original; } };
}

function withEnv<T>(fn: () => Promise<T>): Promise<T> {
  const prevKey = process.env.OPENROUTER_API_KEY;
  process.env.OPENROUTER_API_KEY = "sk-or-test";
  return fn().finally(() => {
    if (prevKey === undefined) delete process.env.OPENROUTER_API_KEY;
    else process.env.OPENROUTER_API_KEY = prevKey;
  });
}

test("deep agent: fenced JSON parses on the first call (no retry burned)", async () => {
  const fence = "`".repeat(3);
  const f = installOpenRouter([`${fence}json\n${VALID_REPLY}\n${fence}`]);
  try {
    const res = await withEnv(() => runDeepAgentRound("Proxy", BODY, [FINDING], [], 1));
    assert.equal(res.hypotheses.length, 1);
    assert.equal(res.hypotheses[0].title, "Unprivileged upgradeTo hijack");
    assert.equal(res.stopReason, null);
    assert.equal(f.requests.length, 1, "tolerant extraction must not spend the corrective retry");
  } finally { f.restore(); }
});

test("deep agent: prose-wrapped JSON with braces in prose parses on the first call", async () => {
  const wrapped =
    `I reviewed the proxy — the pattern is: function upgradeTo(a) { a.delegatecall(""); } — ` +
    `dangerous. My proposals:\n${VALID_REPLY}\nThat is the full list }`;
  const f = installOpenRouter([wrapped]);
  try {
    const res = await withEnv(() => runDeepAgentRound("Proxy", BODY, [FINDING], [], 1));
    assert.equal(res.hypotheses.length, 1);
    assert.equal(f.requests.length, 1);
  } finally { f.restore(); }
});

test("deep agent: a JSON-less reply gets ONE corrective retry, then succeeds", async () => {
  const f = installOpenRouter([
    "I found the issue: upgradeTo is unprotected. Proposals follow in my next message.",
    VALID_REPLY,
  ]);
  try {
    const res = await withEnv(() => runDeepAgentRound("Proxy", BODY, [FINDING], [], 1));
    assert.equal(res.hypotheses.length, 1);
    assert.equal(f.requests.length, 2, "exactly one corrective retry");
    assert.match(f.requests[1].body, /ONLY the JSON object/, "the retry must carry the corrective instruction");
  } finally { f.restore(); }
});

test("deep agent: two unparseable replies fail — with the offending reply in the error", async () => {
  const bad = "No structured answer this time, just commentary about proxies.";
  const f = installOpenRouter([bad, bad]);
  try {
    await assert.rejects(
      () => withEnv(() => runDeepAgentRound("Proxy", BODY, [FINDING], [], 1)),
      (err: unknown) => {
        const message = err instanceof Error ? err.message : String(err);
        assert.match(message, /did not contain a JSON object/);
        assert.match(message, /No structured answer this time/, "the error must quote the offending reply");
        return true;
      },
    );
    assert.equal(f.requests.length, 2, "the corrective retry happened exactly once before failing");
  } finally { f.restore(); }
});

test("deep agent: validation stays strict after extraction (PoC-less hypothesis dropped)", async () => {
  const reply = JSON.stringify({
    hypotheses: [
      { title: "No code attached", detector: "x", severity: "high", hypothesis: "trust me" },
      { title: "", detector: "x", severity: "high", hypothesis: "empty title", foundryTestCode: "contract PoC is Test {}" },
    ],
    stopReason: null,
  });
  const f = installOpenRouter([reply]);
  try {
    const res = await withEnv(() => runDeepAgentRound("Proxy", BODY, [FINDING], [], 1));
    assert.equal(res.hypotheses.length, 0);
    assert.equal(res.stopReason, "no_new_hypotheses");
    assert.equal(f.requests.length, 1, "a parseable reply never triggers the corrective retry");
  } finally { f.restore(); }
});

test("repair: a prose/fence-wrapped repair reply still yields the fixed PoC", async () => {
  // The other half of the 2026-10-25 screenshot: the AI-review
  // auto-run's compile repair died inside the same extractor, so the
  // original compile error stood as the verdict. The repair model's
  // reply here wraps the JSON behind a non-JSON fence and trails a
  // stray brace — the old first-fence read threw on it.
  const fixed = "contract PoC is Test { function test_slot() public { uint256 s = uint256(vm.load(target, bytes32(0))); } }";
  const reply =
    `Here is the fix:\n\`\`\`\nnotes about the type error\n\`\`\`\n\`\`\`json\n${JSON.stringify({ foundryTestCode: fixed })}\n\`\`\`\nHope that compiles }`;
  const f = installOpenRouter([reply]);
  try {
    const res = await withEnv(() =>
      repairPocCode("Proxy", "contract PoC is Test { /* broken */ }", "Error (9574): Type bytes32 is not implicitly convertible", BODY),
    );
    assert.equal(res.fixedCode, fixed);
  } finally { f.restore(); }
});
