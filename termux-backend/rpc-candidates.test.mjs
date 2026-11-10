// Tests for candidateRpcs, without starting the server: server.mjs calls listen() at
// module level, so the function is re-imported from a tiny harness that copies nothing
// — instead we read the source and evaluate the one function we need.
//
// Run: node --test termux-backend/rpc-candidates.test.mjs
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { ALL_RPC_URLS } from "../src/lib/config.mjs";

const src = readFileSync(new URL("./server.mjs", import.meta.url), "utf8");
const start = src.indexOf("function candidateRpcs(");
const end = src.indexOf("\n}\n", start) + 3;
assert.ok(start > 0 && end > start, "candidateRpcs found in server.mjs");
const fnSrc = src.slice(start, end);
// server.mjs derives RPC_PROVIDERS from the central config
// (src/lib/config.mjs); its standalone fallback literal is marked in the
// source. Evaluate the function against the fallback literal, and pin the
// literal to the config table so the two can never drift apart.
const fbStart = src.indexOf("/*FALLBACK_LITERAL_START*/");
const fbEnd = src.indexOf("/*FALLBACK_LITERAL_END*/");
assert.ok(fbStart > 0 && fbEnd > fbStart, "fallback literal markers found in server.mjs");
const fallbackLiteral = src
  .slice(fbStart, fbEnd)
  .replace("/*FALLBACK_LITERAL_START*/", "")
  .trim();
const fallbackProviders = new Function(`return (${fallbackLiteral});`)();
assert.deepEqual(
  fallbackProviders,
  ALL_RPC_URLS,
  "server.mjs standalone fallback must equal ALL_RPC_URLS in src/lib/config.mjs",
);

// eslint-disable-next-line no-new-func
const candidateRpcs = new Function(
  `const RPC_PROVIDERS = ${JSON.stringify(ALL_RPC_URLS)};\n${fnSrc}\nreturn candidateRpcs;`,
)();

test("a supplied rpcUrl is a preference, not the whole candidate set", () => {
  // The bug: the worker always sends one rpcUrl, which used to replace the list
  // entirely, so every RPC failure was fatal to that request ("tried 1").
  const out = candidateRpcs("https://ethereum.publicnode.com", null);
  assert.ok(out.length > 1, `expected fallbacks, got ${out.length}`);
  assert.equal(out[0], "https://ethereum.publicnode.com", "the preference is tried first");
  assert.ok(out.includes("https://1rpc.io/eth"), "the provider that was working is in the list");
});

test("a supplied list is preserved in order, then the built-ins", () => {
  const out = candidateRpcs("https://a.example", ["https://b.example"]);
  assert.equal(out[0], "https://a.example");
  assert.equal(out[1], "https://b.example");
  assert.ok(out.length > 2);
});

test("duplicates collapse and blanks are dropped", () => {
  const out = candidateRpcs("https://eth.drpc.org", ["https://eth.drpc.org", "", "  "]);
  assert.equal(out.filter((u) => u === "https://eth.drpc.org").length, 1);
  assert.ok(out.every((u) => typeof u === "string" && u.trim().length > 0));
});

test("no input still yields a usable list", () => {
  const out = candidateRpcs(null, null);
  assert.ok(out.length > 0);
  assert.equal(out[0], "https://ethereum.publicnode.com");
});
